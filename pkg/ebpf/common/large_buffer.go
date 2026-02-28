// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"fmt"
	"io"
)

// LargeBuffer assembles chunked eBPF ring-buffer events into a readable byte stream.
//
// # Storage
//
// Chunks are stored independently as [][]byte. Each [LargeBuffer.AppendChunk] call allocates
// exactly one new slice and records its header (pointer + length + capacity, 24 bytes) in the
// chunk index. No previously-written chunk data is ever reallocated or copied when new chunks
// arrive — contrast with a flat []byte whose backing array must be copied on every capacity
// growth.
//
// # Reading
//
// Two methods provide zero-copy reads within a single chunk:
//
//   - [LargeBuffer.ReadN] — returns the next n bytes. When all n bytes lie within the current
//     chunk, a sub-slice of that chunk's backing array is returned (zero allocation, zero copy).
//     When n crosses a chunk boundary the internal scratch buffer is reused (one copy, no heap
//     allocation after the first cross-boundary read). The returned slice must NOT be retained
//     across the next ReadN/Slice/Read call. Use for scalar decode-and-discard patterns such as
//     binary.BigEndian.Uint32(lb.ReadN(4)).
//
//   - [LargeBuffer.Slice] — same zero-copy semantic within a chunk, but always safe to retain
//     indefinitely. Cross-chunk reads allocate a fresh []byte (not scratch). Use when wrapping
//     the result in a view type that sub-slices it later, e.g. Packet(lb.Slice(totalLen)).
//
// [LargeBuffer] also implements [io.Reader] for use with bufio.NewReader and stream-oriented
// parsers such as net/http.
//
// # Ring-buffer memory safety
//
// eBPF ring-buffer records share kernel-mapped memory that is reclaimed on the next ReadInto
// call. [LargeBuffer.AppendChunk] always copies the provided data into a new Go-owned allocation,
// so no reference to ring-buffer memory is retained across event-loop iterations.
//
// [LargeBuffer.NewLargeBufferFrom] is the only exception: it wraps an existing slice without
// copying. It is safe only when the wrapped slice outlives all reads — use it exclusively for
// inline event buffers consumed within the same call frame.
type LargeBuffer struct {
	chunks  [][]byte
	total   int
	rchunk  int // index of the current read chunk
	roff    int // byte offset within chunks[rchunk]
	scratch []byte
}

// NewLargeBuffer returns an empty LargeBuffer ready to receive chunks.
func NewLargeBuffer() *LargeBuffer {
	return &LargeBuffer{}
}

// NewLargeBufferFrom wraps b as a single-chunk LargeBuffer without copying.
//
// The caller must ensure that b remains valid for the lifetime of all reads.
// Do NOT use this with ring-buffer memory that will be reclaimed across event-loop iterations.
// Safe use: inline event fields (e.g. event.Buf[:]) consumed within the same call frame.
func NewLargeBufferFrom(b []byte) *LargeBuffer {
	return &LargeBuffer{
		chunks: [][]byte{b},
		total:  len(b),
	}
}

// AppendChunk copies data into a new independently-allocated chunk.
func (lb *LargeBuffer) AppendChunk(data []byte) {
	chunk := make([]byte, len(data))
	copy(chunk, data)

	lb.chunks = append(lb.chunks, chunk)
	lb.total += len(data)
}

// Len returns the total number of bytes across all chunks.
func (lb *LargeBuffer) Len() int {
	return lb.total
}

// Remaining returns the number of unread bytes.
func (lb *LargeBuffer) Remaining() int {
	consumed := lb.roff
	for i := range lb.rchunk {
		consumed += len(lb.chunks[i])
	}
	return lb.total - consumed
}

// ReadN returns exactly n bytes starting at the current read position and advances the cursor.
//
// Zero-copy path: when all n bytes lie within the current chunk, a sub-slice of that chunk's
// backing array is returned — no allocation, no copy.
//
// Cross-chunk path: bytes are copied into the internal scratch buffer (grown as needed, never
// freed). The same scratch slice is reused on subsequent cross-chunk calls.
//
// The returned slice MUST NOT be retained across the next ReadN, Slice, or Read call.
// For a retainable slice, use [LargeBuffer.Slice].
func (lb *LargeBuffer) ReadN(n int) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}

	if n > lb.Remaining() {
		return nil, fmt.Errorf("LargeBuffer.ReadN: requested %d bytes but only %d remaining", n, lb.Remaining())
	}

	// Fast path: all bytes within the current chunk — zero allocation, zero copy.
	if lb.rchunk < len(lb.chunks) && lb.roff+n <= len(lb.chunks[lb.rchunk]) {
		s := lb.chunks[lb.rchunk][lb.roff : lb.roff+n]

		lb.roff += n
		if lb.roff == len(lb.chunks[lb.rchunk]) {
			lb.rchunk++
			lb.roff = 0
		}

		return s, nil
	}

	// Slow path: copy across chunk boundaries into reusable scratch.
	if cap(lb.scratch) < n {
		lb.scratch = make([]byte, n)
	}
	lb.scratch = lb.scratch[:n]
	lb.copyN(lb.scratch)

	return lb.scratch, nil
}

// Slice returns exactly n bytes starting at the current read position and advances the cursor.
//
// Zero-copy path: when all n bytes lie within the current chunk, a sub-slice of that chunk's
// backing array is returned — no allocation, no copy.
//
// Cross-chunk path: a fresh []byte of length n is allocated. Unlike [LargeBuffer.ReadN], the
// scratch buffer is NOT used, so the returned slice is safe to retain indefinitely.
//
// Use Slice when wrapping the result in a view type that sub-slices it, e.g.:
//
//	pkt, _ := lb.Slice(h.TotalLen())
//	packet := Packet(pkt) // Packet.Key() returns pkt[start:end] — safe to hold
func (lb *LargeBuffer) Slice(n int) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}

	if n > lb.Remaining() {
		return nil, fmt.Errorf("LargeBuffer.Slice: requested %d bytes but only %d remaining", n, lb.Remaining())
	}

	// Fast path: all bytes within the current chunk — zero-copy, safe to retain.
	if lb.rchunk < len(lb.chunks) && lb.roff+n <= len(lb.chunks[lb.rchunk]) {
		s := lb.chunks[lb.rchunk][lb.roff : lb.roff+n]

		lb.roff += n
		if lb.roff == len(lb.chunks[lb.rchunk]) {
			lb.rchunk++
			lb.roff = 0
		}

		return s, nil
	}

	// Slow path: fresh allocation — retainable, does not touch scratch.
	buf := make([]byte, n)
	lb.copyN(buf)

	return buf, nil
}

// Peek returns the next n bytes without advancing the read cursor.
//
// Zero-copy path: when all n bytes lie within the current chunk, a sub-slice of that chunk is
// returned with no allocation.
//
// Cross-chunk path: copies into the internal scratch buffer (same reuse semantics as ReadN).
//
// The returned slice MUST NOT be retained across the next ReadN, Slice, or Read call.
func (lb *LargeBuffer) Peek(n int) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}

	if n > lb.Remaining() {
		return nil, fmt.Errorf("LargeBuffer.Peek: requested %d bytes but only %d remaining", n, lb.Remaining())
	}

	// Fast path: within current chunk — return sub-slice directly.
	if lb.rchunk < len(lb.chunks) && lb.roff+n <= len(lb.chunks[lb.rchunk]) {
		return lb.chunks[lb.rchunk][lb.roff : lb.roff+n], nil
	}

	// Slow path: copy into scratch, then restore cursor position.
	savedChunk, savedOff := lb.rchunk, lb.roff

	if cap(lb.scratch) < n {
		lb.scratch = make([]byte, n)
	}
	lb.scratch = lb.scratch[:n]
	lb.copyN(lb.scratch)

	lb.rchunk, lb.roff = savedChunk, savedOff

	return lb.scratch, nil
}

// Skip advances the read cursor by n bytes without copying any data.
func (lb *LargeBuffer) Skip(n int) error {
	if n > lb.Remaining() {
		return fmt.Errorf("LargeBuffer.Skip: requested %d bytes but only %d remaining", n, lb.Remaining())
	}

	for n > 0 {
		avail := len(lb.chunks[lb.rchunk]) - lb.roff

		if n < avail {
			lb.roff += n
			return nil
		}

		n -= avail
		lb.rchunk++
		lb.roff = 0
	}

	return nil
}

// Read implements [io.Reader]. Fills p with up to len(p) bytes from the current read position.
//
// Returns (n, nil) when bytes were read but the cursor has not yet reached the end.
// Returns (0, io.EOF) when the cursor is already at the end of the buffer.
// Per the io.Reader contract, may return (n, nil) even when the last byte was just read;
// the subsequent call returns (0, io.EOF).
func (lb *LargeBuffer) Read(p []byte) (int, error) {
	if lb.Remaining() == 0 {
		return 0, io.EOF
	}

	n := 0
	for n < len(p) && lb.rchunk < len(lb.chunks) {
		src := lb.chunks[lb.rchunk][lb.roff:]
		copied := copy(p[n:], src)

		n += copied
		lb.roff += copied

		if lb.roff == len(lb.chunks[lb.rchunk]) {
			lb.rchunk++
			lb.roff = 0
		}
	}

	return n, nil
}

// ResetRead resets the read cursor to the beginning of the buffer without clearing chunks.
// Use this to re-parse after appending additional data, e.g.:
//
//	lb.AppendChunk([]byte("\r\n\r\n"))
//	lb.ResetRead()
//	resp, err = http.ReadResponse(bufio.NewReader(lb), req)
func (lb *LargeBuffer) ResetRead() {
	lb.rchunk = 0
	lb.roff = 0
}

// Bytes materialises all chunks into a single contiguous []byte.
//
// When there is exactly one chunk, the chunk's backing slice is returned directly (zero-copy).
// When there are multiple chunks, a new slice of length Len() is allocated and all chunks are
// copied into it.
//
// Prefer ReadN / Slice / Read over Bytes. Use Bytes only when an external package requires a
// contiguous []byte and cannot be migrated to accept a reader (e.g. the MQTT parser).
func (lb *LargeBuffer) Bytes() []byte {
	if len(lb.chunks) == 0 {
		return nil
	}

	if len(lb.chunks) == 1 {
		return lb.chunks[0]
	}

	out := make([]byte, lb.total)
	pos := 0
	for _, chunk := range lb.chunks {
		pos += copy(out[pos:], chunk)
	}

	return out
}

// Reset clears all chunks and read state, returning the LargeBuffer to its zero value.
// The scratch buffer is retained to avoid re-allocation on the next use.
// Intended for future use with sync.Pool to allow instance reuse.
func (lb *LargeBuffer) Reset() {
	lb.chunks = lb.chunks[:0]
	lb.total = 0
	lb.rchunk = 0
	lb.roff = 0
}

// copyN copies exactly len(dst) bytes from the current read position into dst, advancing the
// cursor. Assumes the caller has already verified that len(dst) <= lb.Remaining().
func (lb *LargeBuffer) copyN(dst []byte) {
	filled := 0

	for filled < len(dst) {
		src := lb.chunks[lb.rchunk][lb.roff:]
		copied := copy(dst[filled:], src)

		filled += copied
		lb.roff += copied

		if lb.roff == len(lb.chunks[lb.rchunk]) {
			lb.rchunk++
			lb.roff = 0
		}
	}
}
