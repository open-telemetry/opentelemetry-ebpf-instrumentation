// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"encoding/binary"
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
// [LargeBuffer.ReadN] returns the next n bytes. When all n bytes lie within the current chunk,
// a sub-slice of that chunk's backing array is returned (zero allocation, zero copy). When n
// crosses a chunk boundary the internal scratch buffer is reused (one copy, no heap allocation
// after the first cross-boundary read). The returned slice must NOT be retained across the next
// ReadN/Read call. Use for scalar decode-and-discard patterns such as
// binary.BigEndian.Uint32(lb.ReadN(4)).
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
// The returned slice MUST NOT be retained across the next ReadN or Read call.
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

// Peek returns the next n bytes without advancing the read cursor.
//
// Zero-copy path: when all n bytes lie within the current chunk, a sub-slice of that chunk is
// returned with no allocation.
//
// Cross-chunk path: copies into the internal scratch buffer (same reuse semantics as ReadN).
//
// The returned slice MUST NOT be retained across the next ReadN or Read call.
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

// Bytes returns the unread portion of the buffer (from the current read cursor to the end)
// without advancing the cursor — analogous to [bytes.Buffer.Bytes].
//
// Zero-copy path: when all remaining bytes lie within the current chunk, a sub-slice of that
// chunk's backing array is returned with no allocation.
//
// Cross-chunk path: copies into the internal scratch buffer (same reuse semantics as
// [LargeBuffer.ReadN]). The returned slice MUST NOT be retained across the next ReadN, Read,
// or Bytes call.
//
// Returns nil when there are no unread bytes remaining (Remaining() == 0).
//
// Use [LargeBuffer.CloneBytes] when you need a snapshot of all chunks regardless of cursor
// position (e.g. for passing to an external package that stores the slice, or for debug printing
// after partial reads).
func (lb *LargeBuffer) Bytes() []byte {
	r := lb.Remaining()
	if r == 0 {
		return nil
	}
	b, _ := lb.Peek(r)
	return b
}

// CloneBytes returns a freshly allocated copy of all chunks, independent of the current read
// cursor. The caller owns the returned slice — it is never shared with the LargeBuffer's
// internal storage.
//
// Use CloneBytes when an external package requires a contiguous []byte of the full payload
// regardless of read position (e.g. the MQTT parser), or for debug printing after partial reads.
// For cursor-relative access, prefer [LargeBuffer.Bytes], [LargeBuffer.ReadN],
// or [LargeBuffer.Read].
func (lb *LargeBuffer) CloneBytes() []byte {
	if lb.total == 0 {
		return nil
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

// ── Introspection ─────────────────────────────────────────────────────────────

// ReadOffset returns the current cursor position as an absolute byte offset from the start of
// the buffer. Equivalent to Len() - Remaining().
func (lb *LargeBuffer) ReadOffset() int {
	return lb.total - lb.Remaining()
}

// BaseOffset always returns 0. Provided for API symmetry with ReadOffset.
func (lb *LargeBuffer) BaseOffset() int {
	return 0
}

// IsEmpty reports whether the buffer contains no bytes (Len() == 0).
// It is unaffected by the read cursor position.
func (lb *LargeBuffer) IsEmpty() bool {
	return lb.total == 0
}

// ── Absolute-offset access ────────────────────────────────────────────────────

// findChunk maps absOff (an absolute byte offset from the start of the buffer) to the chunk
// index and the byte offset within that chunk. Returns (-1, 0) when absOff is out of
// [0, lb.total). O(number of chunks); fast for the typical 1–3 chunk case.
func (lb *LargeBuffer) findChunk(absOff int) (int, int) {
	if absOff < 0 || absOff >= lb.total {
		return -1, 0
	}
	pos := 0
	for i, chunk := range lb.chunks {
		end := pos + len(chunk)
		if absOff < end {
			return i, absOff - pos
		}
		pos = end
	}
	return -1, 0
}

// UnsafeViewAt returns n bytes starting at absOff without moving the read cursor.
//
// Zero-copy path: when all n bytes lie within one chunk, a sub-slice of that chunk's backing
// array is returned — no allocation, no copy.
//
// Cross-chunk path: bytes are copied into the internal scratch buffer (grown as needed, never
// freed). The same scratch slice is reused on subsequent cross-chunk calls.
//
// The returned slice MUST NOT be retained across the next UnsafeViewAt, ReadN, Peek, or
// Bytes call.
//
// Returns an error when the range [absOff, absOff+n) is out of [0, Len()).
func (lb *LargeBuffer) UnsafeViewAt(absOff, n int) ([]byte, error) {
	if n == 0 {
		return []byte{}, nil
	}
	if n < 0 || absOff < 0 || absOff+n > lb.total {
		return nil, fmt.Errorf("LargeBuffer.UnsafeViewAt: [%d, %d) out of range [0, %d)", absOff, absOff+n, lb.total)
	}
	ci, off := lb.findChunk(absOff)

	// Fast path: all bytes within one chunk — zero-copy.
	if off+n <= len(lb.chunks[ci]) {
		return lb.chunks[ci][off : off+n], nil
	}

	// Slow path: crosses chunk boundary — copy into reusable scratch.
	if cap(lb.scratch) < n {
		lb.scratch = make([]byte, n)
	}
	lb.scratch = lb.scratch[:n]
	for filled := 0; filled < n; {
		copied := copy(lb.scratch[filled:], lb.chunks[ci][off:])
		filled += copied
		ci++
		off = 0
	}
	return lb.scratch, nil
}

// CopyAt copies exactly len(dst) bytes starting at absolute offset absOff into dst.
//
// Does not move the read cursor. Works across chunk boundaries. The caller owns the result.
// Returns an error when the range [absOff, absOff+len(dst)) is out of [0, Len()).
func (lb *LargeBuffer) CopyAt(absOff int, dst []byte) error {
	n := len(dst)
	if n == 0 {
		return nil
	}
	if absOff < 0 || absOff+n > lb.total {
		return fmt.Errorf("LargeBuffer.CopyAt: [%d, %d) out of range [0, %d)", absOff, absOff+n, lb.total)
	}
	ci, off := lb.findChunk(absOff)
	for filled := 0; filled < n; {
		copied := copy(dst[filled:], lb.chunks[ci][off:])
		filled += copied
		ci++
		off = 0
	}
	return nil
}

// ── Scalar helpers ────────────────────────────────────────────────────────────
//
// Each helper reads a fixed-width integer at absOff without moving the read cursor.
// All delegate to UnsafeViewAt: zero-copy within a chunk, scratch-backed across boundaries.

// U8At reads a uint8 at absOff.
func (lb *LargeBuffer) U8At(absOff int) (uint8, error) {
	b, err := lb.UnsafeViewAt(absOff, 1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

// U16BEAt reads a big-endian uint16 at absOff.
func (lb *LargeBuffer) U16BEAt(absOff int) (uint16, error) {
	b, err := lb.UnsafeViewAt(absOff, 2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

// U32BEAt reads a big-endian uint32 at absOff.
func (lb *LargeBuffer) U32BEAt(absOff int) (uint32, error) {
	b, err := lb.UnsafeViewAt(absOff, 4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

// U64BEAt reads a big-endian uint64 at absOff.
func (lb *LargeBuffer) U64BEAt(absOff int) (uint64, error) {
	b, err := lb.UnsafeViewAt(absOff, 8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

// I16BEAt reads a big-endian int16 at absOff.
func (lb *LargeBuffer) I16BEAt(absOff int) (int16, error) {
	v, err := lb.U16BEAt(absOff)
	return int16(v), err
}

// I32BEAt reads a big-endian int32 at absOff.
func (lb *LargeBuffer) I32BEAt(absOff int) (int32, error) {
	v, err := lb.U32BEAt(absOff)
	return int32(v), err
}

// I64BEAt reads a big-endian int64 at absOff.
func (lb *LargeBuffer) I64BEAt(absOff int) (int64, error) {
	v, err := lb.U64BEAt(absOff)
	return int64(v), err
}

// U16LEAt reads a little-endian uint16 at absOff.
func (lb *LargeBuffer) U16LEAt(absOff int) (uint16, error) {
	b, err := lb.UnsafeViewAt(absOff, 2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

// U32LEAt reads a little-endian uint32 at absOff.
func (lb *LargeBuffer) U32LEAt(absOff int) (uint32, error) {
	b, err := lb.UnsafeViewAt(absOff, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

// U64LEAt reads a little-endian uint64 at absOff.
func (lb *LargeBuffer) U64LEAt(absOff int) (uint64, error) {
	b, err := lb.UnsafeViewAt(absOff, 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

// I16LEAt reads a little-endian int16 at absOff.
func (lb *LargeBuffer) I16LEAt(absOff int) (int16, error) {
	v, err := lb.U16LEAt(absOff)
	return int16(v), err
}

// I32LEAt reads a little-endian int32 at absOff.
func (lb *LargeBuffer) I32LEAt(absOff int) (int32, error) {
	v, err := lb.U32LEAt(absOff)
	return int32(v), err
}

// I64LEAt reads a little-endian int64 at absOff.
func (lb *LargeBuffer) I64LEAt(absOff int) (int64, error) {
	v, err := lb.U64LEAt(absOff)
	return int64(v), err
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
