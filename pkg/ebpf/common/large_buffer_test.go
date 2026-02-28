// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bufio"
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chunkOf returns a byte slice filled with the given byte value.
func chunkOf(b byte, n int) []byte {
	s := make([]byte, n)
	for i := range s {
		s[i] = b
	}
	return s
}

// ── Construction ─────────────────────────────────────────────────────────────

func TestNewLargeBuffer_empty(t *testing.T) {
	lb := NewLargeBuffer()

	assert.Equal(t, 0, lb.Len())
	assert.Equal(t, 0, lb.Remaining())
}

func TestNewLargeBufferFrom_wrapsWithoutCopy(t *testing.T) {
	src := []byte("hello")
	lb := NewLargeBufferFrom(src)

	assert.Equal(t, 5, lb.Len())
	assert.Equal(t, 5, lb.Remaining())

	got, err := lb.ReadN(5)
	require.NoError(t, err)
	assert.Equal(t, src, got)

	// Verify the slice is backed by the same array (zero-copy).
	assert.Equal(t, &src[0], &got[0])
}

// ── AppendChunk ───────────────────────────────────────────────────────────────

func TestAppendChunk_copiesData(t *testing.T) {
	src := []byte("world")
	lb := NewLargeBuffer()
	lb.AppendChunk(src)

	// Mutating src must not affect the buffer.
	src[0] = 'X'

	got, err := lb.ReadN(5)
	require.NoError(t, err)
	assert.Equal(t, "world", string(got))
}

func TestAppendChunk_multipleChunks(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("foo"))
	lb.AppendChunk([]byte("bar"))
	lb.AppendChunk([]byte("baz"))

	assert.Equal(t, 9, lb.Len())
	assert.Equal(t, 9, lb.Remaining())
}

// ── ReadN ─────────────────────────────────────────────────────────────────────

func TestReadN_withinChunk_zeroCopy(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abcdefgh"))

	allocs := testing.AllocsPerRun(100, func() {
		lb.ResetRead()
		_, _ = lb.ReadN(4)
	})

	assert.Equal(t, float64(0), allocs, "ReadN within a single chunk must not allocate")
}

func TestReadN_withinChunk_returnsCorrectBytes(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abcdefgh"))

	got, err := lb.ReadN(3)
	require.NoError(t, err)
	assert.Equal(t, "abc", string(got))

	got, err = lb.ReadN(3)
	require.NoError(t, err)
	assert.Equal(t, "def", string(got))

	assert.Equal(t, 2, lb.Remaining())
}

func TestReadN_crossChunk_reusesScatch(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abc"))
	lb.AppendChunk([]byte("def"))

	// Warm up scratch.
	_, _ = lb.ReadN(4)
	scratch1 := lb.scratch

	lb.ResetRead()
	_, _ = lb.ReadN(4)
	scratch2 := lb.scratch

	// Same backing array reused.
	assert.Equal(t, &scratch1[0], &scratch2[0], "scratch buffer must be reused across cross-chunk ReadN calls")
}

func TestReadN_crossChunk_returnsCorrectBytes(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abc"))
	lb.AppendChunk([]byte("def"))

	got, err := lb.ReadN(5)
	require.NoError(t, err)
	assert.Equal(t, "abcde", string(got))
}

func TestReadN_exactlyChunkBoundary(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abc"))
	lb.AppendChunk([]byte("def"))

	got, err := lb.ReadN(3)
	require.NoError(t, err)
	assert.Equal(t, "abc", string(got))

	got, err = lb.ReadN(3)
	require.NoError(t, err)
	assert.Equal(t, "def", string(got))

	assert.Equal(t, 0, lb.Remaining())
}

func TestReadN_tooManyBytes_returnsError(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hi"))

	_, err := lb.ReadN(10)
	assert.Error(t, err)
}

func TestReadN_zero_returnsNil(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hi"))

	got, err := lb.ReadN(0)
	require.NoError(t, err)
	assert.Nil(t, got)
}

// ── Slice ─────────────────────────────────────────────────────────────────────

func TestSlice_withinChunk_zeroCopy(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abcdefgh"))

	allocs := testing.AllocsPerRun(100, func() {
		lb.ResetRead()
		_, _ = lb.Slice(4)
	})

	assert.Equal(t, float64(0), allocs, "Slice within a single chunk must not allocate")
}

func TestSlice_withinChunk_retainable(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abcdef"))

	s1, err := lb.Slice(3)
	require.NoError(t, err)

	// Reading more must not overwrite s1 (it's not scratch).
	s2, err := lb.Slice(3)
	require.NoError(t, err)

	assert.Equal(t, "abc", string(s1))
	assert.Equal(t, "def", string(s2))
}

func TestSlice_crossChunk_freshAllocation(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abc"))
	lb.AppendChunk([]byte("def"))

	s, err := lb.Slice(5)
	require.NoError(t, err)
	assert.Equal(t, "abcde", string(s))

	// s must not share memory with scratch.
	if lb.scratch != nil {
		assert.NotEqual(t, &lb.scratch[0], &s[0], "Slice cross-chunk must not use scratch")
	}
}

func TestSlice_crossChunk_retainableAcrossSubsequentReads(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abc"))
	lb.AppendChunk([]byte("def"))

	// Slice across boundary — allocates fresh buffer.
	s, err := lb.Slice(4)
	require.NoError(t, err)

	// Now do a cross-chunk ReadN that would overwrite scratch.
	lb.ResetRead()
	_, _ = lb.ReadN(4) // warms scratch

	// s must be unaffected.
	assert.Equal(t, "abcd", string(s))
}

// ── Peek ──────────────────────────────────────────────────────────────────────

func TestPeek_doesNotAdvanceCursor(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hello"))

	p, err := lb.Peek(3)
	require.NoError(t, err)
	assert.Equal(t, "hel", string(p))
	assert.Equal(t, 5, lb.Remaining(), "Peek must not advance cursor")

	got, err := lb.ReadN(5)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(got))
}

func TestPeek_crossChunk(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("ab"))
	lb.AppendChunk([]byte("cd"))

	p, err := lb.Peek(3)
	require.NoError(t, err)
	assert.Equal(t, "abc", string(p))
	assert.Equal(t, 4, lb.Remaining(), "Peek must not advance cursor")
}

// ── Skip ──────────────────────────────────────────────────────────────────────

func TestSkip_withinChunk(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abcdef"))

	require.NoError(t, lb.Skip(3))
	assert.Equal(t, 3, lb.Remaining())

	got, err := lb.ReadN(3)
	require.NoError(t, err)
	assert.Equal(t, "def", string(got))
}

func TestSkip_crossChunk(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abc"))
	lb.AppendChunk([]byte("def"))

	require.NoError(t, lb.Skip(4))

	got, err := lb.ReadN(2)
	require.NoError(t, err)
	assert.Equal(t, "ef", string(got))
}

func TestSkip_tooMany_returnsError(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hi"))

	assert.Error(t, lb.Skip(10))
}

// ── Remaining ────────────────────────────────────────────────────────────────

func TestRemaining_tracksReadPosition(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abc"))
	lb.AppendChunk([]byte("def"))

	assert.Equal(t, 6, lb.Remaining())

	_, _ = lb.ReadN(2)
	assert.Equal(t, 4, lb.Remaining())

	_, _ = lb.ReadN(3)
	assert.Equal(t, 1, lb.Remaining())
}

// ── ResetRead ─────────────────────────────────────────────────────────────────

func TestResetRead_restartsFromBeginning(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hello"))

	_, _ = lb.ReadN(5)
	assert.Equal(t, 0, lb.Remaining())

	lb.ResetRead()
	assert.Equal(t, 5, lb.Remaining())

	got, err := lb.ReadN(5)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(got))
}

func TestResetRead_afterAppendChunk(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hello"))

	_, _ = lb.ReadN(5)

	lb.AppendChunk([]byte(" world"))
	lb.ResetRead()

	got, err := lb.ReadN(11)
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(got))
}

// ── Read (io.Reader) ──────────────────────────────────────────────────────────

func TestRead_ioReaderCompliance(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hello "))
	lb.AppendChunk([]byte("world"))

	all, err := io.ReadAll(lb)
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(all))
}

func TestRead_eoFOnEmpty(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hi"))

	_, _ = io.ReadAll(lb)

	n, err := lb.Read(make([]byte, 4))
	assert.Equal(t, 0, n)
	assert.Equal(t, io.EOF, err)
}

func TestRead_withBufioReader(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("GET / HTTP/1.0\r\nHost: x\r\n\r\n"))

	br := bufio.NewReader(lb)
	line, err := br.ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "GET / HTTP/1.0\r\n", line)
}

// ── Bytes ─────────────────────────────────────────────────────────────────────

func TestBytes_singleChunk_zeroCopy(t *testing.T) {
	data := []byte("hello")
	lb := NewLargeBuffer()
	lb.AppendChunk(data)

	got := lb.Bytes()

	// Single chunk: returned slice must share the same backing array.
	assert.Equal(t, &lb.chunks[0][0], &got[0], "Bytes() single-chunk must return the chunk directly")
}

func TestBytes_multiChunk_materialises(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("foo"))
	lb.AppendChunk([]byte("bar"))

	got := lb.Bytes()
	assert.Equal(t, "foobar", string(got))
}

func TestBytes_empty(t *testing.T) {
	lb := NewLargeBuffer()
	assert.Nil(t, lb.Bytes())
}

// ── Reset ─────────────────────────────────────────────────────────────────────

func TestReset_clearsAllState(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("data"))
	_, _ = lb.ReadN(2)

	lb.Reset()

	assert.Equal(t, 0, lb.Len())
	assert.Equal(t, 0, lb.Remaining())
	assert.Equal(t, 0, len(lb.chunks))
}

// ── Multi-chunk edge cases ───────────────────────────────────────────────────

func TestReadN_manySmallChunks(t *testing.T) {
	lb := NewLargeBuffer()
	expected := make([]byte, 0, 26)

	for b := byte('a'); b <= 'z'; b++ {
		lb.AppendChunk([]byte{b})
		expected = append(expected, b)
	}

	got, err := lb.ReadN(26)
	require.NoError(t, err)
	assert.Equal(t, expected, got)
}

func TestReadN_spanThreeChunks(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("ab"))
	lb.AppendChunk([]byte("cd"))
	lb.AppendChunk([]byte("ef"))

	got, err := lb.ReadN(5)
	require.NoError(t, err)
	assert.Equal(t, "abcde", string(got))
}

func TestBytes_singleChunkAfterNewLargeBufferFrom(t *testing.T) {
	src := []byte("direct")
	lb := NewLargeBufferFrom(src)

	got := lb.Bytes()
	assert.Equal(t, src, got)
	assert.Equal(t, &src[0], &got[0], "NewLargeBufferFrom Bytes() must not copy")
}

// ── Interleaved reads across all methods ─────────────────────────────────────

func TestInterleaved_peekReadSkip(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abcdefghij"))

	p, err := lb.Peek(3)
	require.NoError(t, err)
	assert.Equal(t, "abc", string(p))

	got, err := lb.ReadN(2)
	require.NoError(t, err)
	assert.Equal(t, "ab", string(got))

	require.NoError(t, lb.Skip(3))

	got, err = lb.Slice(5)
	require.NoError(t, err)
	assert.Equal(t, "fghij", string(got))

	assert.Equal(t, 0, lb.Remaining())
}

// ── Zero-alloc verification for hot path ─────────────────────────────────────

func TestReadN_singleChunk_zeroAllocsWithBinaryDecode(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk(bytes.Repeat([]byte{0x01}, 64))

	allocs := testing.AllocsPerRun(1000, func() {
		lb.ResetRead()
		for lb.Remaining() >= 4 {
			b, _ := lb.ReadN(4)
			_ = b[0] | b[1] | b[2] | b[3] // simulate scalar decode
		}
	})

	assert.Equal(t, float64(0), allocs, "hot path (single-chunk scalar decoding) must be zero-alloc")
}
