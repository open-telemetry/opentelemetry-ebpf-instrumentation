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

// ── Construction ─────────────────────────────────────────────────────────────

func TestNewLargeBuffer_empty(t *testing.T) {
	lb := NewLargeBuffer()
	r := lb.NewReader()

	assert.Equal(t, 0, lb.Len())
	assert.Equal(t, 0, r.Remaining())
}

func TestNewLargeBufferFrom_wrapsWithoutCopy(t *testing.T) {
	src := []byte("hello")
	lb := NewLargeBufferFrom(src)
	r := lb.NewReader()

	assert.Equal(t, 5, lb.Len())
	assert.Equal(t, 5, r.Remaining())

	got, err := r.ReadN(5)
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

	got, err := lb.NewReader().ReadN(5)
	require.NoError(t, err)
	assert.Equal(t, "world", string(got))
}

func TestAppendChunk_multipleChunks(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("foo"))
	lb.AppendChunk([]byte("bar"))
	lb.AppendChunk([]byte("baz"))

	assert.Equal(t, 9, lb.Len())
	assert.Equal(t, 9, lb.NewReader().Remaining())
}

// ── ReadN ─────────────────────────────────────────────────────────────────────

func TestReadN_withinChunk_zeroCopy(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abcdefgh"))

	r := lb.NewReader()
	allocs := testing.AllocsPerRun(100, func() {
		r.Reset()
		_, _ = r.ReadN(4)
	})

	assert.InDelta(t, float64(0), allocs, 0, "ReadN within a single chunk must not allocate")
}

func TestReadN_withinChunk_returnsCorrectBytes(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abcdefgh"))
	r := lb.NewReader()

	got, err := r.ReadN(3)
	require.NoError(t, err)
	assert.Equal(t, "abc", string(got))

	got, err = r.ReadN(3)
	require.NoError(t, err)
	assert.Equal(t, "def", string(got))

	assert.Equal(t, 2, r.Remaining())
}

func TestReadN_crossChunk_reusesScatch(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abc"))
	lb.AppendChunk([]byte("def"))

	r := lb.NewReader()

	// Warm up scratch.
	_, _ = r.ReadN(4)
	scratch1 := r.scratch

	r.Reset()
	_, _ = r.ReadN(4)
	scratch2 := r.scratch

	// Same backing array reused.
	assert.Equal(t, &scratch1[0], &scratch2[0], "scratch buffer must be reused across cross-chunk ReadN calls")
}

func TestReadN_crossChunk_returnsCorrectBytes(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abc"))
	lb.AppendChunk([]byte("def"))

	got, err := lb.NewReader().ReadN(5)
	require.NoError(t, err)
	assert.Equal(t, "abcde", string(got))
}

func TestReadN_exactlyChunkBoundary(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abc"))
	lb.AppendChunk([]byte("def"))
	r := lb.NewReader()

	got, err := r.ReadN(3)
	require.NoError(t, err)
	assert.Equal(t, "abc", string(got))

	got, err = r.ReadN(3)
	require.NoError(t, err)
	assert.Equal(t, "def", string(got))

	assert.Equal(t, 0, r.Remaining())
}

func TestReadN_tooManyBytes_returnsError(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hi"))

	_, err := lb.NewReader().ReadN(10)
	assert.Error(t, err)
}

func TestReadN_zero_returnsNil(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hi"))

	got, err := lb.NewReader().ReadN(0)
	require.NoError(t, err)
	assert.Nil(t, got)
}

// ── Peek ──────────────────────────────────────────────────────────────────────

func TestPeek_doesNotAdvanceCursor(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hello"))
	r := lb.NewReader()

	p, err := r.Peek(3)
	require.NoError(t, err)
	assert.Equal(t, "hel", string(p))
	assert.Equal(t, 5, r.Remaining(), "Peek must not advance cursor")

	got, err := r.ReadN(5)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(got))
}

func TestPeek_crossChunk(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("ab"))
	lb.AppendChunk([]byte("cd"))
	r := lb.NewReader()

	p, err := r.Peek(3)
	require.NoError(t, err)
	assert.Equal(t, "abc", string(p))
	assert.Equal(t, 4, r.Remaining(), "Peek must not advance cursor")
}

// ── Skip ──────────────────────────────────────────────────────────────────────

func TestSkip_withinChunk(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abcdef"))
	r := lb.NewReader()

	require.NoError(t, r.Skip(3))
	assert.Equal(t, 3, r.Remaining())

	got, err := r.ReadN(3)
	require.NoError(t, err)
	assert.Equal(t, "def", string(got))
}

func TestSkip_crossChunk(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abc"))
	lb.AppendChunk([]byte("def"))
	r := lb.NewReader()

	require.NoError(t, r.Skip(4))

	got, err := r.ReadN(2)
	require.NoError(t, err)
	assert.Equal(t, "ef", string(got))
}

func TestSkip_tooMany_returnsError(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hi"))

	assert.Error(t, lb.NewReader().Skip(10))
}

// ── Remaining ────────────────────────────────────────────────────────────────

func TestRemaining_tracksReadPosition(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abc"))
	lb.AppendChunk([]byte("def"))
	r := lb.NewReader()

	assert.Equal(t, 6, r.Remaining())

	_, _ = r.ReadN(2)
	assert.Equal(t, 4, r.Remaining())

	_, _ = r.ReadN(3)
	assert.Equal(t, 1, r.Remaining())
}

// ── Reset ─────────────────────────────────────────────────────────────────────

func TestReaderReset_restartsFromBeginning(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hello"))
	r := lb.NewReader()

	_, _ = r.ReadN(5)
	assert.Equal(t, 0, r.Remaining())

	r.Reset()
	assert.Equal(t, 5, r.Remaining())

	got, err := r.ReadN(5)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(got))
}

func TestReaderReset_afterAppendChunk(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hello"))
	r := lb.NewReader()
	_, _ = r.ReadN(5)

	lb.AppendChunk([]byte(" world"))
	r.Reset()

	got, err := r.ReadN(11)
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(got))
}

// ── Read (io.Reader) ──────────────────────────────────────────────────────────

func TestRead_ioReaderCompliance(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hello "))
	lb.AppendChunk([]byte("world"))

	all, err := io.ReadAll(lb.NewReader())
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(all))
}

func TestRead_eoFOnEmpty(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hi"))
	r := lb.NewReader()

	_, _ = io.ReadAll(r)

	n, err := r.Read(make([]byte, 4))
	assert.Equal(t, 0, n)
	assert.Equal(t, io.EOF, err)
}

func TestRead_withBufioReader(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("GET / HTTP/1.0\r\nHost: x\r\n\r\n"))

	br := bufio.NewReader(lb.NewReader())
	line, err := br.ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "GET / HTTP/1.0\r\n", line)
}

// ── Bytes (cursor-aware, non-advancing) ──────────────────────────────────────

func TestBytes_cursorAtZero_singleChunk_zeroCopy(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hello"))
	r := lb.NewReader()

	got := r.Bytes()

	// Cursor at start, single chunk: sub-slice of chunk's backing array — zero-copy.
	assert.Equal(t, &lb.chunks[0][0], &got[0], "Bytes() at cursor=0 single-chunk must be zero-copy")
	assert.Equal(t, "hello", string(got))
	assert.Equal(t, 5, r.Remaining(), "Bytes() must not advance cursor")
}

func TestBytes_cursorAware_returnsUnreadPortion(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abcdef"))
	r := lb.NewReader()
	_, _ = r.ReadN(3) // advance cursor past first 3 bytes

	got := r.Bytes()
	assert.Equal(t, "def", string(got))
	assert.Equal(t, 3, r.Remaining(), "Bytes() must not advance cursor")
}

func TestBytes_multiChunk(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("foo"))
	lb.AppendChunk([]byte("bar"))
	r := lb.NewReader()

	got := r.Bytes()
	assert.Equal(t, "foobar", string(got))
	assert.Equal(t, 6, r.Remaining(), "Bytes() must not advance cursor")
}

func TestBytes_empty(t *testing.T) {
	lb := NewLargeBuffer()
	assert.Nil(t, lb.NewReader().Bytes())
}

func TestBytes_afterReadAll_returnsNil(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hi"))
	r := lb.NewReader()
	_, _ = r.ReadN(2)

	assert.Nil(t, r.Bytes(), "Bytes() at end of buffer must return nil")
}

func TestBytes_singleChunk_isSharedView(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hello"))

	got := lb.NewReader().Bytes()

	// Bytes() returns a view into the internal chunk — mutating it affects the chunk.
	got[0] = 'X'
	assert.Equal(t, "Xello", string(lb.chunks[0]), "Bytes() single-chunk must be a shared view, not a copy")
}

func TestBytes_newLargeBufferFrom_isSharedView(t *testing.T) {
	src := []byte("hello")
	lb := NewLargeBufferFrom(src)

	got := lb.NewReader().Bytes()

	// Bytes() returns a view into src — mutating it affects the original slice.
	got[0] = 'X'
	assert.Equal(t, "Xello", string(src), "Bytes() on NewLargeBufferFrom must be a shared view into src")
}

// ── CloneBytes (cursor-independent) ──────────────────────────────────────────

func TestCloneBytes_singleChunk_alwaysCopies(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hello"))

	got := lb.CloneBytes()
	assert.Equal(t, "hello", string(got))

	// Mutate the returned slice — the internal chunk must be unaffected.
	got[0] = 'X'
	assert.Equal(t, "hello", string(lb.chunks[0]), "CloneBytes() must return an independent copy")
}

func TestCloneBytes_multiChunk_materializes(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("foo"))
	lb.AppendChunk([]byte("bar"))

	got := lb.CloneBytes()
	assert.Equal(t, "foobar", string(got))
}

func TestCloneBytes_cursorIndependent(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abcdef"))
	r := lb.NewReader()
	_, _ = r.ReadN(3) // advance cursor past first 3 bytes

	got := lb.CloneBytes()
	// CloneBytes always returns all chunks regardless of cursor position.
	assert.Equal(t, "abcdef", string(got))
}

func TestCloneBytes_empty(t *testing.T) {
	lb := NewLargeBuffer()
	assert.Nil(t, lb.CloneBytes())
}

// ── Reset ─────────────────────────────────────────────────────────────────────

func TestReset_clearsAllState(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("data"))

	lb.Reset()

	assert.Equal(t, 0, lb.Len())
	assert.Empty(t, lb.chunks)
}

func TestReset_allowsReuse(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("first"))
	lb.AppendChunk([]byte("pass"))

	// Populate scratch via a cross-chunk UnsafeView.
	_ = lb.UnsafeView()
	scratch := lb.scratch

	lb.Reset()
	assert.Equal(t, 0, lb.Len())
	assert.True(t, lb.IsEmpty())

	// Reuse: append new data and read it back correctly.
	lb.AppendChunk([]byte("second pass"))
	got := lb.UnsafeView()
	assert.Equal(t, "second pass", string(got))

	// Reset must not free the scratch backing array.
	assert.Equal(t, &scratch[0], &lb.scratch[0], "scratch backing array must survive Reset")
}

// ── Multi-chunk edge cases ───────────────────────────────────────────────────

func TestReadN_manySmallChunks(t *testing.T) {
	lb := NewLargeBuffer()
	expected := make([]byte, 0, 26)

	for b := byte('a'); b <= 'z'; b++ {
		lb.AppendChunk([]byte{b})
		expected = append(expected, b)
	}

	got, err := lb.NewReader().ReadN(26)
	require.NoError(t, err)
	assert.Equal(t, expected, got)
}

func TestReadN_spanThreeChunks(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("ab"))
	lb.AppendChunk([]byte("cd"))
	lb.AppendChunk([]byte("ef"))

	got, err := lb.NewReader().ReadN(5)
	require.NoError(t, err)
	assert.Equal(t, "abcde", string(got))
}

func TestCloneBytes_singleChunkAfterNewLargeBufferFrom(t *testing.T) {
	src := []byte("direct")
	lb := NewLargeBufferFrom(src)

	got := lb.CloneBytes()
	assert.Equal(t, "direct", string(got))

	// Mutate the returned slice — src must be unaffected.
	got[0] = 'X'
	assert.Equal(t, "direct", string(src), "CloneBytes() must return an independent copy")
}

// ── Interleaved reads across all methods ─────────────────────────────────────

func TestInterleaved_peekReadSkip(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abcdefghij"))
	r := lb.NewReader()

	p, err := r.Peek(3)
	require.NoError(t, err)
	assert.Equal(t, "abc", string(p))

	got, err := r.ReadN(2)
	require.NoError(t, err)
	assert.Equal(t, "ab", string(got))

	require.NoError(t, r.Skip(3))

	got, err = r.ReadN(5)
	require.NoError(t, err)
	assert.Equal(t, "fghij", string(got))

	assert.Equal(t, 0, r.Remaining())
}

// ── ReadOffset / BaseOffset / IsEmpty ────────────────────────────────────────

func TestReadOffset_tracksAdvancingCursor(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abcdef"))
	r := lb.NewReader()

	assert.Equal(t, 0, r.ReadOffset())

	_, _ = r.ReadN(3)
	assert.Equal(t, 3, r.ReadOffset())

	_, _ = r.ReadN(3)
	assert.Equal(t, 6, r.ReadOffset())
}

func TestReadOffset_afterReset(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hello"))
	r := lb.NewReader()
	_, _ = r.ReadN(5)

	r.Reset()
	assert.Equal(t, 0, r.ReadOffset())
}

func TestBaseOffset_alwaysZero(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("anything"))
	r := lb.NewReader()
	_, _ = r.ReadN(4)

	assert.Equal(t, 0, r.BaseOffset())
}

func TestIsEmpty(t *testing.T) {
	lb := NewLargeBuffer()
	assert.True(t, lb.IsEmpty())

	lb.AppendChunk([]byte("x"))
	assert.False(t, lb.IsEmpty())

	r := lb.NewReader()
	_, _ = r.ReadN(1) // cursor at end, but buffer is not empty
	assert.False(t, lb.IsEmpty())
}

// ── findChunk ─────────────────────────────────────────────────────────────────

func TestFindChunk_singleChunk(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abcde"))

	ci, off := lb.findChunk(0)
	assert.Equal(t, 0, ci)
	assert.Equal(t, 0, off)

	ci, off = lb.findChunk(4)
	assert.Equal(t, 0, ci)
	assert.Equal(t, 4, off)
}

func TestFindChunk_multiChunk(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abc")) // offsets 0-2
	lb.AppendChunk([]byte("de"))  // offsets 3-4
	lb.AppendChunk([]byte("fgh")) // offsets 5-7

	ci, off := lb.findChunk(3)
	assert.Equal(t, 1, ci)
	assert.Equal(t, 0, off)

	ci, off = lb.findChunk(5)
	assert.Equal(t, 2, ci)
	assert.Equal(t, 0, off)

	ci, off = lb.findChunk(7)
	assert.Equal(t, 2, ci)
	assert.Equal(t, 2, off)
}

func TestFindChunk_outOfRange(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abc"))

	ci, _ := lb.findChunk(3)
	assert.Equal(t, -1, ci)

	ci, _ = lb.findChunk(-1)
	assert.Equal(t, -1, ci)
}

// ── UnsafeViewAt ──────────────────────────────────────────────────────────────

func TestUnsafeViewAt_withinSingleChunk_zeroCopy(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abcdefgh"))

	got, err := lb.UnsafeViewAt(2, 3)
	require.NoError(t, err)
	assert.Equal(t, "cde", string(got))
	// Verify it's a sub-slice of the chunk (zero-copy).
	assert.Equal(t, &lb.chunks[0][2], &got[0])
}

func TestUnsafeViewAt_crossBoundary_usesScratch(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abc")) // offsets 0-2
	lb.AppendChunk([]byte("def")) // offsets 3-5

	// Read straddling the boundary.
	got, err := lb.UnsafeViewAt(1, 4) // "bcde"
	require.NoError(t, err)
	assert.Equal(t, "bcde", string(got))
}

func TestUnsafeViewAt_doesNotMoveCursor(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hello"))
	r := lb.NewReader()

	before := r.ReadOffset()
	_, err := lb.UnsafeViewAt(1, 3)
	require.NoError(t, err)
	assert.Equal(t, before, r.ReadOffset())
}

func TestUnsafeViewAt_outOfRange_returnsError(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hi"))

	_, err := lb.UnsafeViewAt(1, 5)
	require.Error(t, err)

	_, err = lb.UnsafeViewAt(-1, 1)
	require.Error(t, err)

	_, err = lb.UnsafeViewAt(0, -1)
	require.Error(t, err)
}

func TestUnsafeViewAt_zero_returnsEmpty(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hi"))

	got, err := lb.UnsafeViewAt(0, 0)
	require.NoError(t, err)
	assert.NotNil(t, got)
	assert.Empty(t, got)
}

func TestUnsafeViewAt_scratchReuseSemantics(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abc"))
	lb.AppendChunk([]byte("def"))

	// First cross-chunk call — allocates scratch (4 bytes).
	got1, _ := lb.UnsafeViewAt(1, 4) // "bcde"
	scratch1 := lb.scratch

	// Second cross-chunk call with same size — reuses scratch.
	got2, _ := lb.UnsafeViewAt(0, 4) // "abcd"
	scratch2 := lb.scratch

	assert.Equal(t, &scratch1[0], &scratch2[0], "scratch buffer must be reused")
	// got1 is now stale (points at same scratch as got2 but overwritten).
	assert.Equal(t, "abcd", string(got2))
	_ = got1 // intentionally not asserted — it is stale
}

// ── UnsafeView ───────────────────────────────────────────────────────────────

func TestUnsafeView_empty_returnsNil(t *testing.T) {
	lb := NewLargeBuffer()
	assert.Nil(t, lb.UnsafeView())
}

func TestUnsafeView_singleChunk_zeroCopy(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hello"))

	got := lb.UnsafeView()
	assert.Equal(t, "hello", string(got))
	// Single chunk: must be a direct sub-slice of the chunk's backing array.
	assert.Equal(t, &lb.chunks[0][0], &got[0], "UnsafeView single-chunk must be zero-copy")
}

func TestUnsafeView_multiChunk_materializes(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("foo"))
	lb.AppendChunk([]byte("bar"))

	got := lb.UnsafeView()
	assert.Equal(t, "foobar", string(got))
}

func TestUnsafeView_scratchReuseSemantics(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abc"))
	lb.AppendChunk([]byte("def"))

	lb.UnsafeView() // cross-chunk → allocates scratch
	scratch1 := lb.scratch

	lb.UnsafeView() // second call — reuses scratch
	scratch2 := lb.scratch

	assert.Equal(t, &scratch1[0], &scratch2[0], "UnsafeView must reuse scratch across calls")
}

// ── CopyAt ────────────────────────────────────────────────────────────────────

func TestCopyAt_withinSingleChunk(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abcdefgh"))

	dst := make([]byte, 4)
	require.NoError(t, lb.CopyAt(2, dst))
	assert.Equal(t, "cdef", string(dst))
}

func TestCopyAt_crossBoundary(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abc"))
	lb.AppendChunk([]byte("def"))

	dst := make([]byte, 4)
	require.NoError(t, lb.CopyAt(1, dst))
	assert.Equal(t, "bcde", string(dst))
}

func TestCopyAt_doesNotMoveCursor(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hello"))
	r := lb.NewReader()

	before := r.ReadOffset()
	dst := make([]byte, 3)
	require.NoError(t, lb.CopyAt(1, dst))
	assert.Equal(t, before, r.ReadOffset())
}

func TestCopyAt_outOfRange_returnsError(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hi"))

	require.Error(t, lb.CopyAt(0, make([]byte, 10)))
	require.Error(t, lb.CopyAt(-1, make([]byte, 1)))
}

func TestCopyAt_alwaysOwned(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("hello"))

	dst := make([]byte, 5)
	require.NoError(t, lb.CopyAt(0, dst))

	// Mutating dst must not affect the chunk.
	dst[0] = 'X'
	assert.Equal(t, "hello", string(lb.chunks[0]))
}

// ── Scalar helpers — big-endian ───────────────────────────────────────────────

func TestScalarBE_withinSingleChunk(t *testing.T) {
	lb := NewLargeBuffer()
	// Lay out known bytes at known offsets.
	// offset 0: U8 = 0x42
	// offset 1: U16BE = 0x0102
	// offset 3: U32BE = 0x01020304
	// offset 7: U64BE = 0x0102030405060708
	data := []byte{
		0x42,
		0x01, 0x02,
		0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
	lb.AppendChunk(data)

	u8, err := lb.U8At(0)
	require.NoError(t, err)
	assert.Equal(t, uint8(0x42), u8)

	u16, err := lb.U16BEAt(1)
	require.NoError(t, err)
	assert.Equal(t, uint16(0x0102), u16)

	u32, err := lb.U32BEAt(3)
	require.NoError(t, err)
	assert.Equal(t, uint32(0x01020304), u32)

	u64, err := lb.U64BEAt(7)
	require.NoError(t, err)
	assert.Equal(t, uint64(0x0102030405060708), u64)

	i16, err := lb.I16BEAt(1)
	require.NoError(t, err)
	assert.Equal(t, int16(0x0102), i16)

	i32, err := lb.I32BEAt(3)
	require.NoError(t, err)
	assert.Equal(t, int32(0x01020304), i32)

	i64, err := lb.I64BEAt(7)
	require.NoError(t, err)
	assert.Equal(t, int64(0x0102030405060708), i64)
}

func TestScalarBE_crossChunkBoundary(t *testing.T) {
	// Split so that the U32 straddles the boundary: chunk0=[0x01,0x02], chunk1=[0x03,0x04,...]
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte{0x01, 0x02})
	lb.AppendChunk([]byte{0x03, 0x04, 0x05, 0x06, 0x07, 0x08})

	u32, err := lb.U32BEAt(0)
	require.NoError(t, err)
	assert.Equal(t, uint32(0x01020304), u32)

	u64, err := lb.U64BEAt(0)
	require.NoError(t, err)
	assert.Equal(t, uint64(0x0102030405060708), u64)
}

func TestScalarBE_signedNegativeValues(t *testing.T) {
	lb := NewLargeBuffer()
	// -1 as int16 BE = 0xFF 0xFF
	lb.AppendChunk([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})

	i16, err := lb.I16BEAt(0)
	require.NoError(t, err)
	assert.Equal(t, int16(-1), i16)

	i32, err := lb.I32BEAt(0)
	require.NoError(t, err)
	assert.Equal(t, int32(-1), i32)

	i64, err := lb.I64BEAt(0)
	require.NoError(t, err)
	assert.Equal(t, int64(-1), i64)
}

// ── Scalar helpers — little-endian ────────────────────────────────────────────

func TestScalarLE_withinSingleChunk(t *testing.T) {
	lb := NewLargeBuffer()
	// offset 0: U16LE = 0x0201 → value 0x0102 read as LE
	// offset 2: U32LE = 0x04030201
	// offset 6: U64LE = 0x0807060504030201
	data := []byte{
		0x02, 0x01,
		0x04, 0x03, 0x02, 0x01,
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	}
	lb.AppendChunk(data)

	u16, err := lb.U16LEAt(0)
	require.NoError(t, err)
	assert.Equal(t, uint16(0x0102), u16)

	u32, err := lb.U32LEAt(2)
	require.NoError(t, err)
	assert.Equal(t, uint32(0x01020304), u32)

	u64, err := lb.U64LEAt(6)
	require.NoError(t, err)
	assert.Equal(t, uint64(0x0102030405060708), u64)

	i16, err := lb.I16LEAt(0)
	require.NoError(t, err)
	assert.Equal(t, int16(0x0102), i16)

	i32, err := lb.I32LEAt(2)
	require.NoError(t, err)
	assert.Equal(t, int32(0x01020304), i32)

	i64, err := lb.I64LEAt(6)
	require.NoError(t, err)
	assert.Equal(t, int64(0x0102030405060708), i64)
}

func TestScalarLE_crossChunkBoundary(t *testing.T) {
	// U32LE straddles boundary: chunk0=[0x04,0x03], chunk1=[0x02,0x01,...]
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte{0x04, 0x03})
	lb.AppendChunk([]byte{0x02, 0x01, 0x08, 0x07, 0x06, 0x05})

	u32, err := lb.U32LEAt(0)
	require.NoError(t, err)
	assert.Equal(t, uint32(0x01020304), u32)

	u64, err := lb.U64LEAt(0)
	require.NoError(t, err)
	assert.Equal(t, uint64(0x0506070801020304), u64)
}

func TestScalarLE_signedNegativeValues(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})

	i16, err := lb.I16LEAt(0)
	require.NoError(t, err)
	assert.Equal(t, int16(-1), i16)

	i32, err := lb.I32LEAt(0)
	require.NoError(t, err)
	assert.Equal(t, int32(-1), i32)

	i64, err := lb.I64LEAt(0)
	require.NoError(t, err)
	assert.Equal(t, int64(-1), i64)
}

func TestScalar_outOfRange_returnsError(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte{0x01, 0x02})

	_, err := lb.U8At(2)
	require.Error(t, err)

	_, err = lb.U32BEAt(0) // only 2 bytes, needs 4
	require.Error(t, err)

	_, err = lb.U32LEAt(0)
	require.Error(t, err)
}

func TestCursorUnchanged_byAbsoluteOffsetMethods(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abcdefgh"))
	r := lb.NewReader()

	_, _ = r.ReadN(3) // advance cursor to 3
	before := r.ReadOffset()

	_, _ = lb.UnsafeViewAt(0, 4)
	assert.Equal(t, before, r.ReadOffset(), "UnsafeViewAt must not move cursor")

	_ = lb.CopyAt(0, make([]byte, 4))
	assert.Equal(t, before, r.ReadOffset(), "CopyAt must not move cursor")

	_, _ = lb.U32BEAt(0)
	assert.Equal(t, before, r.ReadOffset(), "U32BEAt must not move cursor")

	_, _ = lb.U32LEAt(0)
	assert.Equal(t, before, r.ReadOffset(), "U32LEAt must not move cursor")
}

// ── Zero-alloc verification for hot path ─────────────────────────────────────

func TestReadN_singleChunk_zeroAllocsWithBinaryDecode(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk(bytes.Repeat([]byte{0x01}, 64))

	r := lb.NewReader()
	allocs := testing.AllocsPerRun(1000, func() {
		r.Reset()
		for r.Remaining() >= 4 {
			b, _ := r.ReadN(4)
			_ = b[0] | b[1] | b[2] | b[3] // simulate scalar decode
		}
	})

	assert.InDelta(t, float64(0), allocs, 0, "hot path (single-chunk scalar decoding) must be zero-alloc")
}

// ── Multiple readers on same buffer ──────────────────────────────────────────

func TestMultipleReaders_independent(t *testing.T) {
	lb := NewLargeBuffer()
	lb.AppendChunk([]byte("abcdef"))

	r1 := lb.NewReader()
	r2 := lb.NewReader()

	got1, err := r1.ReadN(3)
	require.NoError(t, err)
	assert.Equal(t, "abc", string(got1))

	// r2 is unaffected by r1's advance.
	got2, err := r2.ReadN(6)
	require.NoError(t, err)
	assert.Equal(t, "abcdef", string(got2))

	// r1 can continue from where it left off.
	got1, err = r1.ReadN(3)
	require.NoError(t, err)
	assert.Equal(t, "def", string(got1))
}
