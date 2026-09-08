// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package largebuf

import (
	"bytes"
	"math"
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCursorMethodsIntegerBoundaries(t *testing.T) {
	data := []byte("abcdefgh")
	lb := chunkedLargeBuffer(data, []byte{2, 3, 1})

	tests := []struct {
		name     string
		call     func(*LargeBufferReader, int) ([]byte, error)
		advances bool
	}{
		{name: "ReadN", call: func(r *LargeBufferReader, n int) ([]byte, error) {
			return r.ReadN(n)
		}, advances: true},
		{name: "Peek", call: func(r *LargeBufferReader, n int) ([]byte, error) {
			return r.Peek(n)
		}},
		{name: "Skip", call: func(r *LargeBufferReader, n int) ([]byte, error) {
			return nil, r.Skip(n)
		}, advances: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, n := range []int{-1, len(data), math.MaxInt} {
				r := lb.NewReader()
				require.NoError(t, r.Skip(1))
				before := r.ReadOffset()

				_, err := test.call(&r, n)
				require.Error(t, err, "size %d", n)
				assert.Equal(t, before, r.ReadOffset(), "size %d moved cursor", n)
			}

			r := lb.NewReader()
			require.NoError(t, r.Skip(1))
			got, err := test.call(&r, 0)
			require.NoError(t, err)
			assert.Empty(t, got)
			assert.Equal(t, 1, r.ReadOffset())

			remaining := r.Remaining()
			got, err = test.call(&r, remaining)
			require.NoError(t, err)
			if test.name != "Skip" {
				assert.Equal(t, data[1:], got)
			}
			if test.advances {
				assert.Equal(t, len(data), r.ReadOffset())
			} else {
				assert.Equal(t, 1, r.ReadOffset())
			}
		})
	}
}

func TestAbsoluteMethodsIntegerBoundaries(t *testing.T) {
	data := []byte("abcdefgh")
	lb := chunkedLargeBuffer(data, []byte{2, 3, 1})
	first := lb.NewReader()
	second := lb.NewReader()
	require.NoError(t, first.Skip(1))
	require.NoError(t, second.Skip(5))
	assertCursors := func(t *testing.T) {
		t.Helper()
		assert.Equal(t, 1, first.ReadOffset())
		assert.Equal(t, 5, second.ReadOffset())
	}

	for _, tc := range []struct {
		name      string
		offset, n int
		want      []byte
	}{
		{name: "zero at start", offset: 0, n: 0, want: []byte{}},
		{name: "zero at end", offset: len(data), n: 0, want: []byte{}},
		{name: "exact end", offset: 1, n: len(data) - 1, want: data[1:]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := lb.UnsafeViewAt(tc.offset, tc.n)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
			assertCursors(t)
		})
	}

	for _, tc := range []struct {
		name      string
		offset, n int
	}{
		{name: "negative offset", offset: -1, n: 0},
		{name: "negative size", offset: 0, n: -1},
		{name: "past end", offset: len(data) + 1, n: 0},
		{name: "max offset", offset: math.MaxInt, n: 1},
		{name: "overflowing end", offset: 1, n: math.MaxInt},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := lb.UnsafeViewAt(tc.offset, tc.n)
			require.Error(t, err)
			assertCursors(t)
		})
	}

	dst := make([]byte, len(data)-1)
	require.NoError(t, lb.CopyAt(1, dst))
	assert.Equal(t, data[1:], dst)
	assertCursors(t)
	require.NoError(t, lb.CopyAt(len(data), nil))
	assertCursors(t)

	for _, tc := range []struct {
		offset int
		dst    []byte
	}{
		{offset: -1, dst: []byte{0xa5}},
		{offset: len(data) + 1, dst: []byte{}},
		{offset: math.MaxInt, dst: []byte{0xa5, 0xa5}},
	} {
		before := append([]byte(nil), tc.dst...)
		err := lb.CopyAt(tc.offset, tc.dst)
		require.Error(t, err, "offset %d", tc.offset)
		assert.True(t, bytes.Equal(before, tc.dst), "offset %d modified destination", tc.offset)
		assertCursors(t)
	}
}

func TestChunkLayoutsMatchFlatOracle(t *testing.T) {
	rng := rand.New(rand.NewPCG(20260803, 1))

	for range 64 {
		data := make([]byte, 1+rng.IntN(64))
		layout := make([]byte, 1+rng.IntN(16))
		for i := range data {
			data[i] = byte(rng.Uint32())
		}
		for i := range layout {
			layout[i] = byte(rng.Uint32())
		}
		lb := chunkedLargeBuffer(data, layout)

		for range 16 {
			offset := rng.IntN(len(data) + 1)
			n := rng.IntN(len(data) - offset + 1)
			want := data[offset : offset+n]

			got, err := lb.UnsafeViewAt(offset, n)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(want, got))

			dst := make([]byte, n)
			require.NoError(t, lb.CopyAt(offset, dst))
			assert.True(t, bytes.Equal(want, dst))

			reader := lb.NewReader()
			other := lb.NewReader()
			require.NoError(t, reader.Skip(offset))
			before := reader.ReadOffset()
			got, err = reader.Peek(n)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(want, got))
			assert.Equal(t, before, reader.ReadOffset())
			got, err = reader.ReadN(n)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(want, got))
			assert.Equal(t, offset+n, reader.ReadOffset())
			assert.Zero(t, other.ReadOffset())
		}
	}
}

func TestCrossChunkScratchReuse(t *testing.T) {
	lb := chunkedLargeBuffer([]byte("abcdef"), []byte{2, 2})

	_, err := lb.UnsafeViewAt(1, 4)
	require.NoError(t, err)
	absoluteScratch := &lb.scratch[0]
	_, err = lb.UnsafeViewAt(0, 4)
	require.NoError(t, err)
	assert.Equal(t, absoluteScratch, &lb.scratch[0])

	r := lb.NewReader()
	_, err = r.ReadN(4)
	require.NoError(t, err)
	readerScratch := &r.scratch[0]
	r.Reset()
	_, err = r.Peek(4)
	require.NoError(t, err)
	assert.Equal(t, readerScratch, &r.scratch[0])
	assert.Zero(t, r.ReadOffset())
}

func FuzzLargeBuffer(f *testing.F) {
	f.Add([]byte("abcdef"), []byte{2, 1}, 1, 4)
	f.Add([]byte("abcdef"), []byte{1}, -1, 1)
	f.Add([]byte("abcdef"), []byte{3, 2}, 1, math.MaxInt)
	f.Add([]byte("abcdef"), []byte{2}, math.MaxInt, 1)
	f.Add([]byte("abcdef"), []byte{2, 2}, 6, 0)

	f.Fuzz(func(t *testing.T, input, layout []byte, offset, n int) {
		if len(input) > 256 || len(layout) > 64 {
			t.Skip()
		}
		lb := chunkedLargeBuffer(input, layout)
		valid := offset >= 0 && n >= 0 && offset <= len(input) && n <= len(input)-offset

		got, err := lb.UnsafeViewAt(offset, n)
		if valid {
			require.NoError(t, err)
			assert.True(t, bytes.Equal(input[offset:offset+n], got))
		} else {
			require.Error(t, err)
		}

		for _, operation := range []struct {
			name     string
			call     func(*LargeBufferReader, int) ([]byte, error)
			advances bool
		}{
			{name: "ReadN", call: func(r *LargeBufferReader, n int) ([]byte, error) {
				return r.ReadN(n)
			}, advances: true},
			{name: "Peek", call: func(r *LargeBufferReader, n int) ([]byte, error) {
				return r.Peek(n)
			}},
			{name: "Skip", call: func(r *LargeBufferReader, n int) ([]byte, error) {
				return nil, r.Skip(n)
			}, advances: true},
		} {
			t.Run(operation.name, func(t *testing.T) {
				r := lb.NewReader()
				got, err := operation.call(&r, n)
				if n < 0 || n > len(input) {
					require.Error(t, err)
					assert.Zero(t, r.ReadOffset())
					return
				}
				require.NoError(t, err)
				if operation.name != "Skip" {
					assert.True(t, bytes.Equal(input[:n], got))
				}
				if operation.advances {
					assert.Equal(t, n, r.ReadOffset())
				} else {
					assert.Zero(t, r.ReadOffset())
				}
			})
		}

		copyN := n
		if copyN < 0 || copyN > len(input)+1 {
			copyN = 1
		}
		dst := make([]byte, copyN)
		for i := range dst {
			dst[i] = 0xa5
		}
		before := append([]byte(nil), dst...)
		copyValid := offset >= 0 && offset <= len(input) && copyN <= len(input)-offset
		err = lb.CopyAt(offset, dst)
		if copyValid {
			require.NoError(t, err)
			assert.True(t, bytes.Equal(input[offset:offset+copyN], dst))
		} else {
			require.Error(t, err)
			assert.True(t, bytes.Equal(before, dst))
		}
	})
}

func chunkedLargeBuffer(data, layout []byte) *LargeBuffer {
	lb := NewLargeBuffer()
	lb.AppendChunk(nil)
	position := 0
	for _, width := range layout {
		if position == len(data) {
			break
		}
		n := min(int(width)%8+1, len(data)-position)
		lb.AppendChunk(data[position : position+n])
		position += n
	}
	if position < len(data) {
		lb.AppendChunk(data[position:])
	}

	return lb
}
