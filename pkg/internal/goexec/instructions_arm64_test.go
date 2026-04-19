// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build arm64

package goexec

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// RET encodes to 0xd65f03c0 in little-endian byte order.
// arm64 instructions are fixed 4 bytes; the decoder always advances by 4.

// TestFindReturnOffsets_SingleRet_ARM64 checks that the exact set of return
// offsets found in a two-instruction buffer is {0x04} — no more, no fewer.
//
//	0x00  00 00 00 00  (non-RET instruction)
//	0x04  c0 03 5f d6  RET
func TestFindReturnOffsets_SingleRet_ARM64(t *testing.T) {
	prog := []byte{
		0x00, 0x00, 0x00, 0x00, // non-RET
		0xc0, 0x03, 0x5f, 0xd6, // RET  → offset 0x04
	}
	offsets, err := FindReturnOffsets(0, prog)
	require.NoError(t, err)
	require.Equal(t, []uint64{0x04}, offsets)
}

// TestFindReturnOffsets_BaseOffset_ARM64 verifies that every reported offset
// equals baseOffset + the instruction's position within data.
//
//	0x00  c0 03 5f d6  RET
func TestFindReturnOffsets_BaseOffset_ARM64(t *testing.T) {
	prog := []byte{
		0xc0, 0x03, 0x5f, 0xd6, // RET  → offset 0x00
	}
	const base = uint64(0x1000)
	offsets, err := FindReturnOffsets(base, prog)
	require.NoError(t, err)
	require.Equal(t, []uint64{base}, offsets)
}

// TestFindReturnOffsets_Empty_ARM64 verifies that an empty input produces no
// offsets and no error.
func TestFindReturnOffsets_Empty_ARM64(t *testing.T) {
	offsets, err := FindReturnOffsets(0, []byte{})
	require.NoError(t, err)
	require.Empty(t, offsets)
}

// TestFindReturnOffsets_NoRet_ARM64 verifies that a buffer with no RET
// instruction produces an empty result.
//
//	0x00  00 00 00 00  (non-RET instruction)
//	0x04  00 00 00 00  (non-RET instruction)
func TestFindReturnOffsets_NoRet_ARM64(t *testing.T) {
	prog := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	offsets, err := FindReturnOffsets(0, prog)
	require.NoError(t, err)
	require.Empty(t, offsets)
}

// TestFindReturnOffsets_MultipleRets_ARM64 checks that all RET instructions are
// reported when more than one is present.  Equal (not ElementsMatch) is correct:
// the implementation scans left-to-right in fixed 4-byte steps, so the returned
// slice is guaranteed to be in ascending offset order.
//
//	0x00  c0 03 5f d6  RET
//	0x04  00 00 00 00  (non-RET)
//	0x08  c0 03 5f d6  RET
func TestFindReturnOffsets_MultipleRets_ARM64(t *testing.T) {
	prog := []byte{
		0xc0, 0x03, 0x5f, 0xd6, // RET  → offset 0x00
		0x00, 0x00, 0x00, 0x00, // non-RET
		0xc0, 0x03, 0x5f, 0xd6, // RET  → offset 0x08
	}
	offsets, err := FindReturnOffsets(0, prog)
	require.NoError(t, err)
	require.Equal(t, []uint64{0x00, 0x08}, offsets)
}

// TestFindReturnOffsets_Truncated_ARM64 verifies that a buffer shorter than one
// instruction (< 4 bytes) is handled without error.  The decoder fails on the
// incomplete word; the implementation advances by 4 anyway and exits the loop,
// returning no offsets.
func TestFindReturnOffsets_Truncated_ARM64(t *testing.T) {
	prog := []byte{0xc0, 0x03, 0x5f} // 3 bytes — incomplete RET encoding
	offsets, err := FindReturnOffsets(0, prog)
	require.NoError(t, err)
	require.Empty(t, offsets)
}
