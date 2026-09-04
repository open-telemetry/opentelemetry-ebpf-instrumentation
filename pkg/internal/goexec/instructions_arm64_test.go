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

func TestFindCallTargets_ARM64(t *testing.T) {
	data := []byte{
		0x04, 0x00, 0x00, 0x94, // BL 0x2010
		0x00, 0x00, 0x3f, 0xd6, // BLR X0
		0xc0, 0x03, 0x5f, 0xd6, // RET
	}
	targets, err := FindCallTargets(0x2000, data)
	require.NoError(t, err)
	require.Equal(t, []uint64{0x2010}, targets)
}

func TestFindPadStartOffset_ARM64(t *testing.T) {
	data := []byte{
		0xe5, 0x03, 0x42, 0x39, // LDRB W5, [SP, #128] (EndStream)
		0x3f, 0x00, 0x00, 0x71, // CMP W1, #0 (not the loaded register)
		0xe5, 0x0b, 0x42, 0x39, // LDRB W5, [SP, #130] (PadLength)
		0xe6, 0x03, 0x05, 0xaa, // MOV X6, X5
		0x26, 0x03, 0x00, 0x34, // CBZ W6
		0xc0, 0x03, 0x5f, 0xd6, // RET
	}
	offset, stackOffset, err := FindPadStartOffset(0x2000, data)
	require.NoError(t, err)
	require.Equal(t, uint64(0x2008), offset)
	require.Equal(t, uint64(130), stackOffset)
}

func TestFindPadStartOffsetRejectsUnrelatedLoad_ARM64(t *testing.T) {
	data := []byte{
		0xe5, 0x03, 0x42, 0x39, // LDRB W5, [SP, #128]
		0xe6, 0x03, 0x07, 0xaa, // MOV X6, X7 (different source)
		0x26, 0x03, 0x00, 0x34, // CBZ W6
		0xc0, 0x03, 0x5f, 0xd6, // RET
	}
	offset, stackOffset, err := FindPadStartOffset(0x2000, data)
	require.NoError(t, err)
	require.Zero(t, offset)
	require.Zero(t, stackOffset)
}
