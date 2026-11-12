// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/grafana/go-offsets-tracker/pkg/offsets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

// debugOffsetsBlob writes the given values at the positions of one minor.
func debugOffsetsBlob(positions debugExceptionFields, values map[*int]uint64) []byte {
	blob := make([]byte, positions.size)
	for position, value := range values {
		binary.LittleEndian.PutUint64(blob[*position:], value)
	}
	return blob
}

func TestDebugExceptionLayout(t *testing.T) {
	// Values published by CPython 3.14.6.
	positions := debugExceptionPositions[14]
	blob := debugOffsetsBlob(positions, map[*int]uint64{
		&positions.interpretersHead: 808, &positions.tstateInterp: 16, &positions.tstateFrame: 72,
		&positions.framePrevious: 8, &positions.frameCode: 0, &positions.frameInstr: 56, &positions.frameOwner: 74,
		&positions.codeFilename: 112, &positions.codeName: 120, &positions.codeLinetable: 136,
		&positions.codeFirstlineno: 68, &positions.codeAdaptive: 208, &positions.tupleItems: 32,
		&positions.unicodeASCIISize: 40,
	})

	layout, err := debugExceptionLayout(blob, 14, positions)
	require.NoError(t, err)
	assert.Equal(t, ExceptionLayout{
		Minor: 14, TstateInterp: 16, TstateFrame: 72,
		FrameCode: 0, FramePrevious: 8, FrameInstr: 56, FrameOwner: 74, FrameOwnerCStack: 4,
		CodeAdaptive: 208, CodeFilename: 112, CodeName: 120, CodeLinetable: 136, CodeFirstlineno: 68,
		TupleItems: 32, UnicodeASCIIData: 40, UnicodeCompactData: 56, ExceptionTraceback: 40,
		FrameReadSize: 80, FrameObjectFrame: 24, TstateExcInfo: 120, ErrItemPrevious: 8, interpretersMain: 816,
	}, layout)

	binary.LittleEndian.PutUint64(blob[positions.codeFilename:], 256)
	_, err = debugExceptionLayout(blob, 14, positions)
	require.ErrorIs(t, err, errUnsupportedLayout, "offsets beyond the probe's field width")

	_, err = debugExceptionLayout(make([]byte, positions.size), 14, positions)
	require.ErrorIs(t, err, errUnsupportedLayout, "zeroed debug offsets")
}

func TestExceptionLayoutMinors(t *testing.T) {
	for _, minor := range []uint8{9, 10, 11, 12} {
		layout, err := exceptionLayout(nil, 0, 3<<24|uint32(minor)<<16|0xf0)
		require.NoError(t, err)
		assert.Equal(t, minor, layout.Minor)
		// PyFrameObject frames read their int f_lasti; interpreter frames their instruction pointer.
		assert.Equal(t, minor < 11, layout.FrameLastiInt)
		assert.LessOrEqual(t, int(layout.FrameInstr)+8, int(layout.FrameReadSize))
		assert.LessOrEqual(t, int(layout.FrameOwner), int(layout.FrameReadSize))
	}

	_, err := exceptionLayout(nil, 0, 3<<24|8<<16|0xf0)
	require.ErrorIs(t, err, errUnsupportedLayout)
}

func TestLegacyExceptionLayoutCompatibility(t *testing.T) {
	expected := map[uint8]ExceptionLayout{
		9: {
			TstateInterp: 16, TstateFrame: 24,
			FrameCode: 32, FramePrevious: 24, FrameInstr: 104, FrameOwnerCStack: frameOwnerNone,
			FrameReadSize: 112, FrameLastiInt: true, FrameLastiBytes: true,
			CodeFilename: 104, CodeName: 112, CodeLinetable: 120, CodeFirstlineno: 40,
			TupleItems: 24, UnicodeASCIIData: 48, UnicodeCompactData: 72, ExceptionTraceback: 32, interpretersMain: 40,
			TstateExcInfo: 144, ErrItemValue: 8, ErrItemPrevious: 24,
		},
		10: {
			TstateInterp: 16, TstateFrame: 24,
			FrameCode: 32, FramePrevious: 24, FrameInstr: 96, FrameOwnerCStack: frameOwnerNone,
			FrameReadSize: 104, FrameLastiInt: true,
			CodeFilename: 104, CodeName: 112, CodeLinetable: 120, CodeFirstlineno: 40,
			TupleItems: 24, UnicodeASCIIData: 48, UnicodeCompactData: 72, ExceptionTraceback: 32, interpretersMain: 40,
			TstateExcInfo: 144, ErrItemValue: 8, ErrItemPrevious: 24,
		},
		11: {
			TstateInterp: 16, TstateFrame: 56, CFrameCurrentFrame: 8, FrameIsCFrame: true,
			FrameCode: 32, FramePrevious: 48, FrameInstr: 56, FrameOwner: 69, FrameOwnerCStack: frameOwnerNone,
			FrameReadSize: interpreterFrameReadSize, FrameObjectFrame: frameObjectFrameOffset,
			CodeAdaptive: 184, CodeFilename: 112, CodeName: 120, CodeLinetable: 136, CodeFirstlineno: 72,
			TupleItems: 24, UnicodeASCIIData: 48, UnicodeCompactData: 72, ExceptionTraceback: exceptionTracebackOffset, interpretersMain: 48,
			TstateExcInfo: 120, ErrItemValue: errItemValueOffset, ErrItemPrevious: errItemPreviousOffset,
		},
		12: {
			TstateInterp: 16, TstateFrame: 56, CFrameCurrentFrame: 0, FrameIsCFrame: true,
			FrameCode: 0, FramePrevious: 8, FrameInstr: 56, FrameOwner: 70, FrameOwnerCStack: 3,
			FrameReadSize: interpreterFrameReadSize, FrameObjectFrame: frameObjectFrameOffset,
			CodeAdaptive: 192, CodeFilename: 112, CodeName: 120, CodeLinetable: 136, CodeFirstlineno: 68,
			TupleItems: 24, UnicodeASCIIData: 40, UnicodeCompactData: 56, ExceptionTraceback: exceptionTracebackOffset, interpretersMain: 48,
			TstateExcInfo: 104, ErrItemValue: errItemValueOffset, ErrItemPrevious: errItemPreviousOffset,
		},
	}
	for minor, want := range expected {
		want.Minor = minor
		for _, patch := range []uint8{0, supportedVersions[fmt.Sprintf("3.%d", minor)]} {
			version := uint32(3)<<24 | uint32(minor)<<16 | uint32(patch)<<8 | 0xf0
			got, err := exceptionLayout(nil, 0, version)
			require.NoError(t, err)
			assert.Equal(t, want, got)
		}
	}
}

func TestExceptionLayoutRejectsUnverifiedVersions(t *testing.T) {
	for _, version := range []uint32{
		0x030c00b1, // pre-release
		0x030f00f0, // unsupported minor
		3<<24 | 12<<16 | uint32(supportedVersions["3.12"]+1)<<8 | 0xf0,
	} {
		_, err := exceptionLayout(nil, 0, version)
		require.ErrorIs(t, err, errUnsupportedLayout)
	}
}

func TestLegacyExceptionLayoutRejectsInvalidOffsets(t *testing.T) {
	original := layoutOffsets.Data["_PyInterpreterFrame"]["f_code"]
	t.Cleanup(func() { layoutOffsets.Data["_PyInterpreterFrame"]["f_code"] = original })
	delete(layoutOffsets.Data["_PyInterpreterFrame"], "f_code")
	_, err := exceptionLayout(nil, 0, 0x030c00f0)
	require.ErrorIs(t, err, errUnsupportedLayout)

	invalid := original
	invalid.Offsets = append([]offsets.Versioned(nil), original.Offsets...)
	invalid.Offsets[len(invalid.Offsets)-1].Offset = 256
	layoutOffsets.Data["_PyInterpreterFrame"]["f_code"] = invalid
	_, err = exceptionLayout(nil, 0, 0x030c00f0)
	require.ErrorIs(t, err, errUnsupportedLayout)
}

func TestErrSetObjectPrefersSplitBody(t *testing.T) {
	symbols := map[string]procs.Sym{
		"_PyErr_SetObject":        {Off: 0x100, Prog: &elf.Prog{}},
		"_PyErr_SetObject.part.0": {Off: 0x200, Prog: &elf.Prog{}},
	}
	offset, err := errSetObjectOffset(nil, symbols)
	require.NoError(t, err)
	assert.Equal(t, uint64(0x200), offset)
	delete(symbols, "_PyErr_SetObject.part.0")
	offset, err = errSetObjectOffset(nil, symbols)
	require.NoError(t, err)
	assert.Equal(t, uint64(0x100), offset)
}
