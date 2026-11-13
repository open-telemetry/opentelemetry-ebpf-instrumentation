// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime // import "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"

import (
	"fmt"
	"math"
)

const frameOwnerCStack312 = 3

// legacyExceptionLayout reads the versioned object fields verified by the
// Python offsets inspector. Frame traversal conventions depend on the minor.
func legacyExceptionLayout(version pythonVersion) (ExceptionLayout, error) {
	layout := ExceptionLayout{Minor: version.minor, FrameOwnerCStack: frameOwnerNone}
	frame, previous, instruction := "PyFrameObject", "f_back", "f_lasti"
	tstateFrame, lineTable := "frame", "co_linetable"
	if version.minor == 9 {
		lineTable = "co_lnotab"
	}
	if version.minor < 11 {
		layout.FrameLastiInt = true
		layout.FrameLastiBytes = version.minor == 9
	} else {
		frame, previous, instruction = "_PyInterpreterFrame", "previous", "prev_instr"
		tstateFrame = "cframe"
		layout.FrameIsCFrame = true
		layout.FrameReadSize = interpreterFrameReadSize
		if version.minor == 12 {
			layout.FrameOwnerCStack = frameOwnerCStack312
		}
	}

	type fieldOffset struct {
		structure, field string
		target           *uint8
	}
	fields := []fieldOffset{
		{"PyThreadState", "interp", &layout.TstateInterp},
		{"PyThreadState", tstateFrame, &layout.TstateFrame},
		{"PyThreadState", "exc_info", &layout.TstateExcInfo},
		{frame, "f_code", &layout.FrameCode},
		{frame, previous, &layout.FramePrevious},
		{frame, instruction, &layout.FrameInstr},
		{"PyCodeObject", "co_filename", &layout.CodeFilename},
		{"PyCodeObject", "co_name", &layout.CodeName},
		{"PyCodeObject", lineTable, &layout.CodeLinetable},
		{"PyCodeObject", "co_firstlineno", &layout.CodeFirstlineno},
		{"PyTupleObject", "ob_item", &layout.TupleItems},
		{"PyASCIIObject", "sizeof", &layout.UnicodeASCIIData},
		{"PyCompactUnicodeObject", "sizeof", &layout.UnicodeCompactData},
		{"PyBaseExceptionObject", "traceback", &layout.ExceptionTraceback},
		{"_PyErr_StackItem", "exc_value", &layout.ErrItemValue},
		{"_PyErr_StackItem", "previous_item", &layout.ErrItemPrevious},
	}
	if version.minor >= 11 {
		fields = append(fields,
			fieldOffset{"_PyCFrame", "current_frame", &layout.CFrameCurrentFrame},
			fieldOffset{"_PyInterpreterFrame", "owner", &layout.FrameOwner},
			fieldOffset{"PyFrameObject", "f_frame", &layout.FrameObjectFrame},
		)
		adaptive, ok := layoutOffsets.Find("PyCodeObject", "co_code_adaptive", version.String())
		if !ok || adaptive > math.MaxUint16 {
			return ExceptionLayout{}, fmt.Errorf("%w: CPython %s code offset", errUnsupportedLayout, version)
		}
		layout.CodeAdaptive = uint16(adaptive)
	}
	for _, field := range fields {
		value, ok := layoutOffsets.Find(field.structure, field.field, version.String())
		// Offset zero is valid, including f_code and current_frame on 3.12.
		if !ok || value > math.MaxUint8 {
			return ExceptionLayout{}, fmt.Errorf("%w: CPython %s %s.%s", errUnsupportedLayout, version, field.structure, field.field)
		}
		*field.target = uint8(value)
	}
	if version.minor < 11 {
		layout.FrameReadSize = layout.FrameInstr + 8
	}
	main, ok := layoutOffsets.Find("_PyRuntimeState", "interpreters.main", version.String())
	if !ok {
		return ExceptionLayout{}, fmt.Errorf("%w: CPython %s main interpreter", errUnsupportedLayout, version)
	}
	layout.interpretersMain = main
	return layout, nil
}
