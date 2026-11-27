// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dwarfutil // import "go.opentelemetry.io/obi/internal/dwarfutil"

import (
	"debug/dwarf"
	"errors"
	"fmt"
)

var ErrFieldNotFound = errors.New("missing field")

// FieldByName returns the direct member, or nil if the struct has no such field.
func FieldByName(s *dwarf.StructType, name string) *dwarf.StructField {
	for _, field := range s.Field {
		if field.Name == name {
			return field
		}
	}

	return nil
}

// FieldPath follows inline struct members through typedefs and returns the byte
// offset from the root and the leaf type. Each member must fit in its container.
// The error wraps ErrFieldNotFound only when a struct has no member of that name.
func FieldPath(t dwarf.Type, path ...string) (int64, dwarf.Type, error) {
	var offset int64
	for _, name := range path {
		for {
			alias, ok := t.(*dwarf.TypedefType)
			if !ok {
				break
			}
			t = alias.Type
		}

		s, ok := t.(*dwarf.StructType)
		if !ok {
			return 0, nil, fmt.Errorf("field %q requires a struct", name)
		}

		field := FieldByName(s, name)
		if field == nil {
			return 0, nil, fmt.Errorf("%w %q in %s", ErrFieldNotFound, name, s.StructName)
		}

		if field.Type == nil {
			return 0, nil, fmt.Errorf("field %q in %s has no type", name, s.StructName)
		}

		size := field.Type.Size()
		if field.ByteOffset < 0 || size < 0 || size > s.ByteSize || field.ByteOffset > s.ByteSize-size {
			return 0, nil, fmt.Errorf("field %q exceeds its containing type", name)
		}

		offset += field.ByteOffset
		t = field.Type
	}

	return offset, t, nil
}
