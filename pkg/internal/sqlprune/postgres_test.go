// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlprune

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestParsePostgresError(t *testing.T) {
	tests := []struct {
		name     string
		buf      []uint8
		expected *request.SQLError
	}{
		{
			name: "valid error with SQLState and Message",
			buf: func() []uint8 {
				// 'E' + 4-byte header + 'C' + code + 'M' + message + 0
				b := []uint8{'E', 0, 0, 0, 75}
				b = append(b, 'C')
				b = append(b, []uint8("23505")...)
				b = append(b, 0)
				b = append(b, 'M')
				b = append(b, []uint8("duplicate key value violates unique constraint \"mytable_pkey\"")...)
				b = append(b, 0)
				b = append(b, 0)
				return b
			}(),
			expected: &request.SQLError{
				SQLState: "23505",
				Message:  "duplicate key value violates unique constraint \"mytable_pkey\"",
			},
		},
		{
			name: "missing SQLState",
			buf: func() []uint8 {
				b := []uint8{'E', 0, 0, 0, 17}
				b = append(b, 'M')
				b = append(b, []uint8("some error")...)
				b = append(b, 0)
				b = append(b, 0)
				return b
			}(),
			expected: nil,
		},
		{
			name: "missing Message",
			buf: func() []uint8 {
				b := []uint8{'E', 0, 0, 0, 11}
				b = append(b, 'C')
				b = append(b, []uint8("23505")...)
				b = append(b, 0)
				return b
			}(),
			expected: nil,
		},
		{
			name: "malformed error packet (no null terminator)",
			buf: func() []uint8 {
				b := []uint8{'E', 0, 0, 0, 16}
				b = append(b, 'C')
				b = append(b, []uint8("23505")...)
				b = append(b, 'M')
				b = append(b, []uint8("error")...)
				// missing null terminator
				return b
			}(),
			expected: nil,
		},
		{
			name:     "too short buffer",
			buf:      []uint8{'E', 0, 0, 3},
			expected: nil,
		},
		{
			name: "valid error with extra fields",
			buf: func() []uint8 {
				b := []uint8{'E', 0, 0, 0, 97}
				b = append(b, 'S')
				b = append(b, []uint8("ERROR")...)
				b = append(b, 0)
				b = append(b, 'C')
				b = append(b, []uint8("23505")...)
				b = append(b, 0)
				b = append(b, 'M')
				b = append(b, []uint8("duplicate key value violates unique constraint")...)
				b = append(b, 0)
				b = append(b, 'D')
				b = append(b, []uint8("Key (id)=(1) already exists.")...)
				b = append(b, 0)
				b = append(b, 0)
				return b
			}(),
			expected: &request.SQLError{
				SQLState: "23505",
				Message:  "duplicate key value violates unique constraint",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsePostgresError(tt.buf)
			assert.Equal(t, tt.expected, got)
		})
	}
}
