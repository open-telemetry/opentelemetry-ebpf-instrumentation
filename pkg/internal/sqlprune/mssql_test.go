// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlprune

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// makeMSSQLErrorPacket builds a minimal TDS response packet containing a single ERROR token.
// msg must contain only ASCII characters.
func makeMSSQLErrorPacket(errNumber uint32, state uint8, msg string) []uint8 {
	msgLen := len(msg)

	b := []uint8{
		mssqlPktResponse, 0x01, // type, status
		0x00, 0x00, // length (not validated by parser)
		0x00, 0x00, // spid
		0x01, 0x00, // packet_id, window
		mssqlErrToken, // ERROR token
		0x00, 0x00,    // token length (not used by parser)
	}

	b = append(b, uint8(errNumber), uint8(errNumber>>8), uint8(errNumber>>16), uint8(errNumber>>24))
	b = append(b, state)
	b = append(b, 0x10) // class

	b = append(b, uint8(msgLen), uint8(msgLen>>8))

	for _, c := range msg {
		b = append(b, uint8(c), 0x00)
	}

	return b
}

func TestParseMSSQLError(t *testing.T) {
	tests := []struct {
		name     string
		buf      []uint8
		expected *request.SQLError
	}{
		{
			name: "valid error with code and message",
			buf:  makeMSSQLErrorPacket(208, 1, "Invalid object name 'nonexistent_table'"),
			expected: &request.SQLError{
				Code:     208,
				SQLState: "1",
				Message:  "Invalid object name 'nonexistent_table'",
			},
		},
		{
			name: "error number exceeds 16 bits clears Code",
			buf:  makeMSSQLErrorPacket(0x10000, 2, "some error"),
			expected: &request.SQLError{
				SQLState: "2",
				Message:  "some error",
			},
		},
		{
			name:     "not a response packet",
			buf:      func() []uint8 { b := makeMSSQLErrorPacket(208, 1, "err"); b[0] = 0x01; return b }(),
			expected: nil,
		},
		{
			name: "no error token at offset 8",
			buf: func() []uint8 {
				b := makeMSSQLErrorPacket(208, 1, "err")
				b[mssqlHdrSize] = 0x79 // DONE token, not ERROR
				return b
			}(),
			expected: nil,
		},
		{
			name:     "too short buffer",
			buf:      []uint8{mssqlPktResponse, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
			expected: nil,
		},
		{
			name: "message truncated",
			buf: func() []uint8 {
				b := makeMSSQLErrorPacket(208, 1, "some long message")
				return b[:len(b)-4] // cut before message ends
			}(),
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMSSQLError(tt.buf)
			assert.Equal(t, tt.expected, got)
		})
	}
}
