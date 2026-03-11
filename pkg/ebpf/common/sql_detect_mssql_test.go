// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsMSSQL(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want bool
	}{
		{
			name: "valid batch packet",
			buf:  []byte{0x01, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00},
			want: true,
		},
		{
			name: "valid rpc packet",
			buf:  []byte{0x03, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00},
			want: true,
		},
		{
			name: "valid response packet",
			buf:  []byte{0x04, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00},
			want: true,
		},
		{
			name: "too short",
			buf:  []byte{0x01, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00},
			want: false,
		},
		{
			name: "invalid type",
			buf:  []byte{0x05, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00},
			want: false,
		},
		{
			name: "invalid status",
			buf:  []byte{0x01, 0x10, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00},
			want: false,
		},
		{
			name: "invalid length too small",
			buf:  []byte{0x01, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00},
			want: false,
		},
		{
			name: "invalid length too large",
			buf:  []byte{0x01, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00},
			want: false,
		},
		{
			name: "invalid window byte",
			buf:  []byte{0x01, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isMSSQL(tt.buf))
		})
	}
}

func TestUCS2ToUTF8(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want string
	}{
		{
			name: "simple ascii",
			buf:  []byte{'S', 0, 'E', 0, 'L', 0, 'E', 0, 'C', 0, 'T', 0},
			want: "SELECT",
		},
		{
			name: "with special chars",
			buf:  []byte{'S', 0, 'E', 0, 'L', 0, 'E', 0, 'C', 0, 'T', 0, ' ', 0, '*', 0, ' ', 0, 'F', 0, 'R', 0, 'O', 0, 'M', 0},
			want: "SELECT * FROM",
		},
		{
			name: "odd length",
			buf:  []byte{'S', 0, 'E', 0, 'L', 0, 'E', 0, 'C', 0, 'T', 0, 'X'},
			want: "SELECT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ucs2ToUTF8(tt.buf))
		})
	}
}

func TestMSSQLBatchParsing(t *testing.T) {
	tests := []struct {
		name      string
		buf       []byte
		wantOp    string
		wantTable string
		wantStmt  string
	}{
		{
			name: "valid batch",
			buf: append([]byte{0x01, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00},
				[]byte{'S', 0, 'E', 0, 'L', 0, 'E', 0, 'C', 0, 'T', 0}...),
			wantOp:    "SELECT",
			wantTable: "",
			wantStmt:  "SELECT",
		},
		{
			name:      "too short",
			buf:       []byte{0x01, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00},
			wantOp:    "",
			wantTable: "",
			wantStmt:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, table, stmt := mssqlPreparedStatements(tt.buf)
			assert.Equal(t, tt.wantOp, op)
			assert.Equal(t, tt.wantTable, table)
			assert.Equal(t, tt.wantStmt, stmt)
		})
	}
}

func TestParseMSSQLRPC(t *testing.T) {
	tests := []struct {
		name       string
		buf        []byte
		wantProcID uint16
	}{
		{
			name: "proc id 13",
			buf: func() []byte {
				hdr := []byte{0x03, 0x01, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00}
				payload := []byte{0xFF, 0xFF, 0x0D, 0x00, 0x00, 0x00}
				return append(hdr, payload...)
			}(),
			wantProcID: 13,
		},
		{
			name: "named proc",
			buf: func() []byte {
				hdr := []byte{0x03, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00}
				// nameLen=2, name='sp', options=0
				payload := []byte{0x02, 0x00, 's', 0, 'p', 0, 0x00, 0x00}
				return append(hdr, payload...)
			}(),
			wantProcID: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			procID, _ := parseMSSQLRPC(tt.buf)
			assert.Equal(t, tt.wantProcID, procID)
		})
	}
}

func TestParseHandleFromExecute(t *testing.T) {
	tests := []struct {
		name       string
		payload    []byte
		wantHandle uint32
	}{
		{
			name: "valid TI_INT4 handle",
			payload: func() []byte {
				// nameLen=0, status=0, type=0x26 (TI_INT4), value=123
				p := []byte{0, 0, 0x26}
				v := make([]byte, 4)
				binary.LittleEndian.PutUint32(v, 123)
				return append(p, v...)
			}(),
			wantHandle: 123,
		},
		{
			name: "valid TI_INTN handle",
			payload: func() []byte {
				// nameLen=0, status=0, type=0x38 (TI_INTN), length=4, value=456
				p := []byte{0, 0, 0x38, 4}
				v := make([]byte, 4)
				binary.LittleEndian.PutUint32(v, 456)
				return append(p, v...)
			}(),
			wantHandle: 456,
		},
		{
			name: "too short",
			payload:    []byte{0, 0, 0x26, 1, 2, 3},
			wantHandle: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handle := parseHandleFromExecute(tt.payload)
			assert.Equal(t, tt.wantHandle, handle)
		})
	}
}

func TestParseHandleFromPrepareResponse(t *testing.T) {
	tests := []struct {
		name       string
		buf        []byte
		wantHandle uint32
	}{
		{
			name: "valid prepare response TI_INT4",
			buf: func() []byte {
				hdr := []byte{0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
				// 0xAC (RETURNVALUE), ordinal=1 (2 bytes), nameLen=0 (1 byte), status=0 (1 byte), userType=0 (4 bytes), flags=0 (2 bytes), type=0x26 (1 byte), value=789 (4 bytes)
				payload := []byte{0xAC, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26}
				v := make([]byte, 4)
				binary.LittleEndian.PutUint32(v, 789)
				payload = append(payload, v...)
				return append(hdr, payload...)
			}(),
			wantHandle: 789,
		},
		{
			name: "valid prepare response TI_INTN",
			buf: func() []byte {
				hdr := []byte{0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
				// 0xAC (RETURNVALUE), ordinal=1, nameLen=0, status=0, userType=0, flags=0, type=0x38 (TI_INTN), length=4, value=1011
				payload := []byte{0xAC, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 4}
				v := make([]byte, 4)
				binary.LittleEndian.PutUint32(v, 1011)
				payload = append(payload, v...)
				return append(hdr, payload...)
			}(),
			wantHandle: 1011,
		},
		{
			name: "no return value token",
			buf: []byte{0x04, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00},
			wantHandle: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handle := parseHandleFromPrepareResponse(tt.buf)
			assert.Equal(t, tt.wantHandle, handle)
		})
	}
}
