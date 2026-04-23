// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
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
			assert.Equal(t, tt.want, isMSSQL(largebuf.NewLargeBufferFrom(tt.buf)))
		})
	}
}

func TestUCS2ToUTF8(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want []byte
	}{
		{
			name: "simple ascii",
			buf:  []byte{'S', 0, 'E', 0, 'L', 0, 'E', 0, 'C', 0, 'T', 0},
			want: []byte{'S', 'E', 'L', 'E', 'C', 'T'},
		},
		{
			name: "with special chars",
			buf:  []byte{'S', 0, 'E', 0, 'L', 0, 'E', 0, 'C', 0, 'T', 0, ' ', 0, '*', 0, ' ', 0, 'F', 0, 'R', 0, 'O', 0, 'M', 0},
			want: []byte{'S', 'E', 'L', 'E', 'C', 'T', ' ', '*', ' ', 'F', 'R', 'O', 'M'},
		},
		{
			name: "odd length",
			buf:  []byte{'S', 0, 'E', 0, 'L', 0, 'E', 0, 'C', 0, 'T', 0, 'X'},
			want: []byte{'S', 'E', 'L', 'E', 'C', 'T'},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ucs2ToUTF8(tt.buf))
		})
	}
}

func makeTDSPacket(pktType, status byte, payload []byte) []byte {
	totalLen := kMSSQLHeaderLen + len(payload)
	hdr := []byte{
		pktType, status,
		byte(totalLen >> 8), byte(totalLen),
		0x00, 0x00, // SPID
		0x01, // PacketID
		0x00, // Window
	}
	return append(hdr, payload...)
}

func TestExtractTDSPayloads(t *testing.T) {
	sqlPart1 := []byte{'S', 0, 'E', 0, 'L', 0, 'E', 0, 'C', 0, 'T', 0}
	sqlPart2 := []byte{' ', 0, '1', 0}

	tests := []struct {
		name string
		buf  []byte
		want []byte
	}{
		{
			name: "single packet",
			buf:  makeTDSPacket(kMSSQLBatch, 0x01, sqlPart1),
			want: sqlPart1,
		},
		{
			name: "two packets concatenated",
			buf: append(
				makeTDSPacket(kMSSQLBatch, 0x00, sqlPart1),
				makeTDSPacket(kMSSQLBatch, 0x01, sqlPart2)...,
			),
			want: append(sqlPart1, sqlPart2...),
		},
		{
			name: "truncated second packet ignored",
			buf: append(
				makeTDSPacket(kMSSQLBatch, 0x00, sqlPart1),
				[]byte{kMSSQLBatch, 0x01, 0x00, 0x0A}..., // header claims 10 bytes but nothing follows
			),
			want: sqlPart1,
		},
		{
			name: "empty payload packet",
			buf:  makeTDSPacket(kMSSQLBatch, 0x01, nil),
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTDSPayloads(largebuf.NewLargeBufferFrom(tt.buf))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMSSQLBatchParsing(t *testing.T) {
	selectSQL := []byte{'S', 0, 'E', 0, 'L', 0, 'E', 0, 'C', 0, 'T', 0, ' ', 0, '*', 0, ' ', 0, 'F', 0, 'R', 0, 'O', 0, 'M', 0, ' ', 0, 't', 0}
	tests := []struct {
		name      string
		buf       []byte
		wantOp    string
		wantTable string
		wantStmt  string
	}{
		{
			name:   "valid single-packet batch",
			buf:    makeTDSPacket(kMSSQLBatch, 0x01, []byte{'S', 0, 'E', 0, 'L', 0, 'E', 0, 'C', 0, 'T', 0}),
			wantOp: "SELECT", wantTable: "", wantStmt: "SELECT",
		},
		{
			name: "sql split across two TDS packets",
			buf: append(
				makeTDSPacket(kMSSQLBatch, 0x00, selectSQL[:len(selectSQL)/2]),
				makeTDSPacket(kMSSQLBatch, 0x01, selectSQL[len(selectSQL)/2:])...,
			),
			wantOp: "SELECT", wantTable: "t", wantStmt: "SELECT * FROM t",
		},
		{
			name:      "too short",
			buf:       makeTDSPacket(kMSSQLBatch, 0x01, nil),
			wantOp:    "",
			wantTable: "",
			wantStmt:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, table, stmt := mssqlExtractBatchSQL(largebuf.NewLargeBufferFrom(tt.buf))
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
		wantErr    bool
	}{
		{
			name:       "proc id 13",
			buf:        makeTDSPacket(kMSSQLRPC, 0x01, []byte{0xFF, 0xFF, 0x0D, 0x00, 0x00, 0x00}),
			wantProcID: 13,
		},
		{
			name:       "named proc",
			buf:        makeTDSPacket(kMSSQLRPC, 0x01, []byte{0x02, 0x00, 's', 0, 'p', 0, 0x00, 0x00}),
			wantProcID: 0,
		},
		{
			// A second TDS packet appended after the first must not confuse header parsing.
			name: "second packet ignored — proc id still parsed from first",
			buf: append(
				makeTDSPacket(kMSSQLRPC, 0x00, []byte{0xFF, 0xFF, 0x0D, 0x00, 0x00, 0x00}),
				makeTDSPacket(kMSSQLRPC, 0x01, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00})...,
			),
			wantProcID: 13,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			procID, _, err := parseMSSQLRPC(largebuf.NewLargeBufferFrom(tt.buf))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
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
			name:       "too short",
			payload:    []byte{0, 0, 0x26, 1, 2, 3},
			wantHandle: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := largebuf.NewLargeBufferFrom(tt.payload).NewReader()
			handle := parseHandleFromExecute(r)
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
				// 0xAC (RETURNVALUE), ordinal=1 (2 bytes), nameLen=0 (1 byte), status=0 (1 byte), userType=0 (4 bytes), flags=0 (2 bytes), type=0x26 (1 byte), value=789 (4 bytes)
				payload := []byte{0xAC, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26}
				v := make([]byte, 4)
				binary.LittleEndian.PutUint32(v, 789)
				return makeTDSPacket(kMSSQLResponse, 0x01, append(payload, v...))
			}(),
			wantHandle: 789,
		},
		{
			name: "valid prepare response TI_INTN",
			buf: func() []byte {
				// 0xAC (RETURNVALUE), ordinal=1, nameLen=0, status=0, userType=0, flags=0, type=0x38 (TI_INTN), length=4, value=1011
				payload := []byte{0xAC, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 4}
				v := make([]byte, 4)
				binary.LittleEndian.PutUint32(v, 1011)
				return makeTDSPacket(kMSSQLResponse, 0x01, append(payload, v...))
			}(),
			wantHandle: 1011,
		},
		{
			name:       "no return value token",
			buf:        []byte{0x04, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00},
			wantHandle: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handle := parseHandleFromPrepareResponse(largebuf.NewLargeBufferFrom(tt.buf))
			assert.Equal(t, tt.wantHandle, handle)
		})
	}
}
