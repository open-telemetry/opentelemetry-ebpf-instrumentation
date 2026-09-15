// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func TestMySQLParsing(t *testing.T) {
	for _, ts := range []struct {
		name   string
		bytes  []byte
		valid  bool
		result mySQLHdr
	}{
		{
			name:  "Test1",
			bytes: []byte{166, 0, 0, 0, 3, 73, 78, 83, 69, 82, 84, 32, 73, 78, 84, 79, 32, 96, 117, 115, 101, 114, 115, 96, 32, 40, 96, 110, 97, 109, 101, 96, 44, 32, 96, 101, 109, 97, 105, 108, 96, 44, 32, 96, 99, 114, 101, 97, 116, 101, 100, 95, 97, 116, 96, 44, 32, 96, 117, 112, 100, 97, 116, 101, 100, 95, 97, 116, 96, 41, 32, 86, 65, 76, 85, 69, 83, 32, 40, 39, 74, 111, 104, 110, 32, 68, 111, 101, 39, 44, 32, 39, 106, 111, 104, 110, 64, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 39, 44, 32, 39, 50, 48, 50, 53, 45, 49, 50, 45, 48, 52, 32, 49, 55, 58, 50, 54, 58, 52, 54, 46, 56, 56, 52, 57, 54, 56, 39, 44, 32, 39, 50, 48, 50, 53, 45, 49, 50, 45, 48, 52, 32, 49, 55, 58, 50, 54, 58, 52, 54, 46, 56, 56, 52, 57, 54, 56, 39, 41},
			valid: true,
			result: mySQLHdr{
				length:  166,
				command: 3,
			},
		},
		{
			name:  "Valid prepare",
			bytes: []byte{0x1c, 0x00, 0x00, 0x00, 0x16, 0x53, 0x45, 0x4c, 0x45, 0x43, 0x54, 0x20, 0x43, 0x4f, 0x4e, 0x43, 0x41, 0x54, 0x28, 0x3f, 0x2c, 0x20, 0x3f, 0x29, 0x20, 0x41, 0x53, 0x20, 0x63, 0x6f, 0x6c, 0x31},
			valid: true,
			result: mySQLHdr{
				length:  0x1c,
				command: 0x16,
			},
		},
		{
			name:  "Valid execute",
			bytes: []byte{0x12, 0x00, 0x00, 0x00, 0x17, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0f, 0x00, 0x03, 0x66, 0x6f, 0x6f},
			valid: true,
			result: mySQLHdr{
				length:  0x12,
				command: 0x17,
			},
		},
		{
			name:  "Valid Query",
			bytes: []byte{0x21, 0x00, 0x00, 0x01, 0x03, 0x01, 0x01, 0x00, 0x01, 0xfe, 0x00, 0x01, 0x61, 0x01, 0x31, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x40, 0x40, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 110, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x20, 0x31},
			valid: true,
			result: mySQLHdr{
				length:  0x21,
				command: 0x3,
			},
		},
		{
			name:  "Unknown opcode",
			bytes: []byte{0x1c, 0x00, 0x00, 0x00, 0x10, 0x53, 0x45, 0x4c, 0x45, 0x43, 0x54, 0x20, 0x43, 0x4f, 0x4e, 0x43, 0x41, 0x54, 0x28, 0x3f, 0x2c, 0x20, 0x3f, 0x29, 0x20, 0x41, 0x53, 0x20, 0x63, 0x6f, 0x6c, 0x31},
			valid: false,
			result: mySQLHdr{
				length:  0x1c,
				command: 0x10,
			},
		},
		{
			name:  "Zero size",
			bytes: []byte{0x00, 0x00, 0x00, 0x00, 0x16, 0x53, 0x45, 0x4c, 0x45, 0x43, 0x54, 0x20, 0x43, 0x4f, 0x4e, 0x43, 0x41, 0x54, 0x28, 0x3f, 0x2c, 0x20, 0x3f, 0x29, 0x20, 0x41, 0x53, 0x20, 0x63, 0x6f, 0x6c, 0x31},
			valid: false,
			result: mySQLHdr{
				length:  0,
				command: 0x16,
			},
		},
	} {
		t.Run(ts.name, func(t *testing.T) {
			hdr := readMySQLHeader(ts.bytes)
			assert.Equal(t, ts.result, hdr)
			assert.Equal(t, ts.valid, isMySQL(largebuf.NewLargeBufferFrom(ts.bytes)))
		})
	}
}

// mysqlPacket frames a MySQL packet: 3-byte payload length, 1-byte sequence
// ID, then the payload starting with the command byte.
func mysqlPacket(command byte, payload []byte) []byte {
	packet := binary.LittleEndian.AppendUint32(nil, uint32(1+len(payload)))
	packet = append(packet, command)
	return append(packet, payload...)
}

func mysqlStmtClosePacket(stmtID uint32) []byte {
	return mysqlPacket(kMySQLStmtClose, binary.LittleEndian.AppendUint32(nil, stmtID))
}

func mysqlPreparePacket(query string) []byte {
	return mysqlPacket(kMySQLPrepare, []byte(query))
}

func mysqlExecutePacket(stmtID uint32) []byte {
	return mysqlPacket(kMySQLExecute, binary.LittleEndian.AppendUint32(nil, stmtID))
}

// mysqlPrepareResponsePacket frames a COM_STMT_PREPARE response: OK status
// byte followed by the statement ID.
func mysqlPrepareResponsePacket(stmtID uint32) []byte {
	return mysqlPacket(0x00, binary.LittleEndian.AppendUint32(nil, stmtID))
}

func mysqlOKResponsePacket() []byte {
	return mysqlPacket(0x00, nil)
}

func TestSkipMySQLNoResponseCommands(t *testing.T) {
	prepare := mysqlPreparePacket("SELECT 1")
	execute := mysqlExecutePacket(1)

	t.Run("keeps the buffer when a span-producing command comes first", func(t *testing.T) {
		remaining, closedStmtIDs := skipMySQLNoResponseCommands(prepare)
		assert.Equal(t, prepare, remaining)
		assert.Empty(t, closedStmtIDs)

		remaining, closedStmtIDs = skipMySQLNoResponseCommands(execute)
		assert.Equal(t, execute, remaining)
		assert.Empty(t, closedStmtIDs)
	})

	t.Run("skips every leading no-response command", func(t *testing.T) {
		buf := append(append(mysqlStmtClosePacket(1), mysqlStmtClosePacket(2)...), prepare...)
		remaining, closedStmtIDs := skipMySQLNoResponseCommands(buf)
		assert.Equal(t, prepare, remaining)
		assert.Equal(t, []uint32{1, 2}, closedStmtIDs)

		buf = append(mysqlPacket(kMySQLStmtSendLongData, []byte{0, 0, 0, 1, 1, 2}), execute...)
		remaining, closedStmtIDs = skipMySQLNoResponseCommands(buf)
		assert.Equal(t, execute, remaining)
		assert.Empty(t, closedStmtIDs)
	})

	t.Run("does not report an ID from a malformed close packet", func(t *testing.T) {
		buf := append(mysqlPacket(kMySQLStmtClose, nil), prepare...)
		remaining, closedStmtIDs := skipMySQLNoResponseCommands(buf)
		assert.Equal(t, prepare, remaining)
		assert.Empty(t, closedStmtIDs)
	})

	t.Run("returns the buffer unchanged when the no-response packet is last", func(t *testing.T) {
		buf := mysqlStmtClosePacket(1)
		remaining, closedStmtIDs := skipMySQLNoResponseCommands(buf)
		assert.Equal(t, buf, remaining)
		assert.Empty(t, closedStmtIDs)
	})

	t.Run("returns the buffer unchanged when the no-response packet is truncated", func(t *testing.T) {
		buf := mysqlStmtClosePacket(1)
		buf[0] = 0xff // payload length beyond the captured buffer
		remaining, closedStmtIDs := skipMySQLNoResponseCommands(buf)
		assert.Equal(t, buf, remaining)
		assert.Empty(t, closedStmtIDs)
	})

	t.Run("returns short buffers unchanged", func(t *testing.T) {
		remaining, closedStmtIDs := skipMySQLNoResponseCommands(nil)
		assert.Nil(t, remaining)
		assert.Empty(t, closedStmtIDs)

		remaining, closedStmtIDs = skipMySQLNoResponseCommands([]byte{1, 2, 3, 4})
		assert.Equal(t, []byte{1, 2, 3, 4}, remaining)
		assert.Empty(t, closedStmtIDs)
	})
}

func TestReadTCPRequestIntoSpan_MySQLStmtCloseCoalescing(t *testing.T) {
	cfg := config.EBPFTracer{
		CouchbaseDBCacheSize:                16,
		MySQLPreparedStatementsCacheSize:    16,
		PostgresPreparedStatementsCacheSize: 16,
		MSSQLPreparedStatementsCacheSize:    16,
		KafkaTopicUUIDCacheSize:             16,
		MongoRequestsCacheSize:              16,
	}
	ctx := NewEBPFParseContext(&cfg, nil, nil)
	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}

	readSpan := func(t *testing.T, r TCPRequestInfo) (request.Span, bool) {
		binaryRecord := bytes.Buffer{}
		require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, r))
		span, ignore, err := ReadTCPRequestIntoSpan(ctx, &cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
		require.NoError(t, err)
		return span, ignore
	}

	mysqlEvent := func(req, resp []byte) TCPRequestInfo {
		r := makeTCPReq(string(req), 3306)
		r.ProtocolType = ProtocolTypeMySQL
		r.RespLen = uint32(len(resp))
		copy(r.Rbuf[:], resp)
		return r
	}

	// Clean PREPARE requests cache their statements without emitting spans.
	_, ignore := readSpan(t, mysqlEvent(mysqlPreparePacket("SELECT * FROM stale"), mysqlPrepareResponsePacket(1)))
	assert.True(t, ignore)

	_, ignore = readSpan(t, mysqlEvent(mysqlPreparePacket("SELECT * FROM accounts"), mysqlPrepareResponsePacket(2)))
	assert.True(t, ignore)

	// The EXECUTE coalesced behind a COM_STMT_CLOSE must produce the span for
	// the still-live statement and remove the closed statement from the cache.
	closeAndExecute := mysqlEvent(
		append(mysqlStmtClosePacket(1), mysqlExecutePacket(2)...),
		mysqlOKResponsePacket(),
	)
	span, ignore := readSpan(t, closeAndExecute)
	assert.False(t, ignore)
	assert.Equal(t, request.EventTypeSQLClient, span.Type)
	assert.Equal(t, "SELECT", span.Method)
	assert.Equal(t, "accounts", span.Path)
	assert.Equal(t, "SELECT * FROM accounts", span.Statement)
	assert.Equal(t, "STMT_EXECUTE", span.SQLCommand)
	assert.Equal(t, int(request.DBMySQL), span.SubType)
	_, found := ctx.mysqlPreparedStatements.Get(mysqlPreparedStatementsKey{
		connInfo: closeAndExecute.ConnInfo,
		stmtID:   1,
	})
	assert.False(t, found)

	// A PREPARE coalesced behind a COM_STMT_CLOSE must still be cached.
	closeAndPrepare := mysqlEvent(
		append(mysqlStmtClosePacket(2), mysqlPreparePacket("SELECT * FROM users")...),
		mysqlPrepareResponsePacket(7),
	)
	_, ignore = readSpan(t, closeAndPrepare)
	assert.True(t, ignore)
	_, found = ctx.mysqlPreparedStatements.Get(mysqlPreparedStatementsKey{
		connInfo: closeAndPrepare.ConnInfo,
		stmtID:   2,
	})
	assert.False(t, found)

	span, ignore = readSpan(t, mysqlEvent(mysqlExecutePacket(7), mysqlOKResponsePacket()))
	assert.False(t, ignore)
	assert.Equal(t, "SELECT", span.Method)
	assert.Equal(t, "users", span.Path)

	// A plain QUERY coalesced behind a COM_STMT_CLOSE must produce a span too.
	span, ignore = readSpan(t, mysqlEvent(
		append(mysqlStmtClosePacket(3), mysqlPacket(kMySQLQuery, []byte("SELECT * FROM products"))...),
		mysqlOKResponsePacket(),
	))
	assert.False(t, ignore)
	assert.Equal(t, "SELECT", span.Method)
	assert.Equal(t, "products", span.Path)
	assert.Equal(t, "QUERY", span.SQLCommand)
}
