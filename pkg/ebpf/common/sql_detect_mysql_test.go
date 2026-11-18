// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
	"go.opentelemetry.io/obi/pkg/internal/sqlprune"
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

func TestMySQLQueryTextBoundedToPacket(t *testing.T) {
	first := "INSERT INTO conformance.items (id, name) VALUES (1, 'first')"
	next := mysqlPacket(kMySQLQuery, []byte("INSERT INTO conformance.items (id, name) VALUES (2, 'second')"))

	t.Run("query", func(t *testing.T) {
		req := append(mysqlPacket(kMySQLQuery, []byte(first)), next...)
		span, err := handleMySQL(newPostgresTestContext(), &TCPRequestInfo{}, largebuf.NewLargeBufferFrom(req), largebuf.NewLargeBufferFrom(mysqlOKResponsePacket()))
		require.NoError(t, err)
		assert.Equal(t, "INSERT", span.Method)
		assert.Equal(t, first, span.Statement)
	})

	t.Run("prepared statement", func(t *testing.T) {
		ctx := newPostgresTestContext()
		req := append(mysqlPreparePacket(first), next...)
		_, err := handleMySQL(ctx, &TCPRequestInfo{}, largebuf.NewLargeBufferFrom(req), largebuf.NewLargeBufferFrom(mysqlPrepareResponsePacket(4)))
		require.ErrorIs(t, err, errIgnore)

		stmt, found := ctx.mysqlPreparedStatements.Get(mysqlPreparedStatementsKey{stmtID: 4})
		require.True(t, found)
		assert.Equal(t, first, stmt)
	})

	t.Run("payload detection", func(t *testing.T) {
		req := append(mysqlPacket(kMySQLQuery, []byte(first)), next...)
		op, tables, statement, kind := detectSQLPayload(false, largebuf.NewLargeBufferFrom(req))
		assert.Equal(t, request.DBMySQL, kind)
		assert.Equal(t, "INSERT", op)
		assert.Equal(t, []string{"conformance.items"}, tables)
		assert.Equal(t, first, statement)
	})

	t.Run("empty packet", func(t *testing.T) {
		assert.Empty(t, mysqlQueryText([]byte{0, 0, 0, 0, kMySQLQuery}))
	})
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

const (
	mysqlTestCaps      = mysqlCapProtocol41 | mysqlCapSecureConnection | mysqlCapPluginAuthLenencClientData | mysqlCapConnectWithDB
	mariaDBTestExtCaps = uint32(0x1c)
)

func mysqlLenEncInt(n int) []byte {
	if n < mysqlLenEncNull {
		return []byte{byte(n)}
	}
	return []byte{mysqlLenEncInt2, byte(n), byte(n >> 8)}
}

func mysqlSeqPacket(seqID byte, payload []byte) []byte {
	packet := binary.LittleEndian.AppendUint32(nil, uint32(len(payload))|uint32(seqID)<<24)
	return append(packet, payload...)
}

func mysqlOKPacket(seqID byte) []byte {
	return mysqlSeqPacket(seqID, []byte{mysqlOKPacketHeader, 0, 0, 2, 0, 0, 0})
}

func mysqlHandshakeResponsePacket(caps, extCaps uint32, auth []byte, db string) []byte {
	payload := binary.LittleEndian.AppendUint32(nil, caps)
	payload = binary.LittleEndian.AppendUint32(payload, 1<<24)
	payload = append(payload, 0x21)
	payload = append(payload, make([]byte, mysqlHandshakeReservedLen)...)
	payload = binary.LittleEndian.AppendUint32(payload, extCaps)
	payload = append(payload, "app\x00"...)

	switch {
	case caps&mysqlCapPluginAuthLenencClientData != 0:
		payload = append(payload, mysqlLenEncInt(len(auth))...)
		payload = append(payload, auth...)
	case caps&mysqlCapSecureConnection != 0:
		payload = append(payload, byte(len(auth)))
		payload = append(payload, auth...)
	default:
		payload = append(payload, auth...)
		payload = append(payload, 0)
	}

	if caps&mysqlCapConnectWithDB != 0 {
		payload = append(payload, db...)
		payload = append(payload, 0)
	}
	payload = append(payload, "mysql_native_password\x00"...)

	return mysqlSeqPacket(mysqlHandshakeResponseSeqID, payload)
}

func mysqlSSLRequestPacket() []byte {
	payload := binary.LittleEndian.AppendUint32(nil, mysqlTestCaps|mysqlCapSSL)
	payload = binary.LittleEndian.AppendUint32(payload, 1<<24)
	payload = append(payload, 0x21)
	payload = append(payload, make([]byte, mysqlHandshakeReservedLen+mysqlHandshakeExtCapsLen)...)
	return mysqlSeqPacket(mysqlHandshakeResponseSeqID, payload)
}

func mysqlTLSHandshakeResponsePacket(extCaps uint32, db string) []byte {
	packet := mysqlHandshakeResponsePacket(mysqlTestCaps|mysqlCapSSL, extCaps, bytes.Repeat([]byte{0xaa}, 20), db)
	packet[mysqlSequenceIDOffset] = mysqlTLSHandshakeResponseSeqID
	return append(mysqlSSLRequestPacket(), packet...)
}

func TestParseMySQLHandshakeResponse(t *testing.T) {
	auth := bytes.Repeat([]byte{0xaa}, 20)
	valid := mysqlHandshakeResponsePacket(mysqlTestCaps, 0, auth, "shop")

	withReserved := bytes.Clone(valid)
	withReserved[sqlprune.MySQLHdrSize+mysqlHandshakeReservedOffset] = 1

	wrongSeq := bytes.Clone(valid)
	wrongSeq[mysqlSequenceIDOffset] = 0

	afterTLS := bytes.Clone(valid)
	afterTLS[mysqlSequenceIDOffset] = mysqlTLSHandshakeResponseSeqID

	tests := []struct {
		name     string
		raw      []byte
		expected mysqlConnInfo
		ok       bool
	}{
		{
			name:     "CLIENT_MYSQL cleared without extended capabilities is MySQL",
			raw:      valid,
			expected: mysqlConnInfo{db: "shop"},
			ok:       true,
		},
		{
			name:     "MariaDB extended capabilities do not affect the database",
			raw:      mysqlHandshakeResponsePacket(mysqlTestCaps, mariaDBTestExtCaps, auth, "shop"),
			expected: mysqlConnInfo{db: "shop"},
			ok:       true,
		},
		{
			name:     "no CLIENT_CONNECT_WITH_DB",
			raw:      mysqlHandshakeResponsePacket(mysqlTestCaps&^mysqlCapConnectWithDB, mariaDBTestExtCaps, auth, ""),
			expected: mysqlConnInfo{},
			ok:       true,
		},
		{
			name:     "multi-byte length-encoded auth response",
			raw:      mysqlHandshakeResponsePacket(mysqlTestCaps, 0, bytes.Repeat([]byte{0xaa}, 300), "shop"),
			expected: mysqlConnInfo{db: "shop"},
			ok:       true,
		},
		{
			name:     "1-byte length auth response",
			raw:      mysqlHandshakeResponsePacket(mysqlTestCaps&^mysqlCapPluginAuthLenencClientData, 0, auth, "shop"),
			expected: mysqlConnInfo{db: "shop"},
			ok:       true,
		},
		{
			name:     "NUL-terminated auth response",
			raw:      mysqlHandshakeResponsePacket(mysqlCapProtocol41|mysqlCapConnectWithDB, 0, []byte("secret"), "shop"),
			expected: mysqlConnInfo{db: "shop"},
			ok:       true,
		},
		{
			name:     "capture truncated inside the database name",
			raw:      valid[:len(valid)-len("op\x00mysql_native_password\x00")],
			expected: mysqlConnInfo{},
			ok:       true,
		},
		{
			name:     "SSLRequest captured together with the handshake response",
			raw:      mysqlTLSHandshakeResponsePacket(mariaDBTestExtCaps, "shop"),
			expected: mysqlConnInfo{db: "shop"},
			ok:       true,
		},
		{
			name: "SSLRequest alone",
			raw:  mysqlSSLRequestPacket(),
			ok:   true,
		},
		{
			name:     "handshake response after the SSL request",
			raw:      afterTLS,
			expected: mysqlConnInfo{db: "shop"},
			ok:       true,
		},
		{
			name: "wrong sequence ID",
			raw:  wrongSeq,
		},
		{
			name: "non-zero reserved filler",
			raw:  withReserved,
		},
		{
			name: "no CLIENT_PROTOCOL_41",
			raw:  mysqlHandshakeResponsePacket(mysqlTestCaps&^mysqlCapProtocol41, 0, auth, "shop"),
		},
		{
			name: "trailing bytes past the packet",
			raw:  append(bytes.Clone(valid), 0),
		},
		{
			name: "shorter than the fixed fields",
			raw:  valid[:sqlprune.MySQLHdrSize+mysqlHandshakeResponseFixedLen-1],
		},
		{
			name: "COM_QUERY",
			raw:  mysqlPacket(kMySQLQuery, []byte("SELECT * FROM accounts WHERE id = 1")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, ok := parseMySQLHandshakeResponse(tt.raw)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.expected, info)
		})
	}
}

func TestParseMySQLHandshakeResponseCaptured(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected mysqlConnInfo
	}{
		{
			name: "MariaDB Connector/J 3.5.1 to MariaDB 11.8",
			raw: "f00000018aa3be01000000402d000000000000000000000000000000000000002c000000726f6f74001493124ec2419e" +
				"ec3929299d5e388d4627e3d9d35873616b696c61006d7973716c5f6e61746976655f70617373776f726400980c5f636c" +
				"69656e745f6e616d65134d61726961444220436f6e6e6563746f722f4a0f5f636c69656e745f76657273696f6e05332e" +
				"352e310c5f7365727665725f686f7374093132372e302e302e31035f6f73054c696e7578075f74687265616401310c5f" +
				"6a6176615f76656e646f721045636c697073652041646f707469756d0d5f6a6176615f76657273696f6e0932312e302e" +
				"31322e31",
			expected: mysqlConnInfo{db: "sakila"},
		},
		{
			name: "libmariadb 3.4.10 to MariaDB 11.8",
			raw: "d60000018ca2bf00000010002d000000000000000000000000000000000000001d000000726f6f740014197224461f19" +
				"26bc3c1c27a186e9329c513ad93b73616b696c61006d7973716c5f6e61746976655f70617373776f7264007e035f6f73" +
				"054c696e75780c5f636c69656e745f6e616d650a6c69626d617269616462045f706964033133330f5f636c69656e745f" +
				"76657273696f6e06332e342e3130095f706c6174666f726d07616172636836340c70726f6772616d5f6e616d65056d79" +
				"73716c0c5f7365727665725f686f7374093132372e302e302e31",
			expected: mysqlConnInfo{db: "sakila"},
		},
		{
			name: "libmysqlclient 8.4.13 to MySQL 8.4",
			raw: "d60000018da2bf1900000001080000000000000000000000000000000000000000000000726f6f740020d646d8d5f952" +
				"310d4c5ca75eddaacf39598597a64e5244d65b939762a426690f73616b696c610063616368696e675f736861325f7061" +
				"7373776f72640072045f70696403323238095f706c6174666f726d0761617263683634035f6f73054c696e75780c5f63" +
				"6c69656e745f6e616d65086c69626d7973716c076f735f7573657204726f6f740f5f636c69656e745f76657273696f6e" +
				"06382e342e31330c70726f6772616d5f6e616d65056d7973716c",
			expected: mysqlConnInfo{db: "sakila"},
		},
		{
			name: "libmysqlclient 8.4.13 to MariaDB 11.8",
			raw: "c80000018da2bf1900000001080000000000000000000000000000000000000000000000726f6f740014cad47d64907b" +
				"980a11969d0874a8d766e10b4c2773616b696c61006d7973716c5f6e61746976655f70617373776f72640070045f7069" +
				"640131095f706c6174666f726d0761617263683634035f6f73054c696e75780c5f636c69656e745f6e616d65086c6962" +
				"6d7973716c076f735f7573657204726f6f740f5f636c69656e745f76657273696f6e06382e342e31330c70726f677261" +
				"6d5f6e616d65056d7973716c",
			expected: mysqlConnInfo{db: "sakila"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := hex.DecodeString(tt.raw)
			require.NoError(t, err)

			reserved := raw[sqlprune.MySQLHdrSize+mysqlHandshakeReservedOffset : sqlprune.MySQLHdrSize+mysqlHandshakeExtCapsOffset]
			assert.Equal(t, make([]byte, mysqlHandshakeReservedLen), reserved)

			info, ok := parseMySQLHandshakeResponse(raw)
			require.True(t, ok)
			assert.Equal(t, tt.expected, info)
		})
	}
}

func TestParseMySQLHandshakeResponseTruncationSafety(t *testing.T) {
	for _, caps := range []uint32{
		mysqlTestCaps,
		mysqlTestCaps &^ mysqlCapPluginAuthLenencClientData,
		mysqlCapProtocol41 | mysqlCapConnectWithDB,
	} {
		raw := mysqlHandshakeResponsePacket(caps, 0, bytes.Repeat([]byte{0xfe}, 260), "shop")
		for i := range raw {
			assert.NotPanics(t, func() { parseMySQLHandshakeResponse(raw[:i]) })
		}
	}
}

func TestMayBeMySQLUse(t *testing.T) {
	for query, expected := range map[string]bool{
		"USE orders":               true,
		"  use orders":             true,
		"/* app */ USE orders":     true,
		"-- c\nUSE orders":         true,
		"# c\nUSE orders":          true,
		"USE":                      true,
		"SELECT * FROM users":      false,
		"INSERT INTO t VALUES (1)": false,
		"":                         false,
	} {
		assert.Equal(t, expected, mayBeMySQLUse([]byte(query)), query)
	}
}

func TestParseMySQLDatabaseChange(t *testing.T) {
	tests := []struct {
		name     string
		req      []byte
		resp     []byte
		expected mysqlDatabaseChange
		ok       bool
	}{
		{
			name:     "COM_INIT_DB",
			req:      mysqlPacket(kMySQLInitDB, []byte("orders")),
			resp:     mysqlOKPacket(1),
			expected: mysqlDatabaseChange{db: "orders", standalone: true},
			ok:       true,
		},
		{
			name:     "USE",
			req:      mysqlPacket(kMySQLQuery, []byte("USE orders")),
			resp:     mysqlOKPacket(1),
			expected: mysqlDatabaseChange{db: "orders", standalone: true},
			ok:       true,
		},
		{
			name:     "USE with quoted name and semicolon",
			req:      mysqlPacket(kMySQLQuery, []byte("/* app */ use `my orders`;")),
			resp:     mysqlOKPacket(1),
			expected: mysqlDatabaseChange{db: "my orders", standalone: true},
			ok:       true,
		},
		{
			name: "USE followed by another token clears the database",
			req:  mysqlPacket(kMySQLQuery, []byte("USE orders extra")),
			resp: mysqlOKPacket(1),
			ok:   true,
		},
		{
			name: "multi-statement USE clears the database",
			req:  mysqlPacket(kMySQLQuery, []byte("USE orders; USE billing")),
			resp: mysqlOKPacket(1),
			ok:   true,
		},
		{
			name:     "COM_INIT_DB after a coalesced COM_STMT_CLOSE",
			req:      append(mysqlStmtClosePacket(7), mysqlPacket(kMySQLInitDB, []byte("orders"))...),
			resp:     mysqlOKPacket(1),
			expected: mysqlDatabaseChange{db: "orders", standalone: true},
			ok:       true,
		},
		{
			name:     "COM_INIT_DB with only the response header captured clears the database",
			req:      mysqlPacket(kMySQLInitDB, []byte("orders")),
			resp:     mysqlOKPacket(1)[:sqlprune.MySQLHdrSize],
			expected: mysqlDatabaseChange{standalone: true},
			ok:       true,
		},
		{
			name:     "USE with only the response header captured clears the database",
			req:      mysqlPacket(kMySQLQuery, []byte("USE orders")),
			resp:     mysqlOKPacket(1)[:sqlprune.MySQLHdrSize],
			expected: mysqlDatabaseChange{standalone: true},
			ok:       true,
		},
		{
			name:     "COM_CHANGE_USER clears the database whatever the response",
			req:      mysqlPacket(kMySQLChangeUser, []byte("app\x00\x00orders\x00")),
			resp:     mysqlSeqPacket(2, []byte{0xfe}),
			expected: mysqlDatabaseChange{standalone: true},
			ok:       true,
		},
		{
			name: "SELECT",
			req:  mysqlPacket(kMySQLQuery, []byte("SELECT * FROM orders")),
			resp: mysqlOKPacket(1),
		},
		{
			name: "error response",
			req:  mysqlPacket(kMySQLInitDB, []byte("orders")),
			resp: mysqlSeqPacket(1, []byte{0xff, 0x19, 0x04, '#', '4', '2', '0', '0', '0'}),
		},
		{
			name: "response with wrong sequence ID",
			req:  mysqlPacket(kMySQLInitDB, []byte("orders")),
			resp: mysqlOKPacket(2),
		},
		{
			name: "truncated request",
			req:  mysqlPacket(kMySQLInitDB, []byte("orders"))[:8],
			resp: mysqlOKPacket(1),
		},
		{
			name: "empty database",
			req:  mysqlPacket(kMySQLInitDB, nil),
			resp: mysqlOKPacket(1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			change, ok := parseMySQLDatabaseChange(tt.req, tt.resp)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.expected, change)
		})
	}
}

func TestReadTCPRequestIntoSpan_MySQLConnState(t *testing.T) {
	cfg := config.EBPFTracer{HeuristicSQLDetect: true, MySQLPreparedStatementsCacheSize: 16}
	ctx := NewEBPFParseContext(&cfg, nil, nil)
	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}

	readSpan := func(t *testing.T, r TCPRequestInfo) (request.Span, bool) {
		binaryRecord := bytes.Buffer{}
		require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, r))
		span, ignore, err := ReadTCPRequestIntoSpan(ctx, &cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
		require.NoError(t, err)
		return span, ignore
	}

	event := func(req, resp []byte, protocol BpfProtocolType) TCPRequestInfo {
		r := makeTCPReq(string(req), 3306)
		r.ProtocolType = protocol
		r.RespLen = uint32(len(resp))
		copy(r.Rbuf[:], resp)
		return r
	}

	query := func(protocol BpfProtocolType) TCPRequestInfo {
		return event(mysqlPacket(kMySQLQuery, []byte("SELECT * FROM accounts")), mysqlOKResponsePacket(), protocol)
	}

	auth := bytes.Repeat([]byte{0xaa}, 20)
	_, ignore := readSpan(t, event(mysqlHandshakeResponsePacket(mysqlTestCaps, mariaDBTestExtCaps, auth, "shop"), mysqlOKPacket(2), ProtocolTypeUnknown))
	assert.True(t, ignore, "handshake response should not produce a span")

	t.Run("kernel-assigned MySQL path", func(t *testing.T) {
		span, ignore := readSpan(t, query(ProtocolTypeMySQL))
		assert.False(t, ignore)
		assert.Equal(t, "SELECT", span.Method)
		assert.Equal(t, "shop", span.DBNamespace)
		assert.Equal(t, semconv.DBSystemNameMySQL, span.DBSystemName())
	})

	t.Run("heuristic SQL path", func(t *testing.T) {
		span, ignore := readSpan(t, query(ProtocolTypeUnknown))
		assert.False(t, ignore)
		assert.Equal(t, "SELECT", span.Method)
		assert.Equal(t, "shop", span.DBNamespace)
		assert.Equal(t, semconv.DBSystemNameMySQL, span.DBSystemName())
	})

	t.Run("COM_INIT_DB changes the namespace", func(t *testing.T) {
		_, ignore := readSpan(t, event(mysqlPacket(kMySQLInitDB, []byte("orders")), mysqlOKPacket(1), ProtocolTypeMySQL))
		assert.True(t, ignore)

		span, _ := readSpan(t, query(ProtocolTypeMySQL))
		assert.Equal(t, "orders", span.DBNamespace)
		assert.Equal(t, semconv.DBSystemNameMySQL, span.DBSystemName())
	})

	t.Run("USE changes the namespace", func(t *testing.T) {
		_, ignore := readSpan(t, event(mysqlPacket(kMySQLQuery, []byte("USE billing")), mysqlOKPacket(1), ProtocolTypeUnknown))
		assert.True(t, ignore)

		span, _ := readSpan(t, query(ProtocolTypeMySQL))
		assert.Equal(t, "billing", span.DBNamespace)
	})

	t.Run("COM_INIT_DB coalesced behind COM_STMT_CLOSE changes the namespace", func(t *testing.T) {
		req := append(mysqlStmtClosePacket(7), mysqlPacket(kMySQLInitDB, []byte("ledger"))...)
		_, ignore := readSpan(t, event(req, mysqlOKPacket(1), ProtocolTypeMySQL))
		assert.True(t, ignore)

		span, _ := readSpan(t, query(ProtocolTypeMySQL))
		assert.Equal(t, "ledger", span.DBNamespace)
	})

	t.Run("USE on the kernel-assigned path changes the namespace", func(t *testing.T) {
		readSpan(t, event(mysqlPacket(kMySQLQuery, []byte("USE payroll")), mysqlOKPacket(1), ProtocolTypeMySQL))

		span, _ := readSpan(t, query(ProtocolTypeMySQL))
		assert.Equal(t, "payroll", span.DBNamespace)
	})

	t.Run("multi-statement USE clears the namespace and keeps its span", func(t *testing.T) {
		for _, protocol := range []BpfProtocolType{ProtocolTypeMySQL, ProtocolTypeUnknown} {
			readSpan(t, event(mysqlPacket(kMySQLInitDB, []byte("orders")), mysqlOKPacket(1), ProtocolTypeMySQL))

			span, ignore := readSpan(t, event(mysqlPacket(kMySQLQuery, []byte("USE billing; SELECT * FROM invoices")), mysqlOKPacket(1), protocol))
			assert.False(t, ignore)
			assert.Equal(t, "invoices", span.Path)
			assert.Empty(t, span.DBNamespace)

			span, _ = readSpan(t, query(ProtocolTypeMySQL))
			assert.Empty(t, span.DBNamespace)
			assert.Equal(t, semconv.DBSystemNameMySQL, span.DBSystemName())
		}
	})

	t.Run("COM_CHANGE_USER clears the namespace", func(t *testing.T) {
		readSpan(t, event(mysqlPacket(kMySQLInitDB, []byte("orders")), mysqlOKPacket(1), ProtocolTypeMySQL))

		_, ignore := readSpan(t, event(mysqlPacket(kMySQLChangeUser, []byte("app\x00\x00orders\x00")), mysqlSeqPacket(2, []byte{0xfe}), ProtocolTypeMySQL))
		assert.True(t, ignore)

		span, _ := readSpan(t, query(ProtocolTypeMySQL))
		assert.Empty(t, span.DBNamespace)
		assert.Equal(t, semconv.DBSystemNameMySQL, span.DBSystemName())
	})

	t.Run("TLS handshake and a database change whose response is only a header", func(t *testing.T) {
		tlsEvent := func(req, resp []byte) TCPRequestInfo {
			r := event(req, resp, ProtocolTypeUnknown)
			r.ConnInfo.S_port = 50944
			return r
		}

		_, ignore := readSpan(t, tlsEvent(mysqlTLSHandshakeResponsePacket(0, "db1"), nil))
		assert.True(t, ignore)

		q := query(ProtocolTypeMySQL)
		q.ConnInfo.S_port = 50944
		span, _ := readSpan(t, q)
		assert.Equal(t, "db1", span.DBNamespace)
		assert.Equal(t, semconv.DBSystemNameMySQL, span.DBSystemName())

		_, ignore = readSpan(t, tlsEvent(mysqlPacket(kMySQLInitDB, []byte("db2")), mysqlOKPacket(1)[:sqlprune.MySQLHdrSize]))
		assert.True(t, ignore)

		span, _ = readSpan(t, q)
		assert.Empty(t, span.DBNamespace)
	})

	t.Run("handshake caught reversed", func(t *testing.T) {
		greeting := mysqlSeqPacket(0, []byte("\x0a11.4.2-MariaDB\x00"))
		reversed := event(greeting, mysqlHandshakeResponsePacket(mysqlTestCaps, 0, auth, "inventory"), ProtocolTypeUnknown)
		reversed.ConnInfo.D_port = 8081
		_, ignore := readSpan(t, reversed)
		assert.True(t, ignore)

		q := query(ProtocolTypeMySQL)
		q.ConnInfo = reverseTCPConnInfo(reversed.ConnInfo)
		span, _ := readSpan(t, q)
		assert.Equal(t, "inventory", span.DBNamespace)
		assert.Equal(t, semconv.DBSystemNameMySQL, span.DBSystemName())
	})

	t.Run("unknown connection is plain MySQL without namespace", func(t *testing.T) {
		q := query(ProtocolTypeMySQL)
		q.ConnInfo.D_port = 8082
		span, _ := readSpan(t, q)
		assert.Empty(t, span.DBNamespace)
		assert.Equal(t, semconv.DBSystemNameMySQL, span.DBSystemName())
	})
}
