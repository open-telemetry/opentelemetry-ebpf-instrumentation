// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"slices"
	"strings"
	"unicode"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
	"go.opentelemetry.io/obi/pkg/internal/sqlprune"
)

type mysqlPreparedStatementsKey struct {
	connInfo BpfConnectionInfoT
	stmtID   uint32
}

type mysqlConnInfo struct {
	db string
}

type mySQLHdr struct {
	length  uint32 // payload length + sequence ID
	command uint8  // command type
}

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_init_db.html
const kMySQLInitDB = uint8(0x2)

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query.html
const kMySQLQuery = uint8(0x3)

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_change_user.html
const kMySQLChangeUser = uint8(0x11)

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_prepare.html
const kMySQLPrepare = uint8(0x16)

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_execute.html
const kMySQLExecute = uint8(0x17)

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_send_long_data.html
const kMySQLStmtSendLongData = uint8(0x18)

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_close.html
const kMySQLStmtClose = uint8(0x19)

const mysqlStatementIDSize = 4

const (
	mysqlCapConnectWithDB              = uint32(0x00000008)
	mysqlCapProtocol41                 = uint32(0x00000200)
	mysqlCapSSL                        = uint32(0x00000800)
	mysqlCapSecureConnection           = uint32(0x00008000)
	mysqlCapPluginAuthLenencClientData = uint32(0x00200000)
)

const (
	mysqlSequenceIDOffset          = 3
	mysqlHandshakeResponseSeqID    = 1
	mysqlTLSHandshakeResponseSeqID = 2
	mysqlHandshakeReservedOffset   = 9
	mysqlHandshakeReservedLen      = 19
	mysqlHandshakeExtCapsOffset    = mysqlHandshakeReservedOffset + mysqlHandshakeReservedLen
	mysqlHandshakeExtCapsLen       = 4
	mysqlHandshakeResponseFixedLen = mysqlHandshakeExtCapsOffset + mysqlHandshakeExtCapsLen
)

const (
	mysqlCommandSeqID         = 0
	mysqlCommandResponseSeqID = 1
	mysqlOKPacketHeader       = uint8(0x00)
	mysqlOKPacketMinLen       = 7
)

const (
	mysqlLenEncNull = 0xfb
	mysqlLenEncInt2 = 0xfc
	mysqlLenEncInt3 = 0xfd
	mysqlLenEncInt8 = 0xfe
)

func readMySQLHeader(b []byte) mySQLHdr {
	hdr := mySQLHdr{}

	hdr.length = binary.LittleEndian.Uint32(b[:4])
	hdr.length &= 0x00ffffff // remove the sequence id from the length
	hdr.command = b[4]

	return hdr
}

func isMySQL(b *largebuf.LargeBuffer) bool {
	// 4-byte header (3-byte length + 1-byte sequence ID) + command byte + at least 1 payload byte
	if b.Len() < 6 {
		return false
	}

	length, err := b.U32LEAt(0)
	if err != nil {
		return false
	}
	length &= 0x00ffffff // remove the sequence id from the length
	if length == 0 {
		return false
	}
	command, err := b.U8At(4)
	if err != nil {
		return false
	}

	return command == kMySQLQuery || command == kMySQLPrepare || command == kMySQLExecute
}

func mysqlNoResponseCommand(command uint8) bool {
	return command == kMySQLStmtSendLongData || command == kMySQLStmtClose
}

// skipMySQLNoResponseCommands advances past leading commands without a server
// response. The kernel keeps such requests pending and appends the next
// command sent on the connection into the same event, so they can be coalesced
// in front of the command the response buffer pairs with.
func skipMySQLNoResponseCommands(reqRaw []byte) ([]byte, []uint32) {
	var closedStmtIDs []uint32

	for {
		if len(reqRaw) < sqlprune.MySQLHdrSize+1 {
			return reqRaw, closedStmtIDs
		}

		hdr := readMySQLHeader(reqRaw)
		if !mysqlNoResponseCommand(hdr.command) {
			return reqRaw, closedStmtIDs
		}

		packetLen := sqlprune.MySQLHdrSize + int(hdr.length)
		if packetLen <= sqlprune.MySQLHdrSize || packetLen >= len(reqRaw) {
			return reqRaw, closedStmtIDs
		}

		if hdr.command == kMySQLStmtClose && hdr.length >= 1+mysqlStatementIDSize {
			stmtIDOffset := sqlprune.MySQLHdrSize + 1
			closedStmtIDs = append(closedStmtIDs, binary.LittleEndian.Uint32(reqRaw[stmtIDOffset:stmtIDOffset+mysqlStatementIDSize]))
		}

		reqRaw = reqRaw[packetLen:]
	}
}

func mysqlPreparedStatements(b []byte) (string, string, string) {
	execIdx := asciiIndexFold(b, sqlExecuteKeyword)
	if execIdx < 0 {
		return "", "", ""
	}

	text := string(b[execIdx:])
	parts := strings.Split(text, " ")
	op := parts[0]
	var table string
	if len(parts) > 1 {
		table = parts[1]
	}

	return op, table, text
}

func mysqlFirstPacket(b []byte) []byte {
	if len(b) < sqlprune.MySQLHdrSize+1 {
		return b
	}
	return b[:min(len(b), sqlprune.MySQLHdrSize+int(readMySQLHeader(b).length))]
}

func mysqlQueryText(b []byte) []byte {
	packet := mysqlFirstPacket(b)
	return packet[min(len(packet), sqlprune.MySQLHdrSize+1):]
}

func handleMySQL(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, error) {
	var (
		op, stmt string
		tables   []string
		span     request.Span
	)

	if responseBuffer.Len() < sqlprune.MySQLHdrSize+1 {
		slog.Debug("MySQL response too short")
		return span, errFallback
	}
	reqRaw := requestBuffer.UnsafeView()
	respRaw := responseBuffer.UnsafeView()

	// Commands without a server response (e.g. COM_STMT_CLOSE) stay pending in
	// the kernel, which appends the next command sent on the connection into
	// the same event. Skip them so the command paired with the response is the
	// one parsed below.
	reqRaw, closedStmtIDs := skipMySQLNoResponseCommands(reqRaw)
	for _, stmtID := range closedStmtIDs {
		parseCtx.mysqlPreparedStatements.Remove(mysqlPreparedStatementsKey{
			connInfo: event.ConnInfo,
			stmtID:   stmtID,
		})
	}
	if len(reqRaw) < sqlprune.MySQLHdrSize+1 {
		slog.Debug("MySQL request too short")
		return span, errFallback
	}

	if parseCtx.mysqlConns != nil {
		trackMySQLConnState(parseCtx, event.ConnInfo, reqRaw, respRaw)
	}

	sqlCommand := sqlprune.SQLParseCommandID(request.DBMySQL, reqRaw)
	sqlError := sqlprune.SQLParseError(request.DBMySQL, respRaw)

	switch sqlCommand {
	case "STMT_PREPARE":
		if sqlError != nil {
			slog.Debug("MySQL PREPARE command errored, ignoring", "error", sqlError)
			return span, errIgnore
		}

		// On the PREPARE command, the statement ID is the first 4 bytes after the header and command ID
		// in the response buffer.
		stmtID := sqlprune.SQLParseStatementID(request.DBMySQL, respRaw)
		if stmtID == 0 {
			slog.Debug("MySQL PREPARE command with invalid statement ID")
			return span, errFallback
		}

		_, _, stmt = detectSQL(mysqlQueryText(reqRaw))
		parseCtx.mysqlPreparedStatements.Add(mysqlPreparedStatementsKey{
			connInfo: event.ConnInfo,
			stmtID:   stmtID,
		}, stmt)

		return span, errIgnore
	case "STMT_EXECUTE":
		// On the EXECUTE command, the statement ID is the first 4 bytes after the header and command ID
		// in the request buffer.
		stmtID := sqlprune.SQLParseStatementID(request.DBMySQL, reqRaw)
		if stmtID == 0 {
			slog.Debug("MySQL EXECUTE command with invalid statement ID")
			return span, errFallback
		}

		var found bool
		stmt, found = parseCtx.mysqlPreparedStatements.Get(mysqlPreparedStatementsKey{
			connInfo: event.ConnInfo,
			stmtID:   stmtID,
		})
		if !found {
			slog.Debug("MySQL EXECUTE command with unknown statement ID", "stmtID", stmtID)
			return span, errFallback
		}
		op, tables = sqlprune.SQLParseOperationAndTables(stmt)
	case "QUERY":
		op, tables, stmt = detectSQL(mysqlQueryText(reqRaw))
	default:
		slog.Debug("MySQL command ID unhandled", "commandID", reqRaw[sqlprune.MySQLHdrSize])
		return span, errFallback
	}

	if !validSQL(op, len(tables) > 0, request.DBMySQL) {
		slog.Debug("MySQL operation and/or table are invalid", "stmt", stmt)
		return span, errFallback
	}

	span = TCPToSQLToSpan(event, op, tables, stmt, request.DBMySQL, sqlCommand, sqlError)
	setMySQLConnAttributes(parseCtx, event.ConnInfo, &span)
	return span, nil
}

func mysqlSequenceID(b []byte) uint8 {
	return b[mysqlSequenceIDOffset]
}

func parseMySQLHandshakeResponse(raw []byte) (mysqlConnInfo, bool) {
	raw = skipMySQLSSLRequest(raw)
	if len(raw) < sqlprune.MySQLHdrSize+mysqlHandshakeResponseFixedLen {
		return mysqlConnInfo{}, false
	}
	if seqID := mysqlSequenceID(raw); seqID != mysqlHandshakeResponseSeqID && seqID != mysqlTLSHandshakeResponseSeqID {
		return mysqlConnInfo{}, false
	}

	payloadLen := int(readMySQLHeader(raw).length)
	payload := raw[sqlprune.MySQLHdrSize:]
	if payloadLen < mysqlHandshakeResponseFixedLen || len(payload) > payloadLen {
		return mysqlConnInfo{}, false
	}

	caps := binary.LittleEndian.Uint32(payload)
	if caps&mysqlCapProtocol41 == 0 {
		return mysqlConnInfo{}, false
	}

	reserved := payload[mysqlHandshakeReservedOffset:mysqlHandshakeExtCapsOffset]
	if slices.ContainsFunc(reserved, func(b byte) bool { return b != 0 }) {
		return mysqlConnInfo{}, false
	}

	var info mysqlConnInfo
	if caps&mysqlCapConnectWithDB != 0 {
		info.db = mysqlHandshakeDatabase(payload[mysqlHandshakeResponseFixedLen:], caps)
	}

	return info, true
}

// skipMySQLSSLRequest drops an SSLRequest captured in the same event as the
// HandshakeResponse that follows it over TLS.
func skipMySQLSSLRequest(raw []byte) []byte {
	const sslRequestLen = sqlprune.MySQLHdrSize + mysqlHandshakeResponseFixedLen
	if len(raw) <= sslRequestLen || mysqlSequenceID(raw) != mysqlHandshakeResponseSeqID ||
		int(readMySQLHeader(raw).length) != mysqlHandshakeResponseFixedLen {
		return raw
	}

	caps := binary.LittleEndian.Uint32(raw[sqlprune.MySQLHdrSize:])
	if caps&mysqlCapSSL == 0 || mysqlSequenceID(raw[sslRequestLen:]) != mysqlTLSHandshakeResponseSeqID {
		return raw
	}
	return raw[sslRequestLen:]
}

func mysqlHandshakeDatabase(b []byte, caps uint32) string {
	_, b, ok := readMySQLNulString(b)
	if !ok {
		return ""
	}

	b, ok = skipMySQLAuthResponse(b, caps)
	if !ok {
		return ""
	}

	db, _, _ := readMySQLNulString(b)
	return db
}

func skipMySQLAuthResponse(b []byte, caps uint32) ([]byte, bool) {
	switch {
	case caps&mysqlCapPluginAuthLenencClientData != 0:
		authLen, size, ok := readMySQLLenEncInt(b)
		if !ok {
			return nil, false
		}
		return skipMySQLBytes(b[size:], authLen)
	case caps&mysqlCapSecureConnection != 0:
		if len(b) == 0 {
			return nil, false
		}
		return skipMySQLBytes(b[1:], uint64(b[0]))
	default:
		_, rest, ok := readMySQLNulString(b)
		return rest, ok
	}
}

func skipMySQLBytes(b []byte, n uint64) ([]byte, bool) {
	if n > uint64(len(b)) {
		return nil, false
	}
	return b[n:], true
}

func readMySQLNulString(b []byte) (string, []byte, bool) {
	value, rest, found := bytes.Cut(b, []byte{0})
	if !found {
		return "", nil, false
	}
	return string(value), rest, true
}

func readMySQLLenEncInt(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}

	var size int
	switch first := b[0]; {
	case first < mysqlLenEncNull:
		return uint64(first), 1, true
	case first == mysqlLenEncInt2:
		size = 2
	case first == mysqlLenEncInt3:
		size = 3
	case first == mysqlLenEncInt8:
		size = 8
	default:
		return 0, 0, false
	}

	if len(b) <= size {
		return 0, 0, false
	}

	var value uint64
	for i := size; i >= 1; i-- {
		value = value<<8 | uint64(b[i])
	}
	return value, size + 1, true
}

type mysqlDatabaseChange struct {
	db string
	// standalone is set when the exchange only changes the database and
	// carries no statement to report.
	standalone bool
}

func parseMySQLDatabaseChange(reqRaw, respRaw []byte) (mysqlDatabaseChange, bool) {
	reqRaw, _ = skipMySQLNoResponseCommands(reqRaw)
	if len(reqRaw) <= sqlprune.MySQLHdrSize {
		return mysqlDatabaseChange{}, false
	}

	req := readMySQLHeader(reqRaw)
	if mysqlSequenceID(reqRaw) != mysqlCommandSeqID || sqlprune.MySQLHdrSize+int(req.length) != len(reqRaw) {
		return mysqlDatabaseChange{}, false
	}

	if req.command == kMySQLChangeUser {
		return mysqlDatabaseChange{standalone: true}, true
	}

	status := mysqlCommandResponseStatus(respRaw)
	if status == mysqlResponseFailed {
		return mysqlDatabaseChange{}, false
	}

	arg := reqRaw[sqlprune.MySQLHdrSize+1:]
	switch req.command {
	case kMySQLInitDB:
		if len(arg) == 0 {
			return mysqlDatabaseChange{}, false
		}
		return mysqlDatabaseChange{db: knownMySQLDatabase(string(arg), status), standalone: true}, true
	case kMySQLQuery:
		if !mayBeMySQLUse(arg) {
			return mysqlDatabaseChange{}, false
		}
		db, isUse := sqlprune.SQLParseUseDatabase(string(arg))
		return mysqlDatabaseChange{db: knownMySQLDatabase(db, status), standalone: db != ""}, isUse
	default:
		return mysqlDatabaseChange{}, false
	}
}

var (
	mysqlUseKeyword      = []byte("use")
	mysqlCommentPrefixes = [][]byte{[]byte("/*"), []byte("--"), []byte("#")}
)

func mayBeMySQLUse(query []byte) bool {
	query = bytes.TrimLeftFunc(query, unicode.IsSpace)
	for _, prefix := range mysqlCommentPrefixes {
		if bytes.HasPrefix(query, prefix) {
			return true
		}
	}
	return len(query) >= len(mysqlUseKeyword) && equalFoldASCII(query[:len(mysqlUseKeyword)], mysqlUseKeyword)
}

type mysqlResponseStatus uint8

const (
	mysqlResponseFailed mysqlResponseStatus = iota
	mysqlResponseOK
	// Only the packet header was captured, as with libmysqlclient over TLS,
	// so OK and ERR cannot be told apart.
	mysqlResponseUnknown
)

func mysqlCommandResponseStatus(respRaw []byte) mysqlResponseStatus {
	if len(respRaw) < sqlprune.MySQLHdrSize || mysqlSequenceID(respRaw) != mysqlCommandResponseSeqID {
		return mysqlResponseFailed
	}
	if len(respRaw) == sqlprune.MySQLHdrSize {
		return mysqlResponseUnknown
	}

	resp := readMySQLHeader(respRaw)
	if resp.command == mysqlOKPacketHeader && resp.length >= mysqlOKPacketMinLen {
		return mysqlResponseOK
	}
	return mysqlResponseFailed
}

func knownMySQLDatabase(db string, status mysqlResponseStatus) string {
	if status == mysqlResponseOK {
		return db
	}
	return ""
}

func isMySQLConnStateCandidate(reqBuf, respBuf *largebuf.LargeBuffer) bool {
	seqID, err := reqBuf.U8At(mysqlSequenceIDOffset)
	if err != nil {
		return false
	}

	switch seqID {
	case mysqlHandshakeResponseSeqID, mysqlTLSHandshakeResponseSeqID:
		caps, err := reqBuf.U32LEAt(sqlprune.MySQLHdrSize)
		return err == nil && caps&mysqlCapProtocol41 != 0
	case mysqlCommandSeqID:
		command, err := reqBuf.U8At(sqlprune.MySQLHdrSize)
		if err != nil {
			return false
		}
		switch {
		case command == kMySQLChangeUser, mysqlNoResponseCommand(command):
			return true
		case command == kMySQLInitDB, command == kMySQLQuery:
			return mayBeMySQLOKResponse(respBuf)
		default:
			return false
		}
	default:
		return false
	}
}

func mayBeMySQLOKResponse(respBuf *largebuf.LargeBuffer) bool {
	respSeqID, err := respBuf.U8At(mysqlSequenceIDOffset)
	if err != nil || respSeqID != mysqlCommandResponseSeqID {
		return false
	}
	if respBuf.Len() == sqlprune.MySQLHdrSize {
		return true
	}
	respHeader, err := respBuf.U8At(sqlprune.MySQLHdrSize)
	return err == nil && respHeader == mysqlOKPacketHeader
}

// trackMySQLConnState records the handshake or a database change and reports
// whether the exchange has nothing else to report.
func trackMySQLConnState(parseCtx *EBPFParseContext, connInfo BpfConnectionInfoT, reqRaw, respRaw []byte) bool {
	if info, ok := parseMySQLHandshakeResponse(reqRaw); ok {
		parseCtx.mysqlConns.Add(connInfo, info)
		return true
	}

	change, ok := parseMySQLDatabaseChange(reqRaw, respRaw)
	if !ok {
		return false
	}

	info, found := parseCtx.mysqlConns.Get(connInfo)
	if !found && change.db == "" {
		return false
	}

	info.db = change.db
	parseCtx.mysqlConns.Add(connInfo, info)
	return change.standalone
}

func setMySQLConnAttributes(parseCtx *EBPFParseContext, connInfo BpfConnectionInfoT, span *request.Span) {
	if parseCtx.mysqlConns == nil {
		return
	}

	info, ok := parseCtx.mysqlConns.Get(connInfo)
	if !ok {
		return
	}

	span.DBNamespace = info.db
}
