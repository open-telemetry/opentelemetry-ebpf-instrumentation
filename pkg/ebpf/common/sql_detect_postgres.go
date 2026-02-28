// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/sqlprune"
)

type postgresPreparedStatementsKey struct {
	connInfo BpfConnectionInfoT
	stmtName string
}

type postgresPortalsKey struct {
	connInfo   BpfConnectionInfoT
	portalName string
}

const (
	kPostgresBind    = byte('B')
	kPostgresQuery   = byte('Q')
	kPostgresCommand = byte('C')
)

func isPostgres(b []byte) bool {
	op, ok := isValidPostgresPayload(b)

	return ok && (op == kPostgresQuery || op == kPostgresCommand || op == kPostgresBind)
}

func isPostgresBindCommand(b []byte) bool {
	op, ok := isValidPostgresPayload(b)

	return ok && (op == kPostgresBind)
}

func isPostgresQueryCommand(b []byte) bool {
	op, ok := isValidPostgresPayload(b)

	return ok && (op == kPostgresQuery)
}

func isValidPostgresPayload(b []byte) (byte, bool) {
	// https://github.com/postgres/postgres/blob/master/src/interfaces/libpq/fe-protocol3.c#L97
	if len(b) < 5 {
		return 0, false
	}

	size := int32(binary.BigEndian.Uint32(b[1:5]))
	if size < 0 || size > 3000 {
		return 0, false
	}

	return b[0], true
}

//nolint:cyclop
func parsePostgresBindCommand(buf []byte) (string, string, []string, error) {
	statement := []byte{}
	portal := []byte{}
	args := []string{}

	size := min(int(binary.BigEndian.Uint32(buf[1:5])), len(buf))
	ptr := 5

	// parse statement, zero terminated string
	for {
		if ptr >= size {
			return string(statement), string(portal), args, errors.New("too short, while parsing statement")
		}
		b := buf[ptr]
		ptr++

		if b == 0 {
			break
		}
		statement = append(statement, b)
	}

	// parse portal, zero terminated string
	for {
		if ptr >= size {
			return string(statement), string(portal), args, errors.New("too short, while parsing portal")
		}
		b := buf[ptr]
		ptr++

		if b == 0 {
			break
		}
		portal = append(portal, b)
	}

	if ptr+2 >= size {
		return string(statement), string(portal), args, errors.New("too short, while parsing format codes")
	}

	formats := int16(binary.BigEndian.Uint16(buf[ptr : ptr+2]))
	ptr += 2
	for i := 0; i < int(formats); i++ {
		// ignore format codes
		if ptr+2 >= size {
			return string(statement), string(portal), args, errors.New("too short, while parsing format codes")
		}
		ptr += 2
	}

	if ptr+2 >= size {
		return string(statement), string(portal), args, errors.New("too short, while parsing format codes")
	}

	params := int16(binary.BigEndian.Uint16(buf[ptr : ptr+2]))
	ptr += 2
	for i := 0; i < int(params); i++ {
		if ptr+4 >= size {
			return string(statement), string(portal), args, errors.New("too short, while parsing params")
		}
		argLen := int(binary.BigEndian.Uint32(buf[ptr : ptr+4]))
		ptr += 4
		arg := []byte{}
		for range argLen {
			if ptr >= size {
				break
			}
			arg = append(arg, buf[ptr])
			ptr++
		}
		args = append(args, string(arg))
	}

	return string(statement), string(portal), args, nil
}

func parsePosgresQueryCommand(buf []byte) (string, error) {
	size := min(int(binary.BigEndian.Uint32(buf[1:5])), len(buf))
	ptr := 5

	if ptr > size {
		return "", errors.New("too short")
	}

	return string(buf[ptr:size]), nil
}

func postgresPreparedStatements(b []byte) (string, string, string) {
	var op, table, sql string
	if isPostgresBindCommand(b) {
		statement, portal, args, err := parsePostgresBindCommand(b)
		if err == nil {
			op = "PREPARED STATEMENT"
			table = fmt.Sprintf("%s.%s", statement, portal)
			var sqlBuilder strings.Builder
			for _, arg := range args {
				if isASCII(arg) {
					sqlBuilder.WriteString(arg)
					sqlBuilder.WriteString(" ")
				}
			}
			sql = sqlBuilder.String()
		}
	} else if isPostgresQueryCommand(b) {
		text, err := parsePosgresQueryCommand(b)
		if err == nil {
			query := asciiToUpper(text)
			if strings.HasPrefix(query, "EXECUTE ") {
				parts := strings.Split(text, " ")
				op = parts[0]
				if len(parts) > 1 {
					table = parts[1]
				}
				sql = text
			}
		}
	}

	return op, table, sql
}

type postgresMessage struct {
	typ  string
	data []byte
}

type postgresMessageIterator struct {
	r   *LargeBufferReader
	err error
	eof bool
}

func (it *postgresMessageIterator) isEOF() bool {
	return it.eof
}

func (it *postgresMessageIterator) next() (msg postgresMessage) {
	if it.err != nil || it.r.Remaining() == 0 {
		it.eof = true
		return
	}
	if it.r.Remaining() < sqlprune.PostgresHdrSize {
		it.err = errors.New("remaining buffer too short for message header")
		return
	}

	// Read the 5-byte header (type byte + 4-byte size) atomically.
	// SQLParseCommandID needs buf[0] as the type byte; it requires len(buf) >= PostgresHdrSize (5).
	hdrBuf, err := it.r.ReadN(sqlprune.PostgresHdrSize)
	if err != nil {
		it.err = err
		return
	}
	msgType := sqlprune.SQLParseCommandID(request.DBPostgres, hdrBuf)
	size := int32(binary.BigEndian.Uint32(hdrBuf[1:5]))

	if size < sqlprune.PostgresHdrSize-1 {
		it.err = errors.New("malformed Postgres message")
		return
	}

	payloadSize := size - sqlprune.PostgresHdrSize + 1
	if it.r.Remaining() < int(payloadSize) {
		it.err = fmt.Errorf("remaining buffer too short for message data: expected %d bytes, got %d", payloadSize, it.r.Remaining())
		return
	}

	// ReadN is safe: all uses of msg.data convert it to a Go string before the next
	// it.next() call, so scratch overwrite between iterations is not a concern.
	// Use empty non-nil slice for zero-length payloads to match []byte{} semantics.
	data := []byte{}
	if payloadSize > 0 {
		data, err = it.r.ReadN(int(payloadSize))
		if err != nil {
			it.err = err
			return
		}
	}

	msg = postgresMessage{typ: msgType, data: data}
	return
}

func handlePostgres(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *LargeBufferReader) (request.Span, error) {
	var (
		hasSpan         bool
		op, table, stmt string
		span            request.Span
	)

	if requestBuffer.Remaining() < sqlprune.PostgresHdrSize+1 {
		slog.Debug("Postgres request too short")
		return span, errFallback
	}
	if responseBuffer.Remaining() < sqlprune.PostgresHdrSize+1 {
		slog.Debug("Postgres response too short")
		return span, errFallback
	}

	// ReadN(remaining) for response — materialized once for sqlprune.SQLParseError.
	respRaw, _ := responseBuffer.ReadN(responseBuffer.Remaining())

	var (
		msg      postgresMessage
		it       = &postgresMessageIterator{r: requestBuffer}
		sqlError = sqlprune.SQLParseError(request.DBPostgres, respRaw)
	)

Loop:
	for {
		if msg = it.next(); it.isEOF() {
			break
		}
		if it.err != nil {
			slog.Debug("failed to parse Postgres request messages", "error", it.err)
			return span, errFallback
		}

		switch msg.typ {
		case "QUERY":
			op, table, stmt = detectSQL(string(msg.data))
			hasSpan = true
			break Loop
		case "PARSE":
			// On the PARSE command, the statement name is the first 4 bytes after the header and command ID
			// in the request buffer.
			stmtName := unix.ByteSliceToString(msg.data)
			stmtNameLen := len(stmtName)
			_, _, stmt = detectSQL(string(msg.data[stmtNameLen:]))

			parseCtx.postgresPreparedStatements.Add(postgresPreparedStatementsKey{
				connInfo: event.ConnInfo,
				stmtName: stmtName,
			}, stmt)

			continue
		case "BIND":
			portal := unix.ByteSliceToString(msg.data)
			portalLen := len(portal) + 1 // +1 for the null terminator
			stmtName := unix.ByteSliceToString(msg.data[portalLen:])

			parseCtx.postgresPortals.Add(postgresPortalsKey{
				connInfo:   event.ConnInfo,
				portalName: portal,
			}, stmtName)

			continue
		case "EXECUTE":
			portalKey := postgresPortalsKey{
				connInfo:   event.ConnInfo,
				portalName: unix.ByteSliceToString(msg.data),
			}

			stmtName, found := parseCtx.postgresPortals.Get(portalKey)
			if !found {
				slog.Debug("Postgres EXECUTE command with unknown portal", "portal", portalKey.portalName)
				continue
			}

			preparedStmtKey := postgresPreparedStatementsKey{
				connInfo: event.ConnInfo,
				stmtName: stmtName,
			}

			stmt, found = parseCtx.postgresPreparedStatements.Get(preparedStmtKey)
			if !found {
				slog.Debug("Postgres EXECUTE command with unknown statement", "stmtName", stmtName)
				continue
			}

			op, table = sqlprune.SQLParseOperationAndTable(stmt)
			hasSpan = true
			break Loop
		default:
			continue
		}
	}

	if !hasSpan {
		return span, errIgnore
	}

	if !validSQL(op, table, request.DBPostgres) {
		// This can happen for stuff like 'BEGIN', etc.
		slog.Debug("Postgres operation and/or table are invalid", "stmt", stmt)
		return span, errFallback
	}

	return TCPToSQLToSpan(event, op, table, stmt, request.DBPostgres, msg.typ, sqlError), nil
}
