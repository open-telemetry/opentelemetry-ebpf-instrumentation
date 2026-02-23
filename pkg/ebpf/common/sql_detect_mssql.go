// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"encoding/binary"
	"log/slog"
	"unicode/utf16"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/sqlprune"
)

type mssqlPreparedStatementsKey struct {
	connInfo BpfConnectionInfoT
	stmtID   uint32
}

const (
	kMSSQLHeaderLen = 8
	kMSSQLBatch     = 1
	kMSSQLRPC       = 3
	kMSSQLResponse  = 4

	kMSSQLProcIDPrepare  = 11
	kMSSQLProcIDExecute  = 12
	kMSSQLProcIDPrepExec = 13
)

func isMSSQL(b []byte) bool {
	if len(b) < kMSSQLHeaderLen {
		return false
	}

	// Check for valid packet types
	pktType := b[0]
	if pktType != kMSSQLBatch && pktType != kMSSQLRPC && pktType != kMSSQLResponse {
		return false
	}

	// Status byte check: upper 4 bits are reserved and should be 0.
	// This helps filter out random binary data that might match the packet type.
	status := b[1]
	if (status & 0xF0) != 0 {
		return false
	}

	// Length is big-endian in TDS. It's the length of the packet including the header.
	length := binary.BigEndian.Uint16(b[2:4])
	// The length must be at least the header length.
	// We also add an upper bound to avoid misinterpreting other protocols as MSSQL.
	// The default TDS packet size is 4096, but can be negotiated up to 32767.
	// We'll use a generous upper bound.
	if length < kMSSQLHeaderLen || length > 32768 {
		return false
	}

	// The Window byte (at offset 7) is currently unused and should be 0.
	return b[7] == 0
}

func ucs2ToUTF8(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16s := make([]uint16, len(b)/2)
	for i := 0; i < len(u16s); i++ {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16s))
}

func mssqlPreparedStatements(b []byte) (string, string, string) {
	if len(b) <= kMSSQLHeaderLen {
		return "", "", ""
	}

	pktType := b[0]
	if pktType == kMSSQLBatch {
		// SQL Batch
		payload := b[kMSSQLHeaderLen:]
		stmt := ucs2ToUTF8(payload)
		return detectSQL(stmt)
	}

	return "", "", ""
}

func handleMSSQL(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer []byte) (request.Span, error) {
	var (
		op, table, stmt string
		span            request.Span
	)

	if len(requestBuffer) < kMSSQLHeaderLen {
		slog.Debug("MSSQL request too short")
		return span, errFallback
	}

	pktType := requestBuffer[0]

	switch pktType {
	case kMSSQLBatch:
		op, table, stmt = mssqlPreparedStatements(requestBuffer)
	case kMSSQLRPC:
		procID, payload := parseMSSQLRPC(requestBuffer)
		switch procID {
		case kMSSQLProcIDPrepExec:
			// Extract SQL from payload
			text := ucs2ToUTF8(payload)
			op, table, stmt = detectSQL(text)
		case kMSSQLProcIDPrepare:
			// Extract SQL and cache it
			text := ucs2ToUTF8(payload)
			_, _, stmt = detectSQL(text)
			handle := parseHandleFromPrepareResponse(responseBuffer)
			if handle != 0 && stmt != "" {
				parseCtx.mssqlPreparedStatements.Add(mssqlPreparedStatementsKey{
					connInfo: event.ConnInfo,
					stmtID:   handle,
				}, stmt)
				return span, errIgnore
			}
		case kMSSQLProcIDExecute:
			handle := parseHandleFromExecute(payload)
			if handle != 0 {
				var found bool
				stmt, found = parseCtx.mssqlPreparedStatements.Get(mssqlPreparedStatementsKey{
					connInfo: event.ConnInfo,
					stmtID:   handle,
				})
				if found {
					op, table = sqlprune.SQLParseOperationAndTable(stmt)
				}
			}
		}
	}

	if !validSQL(op, table, request.DBMSSQL) {
		slog.Debug("MSSQL operation and/or table are invalid", "stmt", stmt)
		return span, errFallback
	}

	sqlCommand := sqlprune.SQLParseCommandID(request.DBMSSQL, requestBuffer)
	sqlError := sqlprune.SQLParseError(request.DBMSSQL, responseBuffer)

	return TCPToSQLToSpan(event, op, table, stmt, request.DBMSSQL, sqlCommand, sqlError), nil
}

func parseMSSQLRPC(b []byte) (uint16, []byte) {
	if len(b) < kMSSQLHeaderLen+2 {
		return 0, nil
	}
	data := b[kMSSQLHeaderLen:]
	nameLen := binary.LittleEndian.Uint16(data[:2])
	data = data[2:]

	var procID uint16
	if nameLen == 0xFFFF {
		if len(data) < 2 {
			return 0, nil
		}
		procID = binary.LittleEndian.Uint16(data[:2])
		data = data[2:]
	} else {
		skip := int(nameLen) * 2
		if len(data) < skip {
			return 0, nil
		}
		data = data[skip:]
	}
	// Skip options
	if len(data) < 2 {
		return procID, nil
	}
	data = data[2:]
	return procID, data
}

func parseHandleFromExecute(data []byte) uint32 {
	if len(data) < 3 {
		return 0
	}
	nameLen := int(data[0])
	data = data[1:]
	if len(data) < nameLen*2+2 {
		return 0
	}
	data = data[nameLen*2:] // skip name

	// status
	data = data[1:]

	// type
	typ := data[0]
	data = data[1:]

	switch typ {
	case 0x26: // TI_INT4
		if len(data) < 4 {
			return 0
		}
		return binary.LittleEndian.Uint32(data[:4])
	case 0x38: // TI_INTN
		if len(data) < 5 {
			return 0
		}
		length := data[0]
		data = data[1:]
		if length == 4 {
			return binary.LittleEndian.Uint32(data[:4])
		}
	}
	return 0
}

func parseHandleFromPrepareResponse(b []byte) uint32 {
	if len(b) < kMSSQLHeaderLen {
		return 0
	}
	data := b[kMSSQLHeaderLen:]

	// Scan for 0xAC (RETURNVALUE)
	for i := 0; i < len(data); i++ {
		if data[i] == 0xAC {
			curr := data[i+1:]
			if len(curr) < 3 {
				continue
			}
			// Ordinal (2)
			curr = curr[2:]
			// NameLen (1)
			nameLen := int(curr[0])
			curr = curr[1:]
			if len(curr) < nameLen*2+7 {
				continue
			}
			curr = curr[nameLen*2:] // skip name

			// Status (1)
			curr = curr[1:]
			// UserType (4)
			curr = curr[4:]
			// Flags (2)
			curr = curr[2:]

			// TypeInfo
			if len(curr) < 1 {
				continue
			}
			typ := curr[0]
			curr = curr[1:]

			if typ == 0x26 { // TI_INT4
				if len(curr) < 4 {
					continue
				}
				return binary.LittleEndian.Uint32(curr[:4])
			} else if typ == 0x38 { // TI_INTN
				if len(curr) < 1 {
					continue
				}
				length := curr[0]
				curr = curr[1:]
				if length == 4 && len(curr) >= 4 {
					return binary.LittleEndian.Uint32(curr[:4])
				}
			}
		}
	}
	return 0
}
