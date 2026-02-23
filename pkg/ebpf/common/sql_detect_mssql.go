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

	op, table, stmt = mssqlPreparedStatements(requestBuffer)

	if !validSQL(op, table, request.DBMSSQL) {
		slog.Debug("MSSQL operation and/or table are invalid", "stmt", stmt)
		return span, errFallback
	}

	sqlCommand := sqlprune.SQLParseCommandID(request.DBMSSQL, requestBuffer)
	sqlError := sqlprune.SQLParseError(request.DBMSSQL, responseBuffer)

	return TCPToSQLToSpan(event, op, table, stmt, request.DBMSSQL, sqlCommand, sqlError), nil
}
