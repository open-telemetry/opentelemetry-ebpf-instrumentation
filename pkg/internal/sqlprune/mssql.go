// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlprune // import "go.opentelemetry.io/obi/pkg/internal/sqlprune"

import (
	"encoding/binary"
	"unicode/utf16"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const (
	MSSQLHdrSize  = 8
	MSSQLErrToken = 0xAA
)

func parseMSSQLCommandID(buf []uint8) uint8 {
	if len(buf) < 1 {
		return 0
	}
	// The first byte is the packet type
	return buf[0]
}

func mssqlCommandIDToString(commandID uint8) string {
	switch commandID {
	case 1:
		return "SQL Batch"
	case 3:
		return "RPC"
	case 4:
		return "Response"
	default:
		return ""
	}
}

func parseMSSQLError(buf []uint8) *request.SQLError {
	if len(buf) < MSSQLHdrSize+1 {
		return nil
	}

	// Check if it is a response packet
	if buf[0] != 4 {
		return nil
	}

	offset := MSSQLHdrSize
	if offset >= len(buf) {
		return nil
	}

	// We only check the first token for now to avoid complex parsing
	token := buf[offset]
	if token == MSSQLErrToken {
		offset++ // skip token
		if offset+2 > len(buf) {
			return nil
		}
		// Length of the error token stream
		// length := binary.LittleEndian.Uint16(buf[offset : offset+2])
		offset += 2

		// Number (4 bytes)
		if offset+4 > len(buf) {
			return nil
		}
		code := binary.LittleEndian.Uint32(buf[offset : offset+4])
		offset += 4

		// State (1 byte)
		if offset+1 > len(buf) {
			return nil
		}
		offset++

		// Class (1 byte)
		if offset+1 > len(buf) {
			return nil
		}
		offset++

		// MsgText (US_VARCHAR)
		if offset+2 > len(buf) {
			return nil
		}
		msgLen := int(binary.LittleEndian.Uint16(buf[offset : offset+2]))
		offset += 2

		if offset+msgLen*2 > len(buf) {
			return nil
		}
		msgBytes := buf[offset : offset+msgLen*2]

		u16s := make([]uint16, msgLen)
		for i := 0; i < msgLen; i++ {
			u16s[i] = binary.LittleEndian.Uint16(msgBytes[i*2:])
		}
		message := string(utf16.Decode(u16s))

		return &request.SQLError{
			Code:    uint16(code),
			Message: message,
		}
	}

	return nil
}
