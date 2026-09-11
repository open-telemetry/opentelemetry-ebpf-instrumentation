// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlprune

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestMySQLErrorCodes(t *testing.T) {
	for _, code := range []uint16{1, 1001, 1002, 1045, 4167, 4168, 20301, 39321, 50000, 65534} {
		t.Run(strconv.Itoa(int(code)), func(t *testing.T) {
			packet := mysqlErrorPacket(code, "#HY000test error")
			err := SQLParseError(request.DBMySQL, packet)
			require.NotNil(t, err)
			assert.Equal(t, code, err.Code)
			assert.Equal(t, "HY000", strings.TrimPrefix(err.SQLState, "#"))
			assert.Equal(t, "test error", err.Message)

			err = SQLParseError(request.DBMySQL, mysqlErrorPacket(code, "legacy error"))
			require.NotNil(t, err)
			assert.Equal(t, code, err.Code)
			assert.Empty(t, err.SQLState)
			assert.Equal(t, "legacy error", err.Message)
		})
	}
}

func TestMySQLErrorPacketValidation(t *testing.T) {
	t.Run("zero_code_with_sqlstate", func(t *testing.T) {
		assert.Nil(t, SQLParseError(request.DBMySQL, mysqlErrorPacket(0, "#HY000test error")))
	})
	t.Run("zero_code_without_sqlstate", func(t *testing.T) {
		assert.Nil(t, SQLParseError(request.DBMySQL, mysqlErrorPacket(0, "legacy error")))
	})

	t.Run("empty_message", func(t *testing.T) {
		packet := mysqlErrorPacket(20301, "#HY000")
		require.Len(t, packet, 13)
		err := SQLParseError(request.DBMySQL, packet)
		require.NotNil(t, err)
		assert.Equal(t, uint16(20301), err.Code)
		assert.Empty(t, err.Message)
		assert.Equal(t, "HY000", strings.TrimPrefix(err.SQLState, "#"))
	})
	t.Run("legacy_empty_message", func(t *testing.T) {
		packet := mysqlErrorPacket(1040, "")
		require.Len(t, packet, MySQLErrMinLen)
		err := SQLParseError(request.DBMySQL, packet)
		require.NotNil(t, err)
		assert.Equal(t, uint16(1040), err.Code)
		assert.Empty(t, err.SQLState)
		assert.Empty(t, err.Message)
	})

	for _, payloadLength := range []int{0, 1, 2} {
		t.Run("header_payload_too_short/"+strconv.Itoa(payloadLength), func(t *testing.T) {
			packet := mysqlErrorPacket(1040, "#HY000test error")
			packet[0] = byte(payloadLength)
			assert.Nil(t, SQLParseError(request.DBMySQL, packet))
		})
	}

	packet := mysqlErrorPacket(20301, "#HY000test error")
	for length := range MySQLHdrSize + 1 + 2 + 1 + 5 {
		if length == MySQLErrMinLen {
			continue // Cut right after the code, see truncated_after_code
		}
		t.Run("truncated/"+strconv.Itoa(length), func(t *testing.T) {
			assert.Nil(t, SQLParseError(request.DBMySQL, packet[:length]))
		})
	}
	t.Run("truncated_after_code", func(t *testing.T) {
		err := SQLParseError(request.DBMySQL, packet[:MySQLErrMinLen])
		require.NotNil(t, err)
		assert.Equal(t, uint16(20301), err.Code)
		assert.Empty(t, err.SQLState)
		assert.Empty(t, err.Message)
	})
	for _, marker := range []byte{0x00, 0x01, 0xfe} {
		packet[MySQLHdrSize] = marker
		assert.Nil(t, SQLParseError(request.DBMySQL, packet))
	}
	assert.Nil(t, SQLParseError(request.DBMySQL, mysqlErrorPacket(MySQLProgressReporting, "progress")))
}

func TestMySQLErrorPacketBounds(t *testing.T) {
	t.Run("trailing_bytes_after_message", func(t *testing.T) {
		packet := append(mysqlErrorPacket(1040, "#HY000boom"), "trailing-next-packet"...)
		err := SQLParseError(request.DBMySQL, packet)
		require.NotNil(t, err)
		assert.Equal(t, uint16(1040), err.Code)
		assert.Equal(t, "HY000", strings.TrimPrefix(err.SQLState, "#"))
		assert.Equal(t, "boom", err.Message)
	})
	t.Run("trailing_bytes_after_empty_message", func(t *testing.T) {
		packet := append(mysqlErrorPacket(1040, "#HY000"), "trailing-next-packet"...)
		err := SQLParseError(request.DBMySQL, packet)
		require.NotNil(t, err)
		assert.Equal(t, "HY000", strings.TrimPrefix(err.SQLState, "#"))
		assert.Empty(t, err.Message)
	})
	t.Run("legacy_message_too_short_for_sqlstate", func(t *testing.T) {
		packet := append(mysqlErrorPacket(1040, "#ab"), "trailing-next-packet"...)
		err := SQLParseError(request.DBMySQL, packet)
		require.NotNil(t, err)
		assert.Equal(t, uint16(1040), err.Code)
		assert.Empty(t, err.SQLState)
		assert.Equal(t, "#ab", err.Message)
	})
	t.Run("trailing_sqlstate_after_legacy_packet", func(t *testing.T) {
		packet := append(mysqlErrorPacket(1040, ""), "#HY000next"...)
		err := SQLParseError(request.DBMySQL, packet)
		require.NotNil(t, err)
		assert.Equal(t, uint16(1040), err.Code)
		assert.Empty(t, err.SQLState)
		assert.Empty(t, err.Message)
	})
	t.Run("message_cut_by_capture", func(t *testing.T) {
		packet := mysqlErrorPacket(1040, "#HY000Some error")
		err := SQLParseError(request.DBMySQL, packet[:len(packet)-len(" error")])
		require.NotNil(t, err)
		assert.Equal(t, "HY000", strings.TrimPrefix(err.SQLState, "#"))
		assert.Equal(t, "Some", err.Message)
	})
}

func mysqlErrorPacket(code uint16, message string) []byte {
	payloadLength := 1 + 2 + len(message)
	packet := make([]byte, MySQLHdrSize+payloadLength)
	binary.LittleEndian.PutUint32(packet, uint32(payloadLength))
	packet[MySQLHdrSize-1] = 1
	packet[MySQLHdrSize] = MySQLErrPacketMarker
	binary.LittleEndian.PutUint16(packet[MySQLHdrSize+1:], code)
	copy(packet[MySQLHdrSize+1+2:], message)
	return packet
}
