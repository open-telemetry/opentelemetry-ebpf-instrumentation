// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlprune

import (
	"encoding/binary"
	"strconv"
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
			assert.Equal(t, "#HY000", err.SQLState)
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
	packet := mysqlErrorPacket(20301, "#HY000test error")
	for length := 0; length < MySQLHdrSize+1+2+1+5; length++ {
		t.Run("truncated/"+strconv.Itoa(length), func(t *testing.T) {
			assert.Nil(t, SQLParseError(request.DBMySQL, packet[:length]))
		})
	}
	for _, marker := range []byte{0x00, 0x01, 0xfe} {
		packet[MySQLHdrSize] = marker
		assert.Nil(t, SQLParseError(request.DBMySQL, packet))
	}
	assert.Nil(t, SQLParseError(request.DBMySQL, mysqlErrorPacket(MySQLProgressReporting, "progress")))
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
