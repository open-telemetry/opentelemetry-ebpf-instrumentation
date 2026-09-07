// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func TestMySQLQueryProtocolLengthCollision(t *testing.T) {
	// Payload lengths 66, 67 and 81 start with PostgreSQL B, C and Q bytes.
	for _, sqlLength := range []int{64, 65, 66, 67, 79, 80, 81, 82, 336} {
		t.Run(fmt.Sprint(sqlLength), func(t *testing.T) {
			query := "SELECT 1" + strings.Repeat(" ", sqlLength-len("SELECT 1"))
			packet := make([]byte, 4+1+len(query))
			binary.LittleEndian.PutUint32(packet, uint32(1+len(query)))
			packet[4] = kMySQLQuery
			copy(packet[5:], query)
			buf := largebuf.NewLargeBufferFrom(packet)

			assert.False(t, isPostgres(buf))
			assert.Equal(t, request.DBMySQL, sqlKind(buf))

			cfg := &config.EBPFTracer{
				CouchbaseDBCacheSize:                1,
				MySQLPreparedStatementsCacheSize:    1,
				PostgresPreparedStatementsCacheSize: 1,
				MSSQLPreparedStatementsCacheSize:    1,
				KafkaTopicUUIDCacheSize:             1,
				MongoRequestsCacheSize:              1,
			}
			ctx := NewEBPFParseContext(cfg, nil, nil)
			span, ignore, matched, err := matchSQL(ctx, cfg, &TCPRequestInfo{}, buf, largebuf.NewLargeBufferFrom(nil))
			require.NoError(t, err)
			require.True(t, matched)
			assert.False(t, ignore)
			assert.Equal(t, int(request.DBMySQL), span.SubType)
			assert.Equal(t, "SELECT", span.Method)
		})
	}
}

func TestPostgresProtocolLengthField(t *testing.T) {
	t.Run("minimum_length", func(t *testing.T) {
		// Sync has no body: its length is exactly the four-byte length field.
		packet := []byte{'S', 0, 0, 0, 4}
		op, valid := isValidPostgresPayload(largebuf.NewLargeBufferFrom(packet))
		assert.True(t, valid)
		assert.Equal(t, byte('S'), op)
	})

	for _, op := range []byte{kPostgresQuery, kPostgresCommand, kPostgresBind} {
		for size := int32(-1); size < pgHeaderLen-1; size++ {
			t.Run(fmt.Sprintf("%c/%d", op, size), func(t *testing.T) {
				packet := make([]byte, pgHeaderLen)
				packet[0] = op
				binary.BigEndian.PutUint32(packet[1:], uint32(size))
				_, valid := isValidPostgresPayload(largebuf.NewLargeBufferFrom(packet))
				assert.False(t, valid)
			})
		}
	}

	for _, tt := range []struct {
		name string
		op   byte
		body []byte
	}{
		{"query", kPostgresQuery, []byte("SELECT 1\x00")},
		{"command_complete", kPostgresCommand, []byte("SELECT 1\x00")},
		{"bind", kPostgresBind, make([]byte, 8)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			packet := make([]byte, pgHeaderLen+len(tt.body))
			packet[0] = tt.op
			binary.BigEndian.PutUint32(packet[1:], uint32(len(packet)-1))
			copy(packet[pgHeaderLen:], tt.body)
			assert.True(t, isPostgres(largebuf.NewLargeBufferFrom(packet)))
			// Capture truncation does not change a valid declared length.
			assert.True(t, isPostgres(largebuf.NewLargeBufferFrom(packet[:pgHeaderLen])))
			for size := 0; size < pgHeaderLen; size++ {
				assert.False(t, isPostgres(largebuf.NewLargeBufferFrom(packet[:size])))
			}
		})
	}
}

func TestMySQLPreparedProtocolLengthCollision(t *testing.T) {
	for _, command := range []byte{kMySQLPrepare, kMySQLExecute} {
		for _, payloadLength := range []int{65, 66, 67, 68, 80, 81, 82, 255, 256, 337} {
			t.Run(fmt.Sprintf("%x/%d", command, payloadLength), func(t *testing.T) {
				packet := make([]byte, 4+payloadLength)
				binary.LittleEndian.PutUint32(packet, uint32(payloadLength))
				packet[4] = command
				if command == kMySQLPrepare {
					copy(packet[5:], "SELECT ?"+strings.Repeat(" ", payloadLength))
				} else {
					// Statement 1, cursor flags 0, iteration count 1, one non-NULL
					// string parameter with its type supplied on this execution.
					binary.LittleEndian.PutUint32(packet[5:], 1)
					binary.LittleEndian.PutUint32(packet[10:], 1)
					packet[15] = 1
					packet[16] = 0xfd // MYSQL_TYPE_VAR_STRING
					value := strings.Repeat("x", len(packet)-21)
					packet[18] = 0xfc // two-byte length-encoded string length
					binary.LittleEndian.PutUint16(packet[19:], uint16(len(value)))
					copy(packet[21:], value)
				}
				assert.Equal(t, request.DBMySQL, sqlKind(largebuf.NewLargeBufferFrom(packet)))
			})
		}
	}
}

func postgresTestPacket(op byte, body []byte) []byte {
	packet := make([]byte, pgHeaderLen+len(body))
	packet[0] = op
	binary.BigEndian.PutUint32(packet[1:], uint32(len(packet)-1))
	copy(packet[pgHeaderLen:], body)
	return packet
}

func TestPostgresReverseProtocolCollision(t *testing.T) {
	for _, op := range []byte{kPostgresQuery, kPostgresCommand, kPostgresBind} {
		for size := 12; size <= 3000; size++ {
			if byte(size) != kMySQLQuery && byte(size) != kMySQLPrepare && byte(size) != kMySQLExecute {
				continue
			}
			t.Run(fmt.Sprintf("%c/%d", op, size), func(t *testing.T) {
				var body []byte
				if op == kPostgresBind {
					// Portal name, empty statement name, zero formats/parameters/results.
					body = append([]byte(strings.Repeat("p", size-4-8)), make([]byte, 8)...)
				} else {
					body = append([]byte("SELECT 1"+strings.Repeat(" ", size-4-9)), 0)
				}
				packet := postgresTestPacket(op, body)
				require.True(t, isMySQL(largebuf.NewLargeBufferFrom(packet)), "exercise overlapping headers")
				assert.Equal(t, request.DBPostgres, sqlKind(largebuf.NewLargeBufferFrom(packet)))
				// Coalesced messages must not be mistaken for a length mismatch.
				pipeline := append(append([]byte(nil), packet...), postgresTestPacket('S', nil)...)
				assert.Equal(t, request.DBPostgres, sqlKind(largebuf.NewLargeBufferFrom(pipeline)))
				assert.Equal(t, request.DBGeneric, sqlKind(largebuf.NewLargeBufferFrom(packet[:6])))
			})
		}
	}
}

func TestPostgresBindBodyValidation(t *testing.T) {
	// Empty names, two parameter formats (text/binary), NULL and empty values,
	// and one binary result format.
	valid := []byte{0, 0, 0, 2, 0, 0, 0, 1, 0, 2, 255, 255, 255, 255, 0, 0, 0, 0, 0, 1, 0, 1}
	assert.True(t, validPostgresSQLBody(largebuf.NewLargeBufferFrom(postgresTestPacket(kPostgresBind, valid))))
	for n := 0; n < len(valid); n++ {
		assert.False(t, validPostgresSQLBody(largebuf.NewLargeBufferFrom(postgresTestPacket(kPostgresBind, valid[:n]))), "prefix %d", n)
	}
	for _, pos := range []int{7, 9, 13, 17, 21} {
		invalid := append([]byte(nil), valid...)
		invalid[pos] = 3 // bad format, count, NULL length, value length or result format
		assert.False(t, validPostgresSQLBody(largebuf.NewLargeBufferFrom(postgresTestPacket(kPostgresBind, invalid))), "offset %d", pos)
	}
	assert.False(t, validPostgresSQLBody(largebuf.NewLargeBufferFrom(postgresTestPacket(kPostgresBind, append(valid, 0)))))
}
