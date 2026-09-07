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
