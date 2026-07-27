// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func TestPostgresMessagesIterator(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		want    []postgresMessage
		wantErr bool
	}{
		{
			name: "single valid message",
			// Message: type 'Q', length 11, data "SELECT\x00"
			buf: append([]byte{'Q', 0, 0, 0, 11}, append([]byte("SELECT"), 0)...),
			want: []postgresMessage{
				{
					typ:  "QUERY",
					data: append([]byte("SELECT"), 0),
				},
			},
			wantErr: false,
		},
		{
			name: "multiple valid messages",
			buf: func() []byte {
				// First message: type 'Q', length 11, data "SELECT\x00"
				// Second message: type 'Q', length 11, data "COMMIT\x00"
				b := []byte{'Q', 0, 0, 0, 11}
				b = append(b, append([]byte("SELECT"), 0)...)
				b = append(b, 'Q', 0, 0, 0, 11)
				b = append(b, append([]byte("COMMIT"), 0)...)
				return b
			}(),
			want: []postgresMessage{
				{
					typ:  "QUERY",
					data: append([]byte("SELECT"), 0),
				},
				{
					typ:  "QUERY",
					data: append([]byte("COMMIT"), 0),
				},
			},
			wantErr: false,
		},
		{
			name:    "buffer too short for header",
			buf:     []byte{'Q', 0, 0, 0},
			want:    nil,
			wantErr: true,
		},
		{
			name: "buffer too short for message data",
			// Header says length 20, but only 10 bytes in buffer (5 header + 5 data)
			buf:     append([]byte{'Q', 0, 0, 0, 20}, []byte("short")...),
			want:    nil,
			wantErr: true,
		},
		{
			name: "zero length message",
			// Header says length 4 (header only, no data)
			buf: []byte{'Q', 0, 0, 0, 4},
			want: []postgresMessage{
				{
					typ:  "QUERY",
					data: []byte{},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []postgresMessage
			it := &postgresMessageIterator{r: largebuf.NewLargeBufferFrom(tt.buf).NewReader()}
			for {
				msg := it.next()
				if it.isEOF() {
					break
				}
				got = append(got, msg)
			}
			if tt.wantErr {
				assert.Error(t, it.err, "postgresMessageIterator should return an error for test case: %s", tt.name)
				return
			}
			require.NoError(t, it.err, "postgresMessageIterator returned unexpected error for test case: %s", tt.name)
			assert.Len(t, got, len(tt.want), "postgresMessageIterator returned unexpected number of messages for test case: %s", tt.name)
			assert.Equal(t, tt.want, got, "postgresMessageIterator returned unexpected messages for test case: %s", tt.name)
		})
	}
}

func TestPostgresMessagesIteratorNoAllocs(t *testing.T) {
	buf := func() []byte {
		// First message: type 'Q', length 11, data "SELECT\x00"
		// Second message: type 'Q', length 11, data "COMMIT\x00"
		b := []byte{'Q', 0, 0, 0, 11}
		b = append(b, append([]byte("SELECT"), 0)...)
		b = append(b, 'Q', 0, 0, 0, 11)
		b = append(b, append([]byte("COMMIT"), 0)...)
		return b
	}()

	lb := largebuf.NewLargeBufferFrom(buf)
	r := lb.NewReader()
	allocs := testing.AllocsPerRun(1000, func() {
		r.Reset()
		it := postgresMessageIterator{r: r}

		for {
			it.next()
			if it.isEOF() {
				break
			}
		}
	})

	if allocs != 0 {
		t.Errorf("MessageIterator allocated %v allocs per run; want 0", allocs)
	}
}

func TestParsePostgresBindNames(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantPortal string
		wantStmt   string
		wantOK     bool
	}{
		{
			name:       "valid portal and statement",
			data:       []byte("portal\x00stmt\x00rest"),
			wantPortal: "portal",
			wantStmt:   "stmt",
			wantOK:     true,
		},
		{
			name:       "valid unnamed portal",
			data:       []byte("\x00stmt\x00rest"),
			wantPortal: "",
			wantStmt:   "stmt",
			wantOK:     true,
		},
		{
			name:       "valid unnamed portal and statement",
			data:       []byte("\x00\x00rest"),
			wantPortal: "",
			wantStmt:   "",
			wantOK:     true,
		},
		{
			name:   "empty payload",
			data:   []byte{},
			wantOK: false,
		},
		{
			name:   "missing portal terminator",
			data:   []byte("portal-without-nul"),
			wantOK: false,
		},
		{
			name:   "missing statement name",
			data:   []byte("portal\x00"),
			wantOK: false,
		},
		{
			name:       "missing statement terminator",
			data:       []byte("portal\x00stmt-without-nul"),
			wantPortal: "portal",
			wantStmt:   "stmt-without-nul",
			wantOK:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			portal, stmt, ok := parsePostgresBindNames(tt.data)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantPortal, portal)
			assert.Equal(t, tt.wantStmt, stmt)
		})
	}
}

func pgStartupMessage(params ...string) []byte {
	body := []byte{0, 3, 0, 0} // protocol 3.0
	for _, p := range params {
		body = append(body, p...)
		body = append(body, 0)
	}
	body = append(body, 0)
	msg := binary.BigEndian.AppendUint32(nil, uint32(4+len(body)))
	return append(msg, body...)
}

func TestParsePostgresStartup(t *testing.T) {
	tests := []struct {
		name   string
		buf    []byte
		wantDB string
		wantOK bool
	}{
		{
			name:   "database parameter",
			buf:    pgStartupMessage("user", "postgres", "database", "mydb"),
			wantDB: "mydb",
			wantOK: true,
		},
		{
			name:   "database defaults to user",
			buf:    pgStartupMessage("user", "postgres", "application_name", "psql"),
			wantDB: "postgres",
			wantOK: true,
		},
		{
			name:   "protocol 3.2",
			buf:    append([]byte{0, 0, 0, 23, 0, 3, 0, 2}, "database\x00mydb\x00\x00"...),
			wantDB: "mydb",
			wantOK: true,
		},
		{
			name: "SSLRequest is not a startup",
			// length 8, request code 80877103
			buf: []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f},
		},
		{
			// sslmode=prefer: BPF drops the 1-byte 'N' refusal, gluing both messages
			name:   "SSLRequest glued to startup",
			buf:    append([]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}, pgStartupMessage("user", "postgres", "database", "sqltest")...),
			wantDB: "sqltest",
			wantOK: true,
		},
		{
			name:   "GSSENC and SSLRequest glued to startup",
			buf:    append([]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x30, 0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}, pgStartupMessage("database", "mydb")...),
			wantDB: "mydb",
			wantOK: true,
		},
		{
			name: "SSLRequest glued to garbage",
			buf:  append([]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xff),
		},
		{
			name: "trailing bytes rejected (Kafka-like framing)",
			buf:  append(pgStartupMessage("user", "postgres"), 0xff),
		},
		{
			name: "wrong protocol version",
			buf:  []byte{0, 0, 0, 9, 0, 2, 0, 0, 0},
		},
		{
			name: "truncated before parameters",
			buf:  []byte{0, 0, 0, 20, 0, 3, 0, 0},
		},
		{
			// cut mid-"database" pair: the explicit db name is lost, user alone must not be trusted
			name: "truncated capture does not fall back to user",
			buf: func() []byte {
				m := pgStartupMessage("user", "postgres", "database", "mydb")
				return m[:len(m)-10]
			}(),
		},
		{
			name: "truncated capture with database already captured",
			buf: func() []byte {
				m := pgStartupMessage("database", "mydb", "application_name", "psql")
				return m[:len(m)-8]
			}(),
			wantDB: "mydb",
			wantOK: true,
		},
		{
			name: "regular typed message",
			buf:  append([]byte{'Q', 0, 0, 0, 11}, append([]byte("SELECT"), 0)...),
		},
		{
			name: "empty buffer",
			buf:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, ok := parsePostgresStartup(largebuf.NewLargeBufferFrom(tt.buf))
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantDB, db)
		})
	}
}

func chunkedLargeBuffer(buf []byte, chunkSize int) *largebuf.LargeBuffer {
	lb := largebuf.NewLargeBuffer()
	for len(buf) > 0 {
		n := min(chunkSize, len(buf))
		lb.AppendChunk(buf[:n])
		buf = buf[n:]
	}
	return lb
}

// BPF captures can cut the StartupMessage at any byte; the parser must never
// panic and must never invent a namespace it didn't fully read
func TestParsePostgresStartupTruncationSafety(t *testing.T) {
	buffers := map[string][]byte{
		"plain":      pgStartupMessage("user", "postgres", "database", "mydb", "application_name", "psql"),
		"ssl glued":  append([]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}, pgStartupMessage("user", "postgres", "database", "mydb")...),
		"gssenc+ssl": append([]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x30, 0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}, pgStartupMessage("database", "mydb")...),
		"proto 3.2":  append([]byte{0, 0, 0, 23, 0, 3, 0, 2}, "database\x00mydb\x00\x00"...),
	}

	for name, full := range buffers {
		t.Run(name, func(t *testing.T) {
			for i := range len(full) + 1 {
				prefix := full[:i]

				db, ok := parsePostgresStartup(largebuf.NewLargeBufferFrom(prefix))
				if ok {
					// only the explicitly captured name is acceptable, never a user fallback
					assert.Equal(t, "mydb", db, "prefix of %d bytes", i)
				}

				// same prefix split into tiny chunks exercises every cross-chunk read path
				cdb, cok := parsePostgresStartup(chunkedLargeBuffer(prefix, 3))
				assert.Equal(t, ok, cok, "chunked parse diverges at prefix %d", i)
				assert.Equal(t, db, cdb, "chunked parse diverges at prefix %d", i)
			}

			db, ok := parsePostgresStartup(largebuf.NewLargeBufferFrom(full))
			assert.True(t, ok)
			assert.Equal(t, "mydb", db)
		})
	}
}
