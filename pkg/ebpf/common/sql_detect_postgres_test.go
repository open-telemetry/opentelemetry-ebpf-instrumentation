// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
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

// TestPostgresHandleBindTruncatedDoesNotPanic reproduces the production crash
// where the BPF ring buffer captures only the portal-name portion of a Postgres
// BIND message (statement-name byte was lost to TCP segmentation). Without a
// bounds check, msg.data[portalLen:] in the BIND case panics with
// "slice bounds out of range [13:12]".
//
// Stack trace observed in production:
//
//	panic: runtime error: slice bounds out of range [13:12]
//	  go.opentelemetry.io/obi/pkg/ebpf/common.handlePostgres(...)
//	    sql_detect_postgres.go:330
//	  go.opentelemetry.io/obi/pkg/ebpf/common.dispatchPostgres(...)
//	    tcp_detect_transform.go:151
//	  go.opentelemetry.io/obi/pkg/ebpf/common.ReadTCPRequestIntoSpan(...)
//	    tcp_detect_transform.go:61
//
// Trigger: Rust application (sqlx / tokio-postgres) sending prepared-statement
// BIND messages large enough that the BIND header arrives in one BPF event but
// the body is captured truncated.
func TestPostgresHandleBindTruncatedDoesNotPanic(t *testing.T) {
	// Body = 12 bytes of portal-name with NO null terminator within the buffer.
	// unix.ByteSliceToString reads to the end → portal length = 12,
	// portalLen = len(portal)+1 = 13, but len(msg.data) = 12 → slice [13:12].
	body := []byte("abcdefghijkl")

	// Postgres BIND wire frame: type byte + 4-byte length (length includes
	// itself, excludes the type byte).
	bind := []byte{'B', 0, 0, 0, byte(4 + len(body))}
	bind = append(bind, body...)

	requestBuffer := largebuf.NewLargeBufferFrom(bind)
	// Minimal valid response buffer (just the header bytes — content is not
	// consulted on the panic path).
	responseBuffer := largebuf.NewLargeBufferFrom([]byte{'B', 0, 0, 0, 4})

	cfg := config.EBPFTracer{HeuristicSQLDetect: true}
	ctx := NewEBPFParseContext(&cfg, nil, nil)

	require.NotPanics(t, func() {
		_, _ = handlePostgres(ctx, &TCPRequestInfo{}, requestBuffer, responseBuffer)
	}, "handlePostgres must not panic on a Postgres BIND message truncated mid-portal")
}
