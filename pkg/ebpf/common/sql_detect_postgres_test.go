// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			it := &postgresMessageIterator{buf: tt.buf}
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

	allocs := testing.AllocsPerRun(1000, func() {
		it := &postgresMessageIterator{buf: buf}

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
