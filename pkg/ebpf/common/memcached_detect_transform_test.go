// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func TestIsMemcachedCommands(t *testing.T) {
	for _, tc := range []string{
		"get key\r\n",
		"gets key\r\n",
		"gat 60 key\r\n",
		"gats 60 key\r\n",
		"set key 0 300 5\r\nvalue\r\n",
		"delete key\r\n",
		"incr counter 1\r\n",
		"flush_all\r\n",
		"stats slabs\r\n",
		"version\r\n",
		"VALUE key 0 5\r\nvalue\r\nEND\r\n",
		"END\r\n",
		"STORED\r\n",
		"NOT_STORED\r\n",
		"EXISTS\r\n",
		"NOT_FOUND\r\n",
		"DELETED\r\n",
		"OK\r\n",
		"ERROR\r\n",
		"CLIENT_ERROR bad command line format\r\n",
		"SERVER_ERROR out of memory\r\n",
		"VERSION 1.6.22\r\n",
		"STAT pid 123\r\n",
		"TOUCHED\r\n",
		"42\r\n",
	} {
		assert.True(t, isMemcached(largebuf.NewLargeBufferFrom([]byte(tc))), tc)
		assert.True(t, isMemcachedOp([]byte(tc)), tc)
	}

	for _, tc := range []string{
		"",
		"GE",
		"GET / HTTP/1.1\r\n",
		"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n",
		string([]byte{0x80, 0x00, 0x00, 0x00}),
		"unknown key\r\n",
	} {
		assert.False(t, isMemcached(largebuf.NewLargeBufferFrom([]byte(tc))), tc)
		assert.False(t, isMemcachedOp([]byte(tc)), tc)
	}
}

func TestParseMemcachedRequest(t *testing.T) {
	tests := []struct {
		name  string
		input string
		op    string
		key   string
		ok    bool
	}{
		{name: "get", input: "get session\r\n", op: "GET", key: "session", ok: true},
		{name: "gets", input: "gets session\r\n", op: "GET", key: "session", ok: true},
		{name: "gat", input: "gat 60 session\r\n", op: "GAT", key: "session", ok: true},
		{name: "gats", input: "gats 60 session\r\n", op: "GAT", key: "session", ok: true},
		{name: "set", input: "set session 0 300 5\r\nvalue\r\n", op: "SET", key: "session", ok: true},
		{name: "delete", input: "delete session\r\n", op: "DELETE", key: "session", ok: true},
		{name: "touch", input: "touch session 60\r\n", op: "TOUCH", key: "session", ok: true},
		{name: "incr", input: "incr counter 1\r\n", op: "INCR", key: "counter", ok: true},
		{name: "multi key get", input: "get key1 key2 key3\r\n", op: "GET", key: "key1", ok: true},
		{name: "flush all", input: "flush_all 10\r\n", op: "FLUSH_ALL", key: "", ok: true},
		{name: "stats", input: "stats slabs\r\n", op: "STATS", key: "", ok: true},
		{name: "response", input: "VALUE session 0 5\r\nvalue\r\nEND\r\n", op: "", key: "", ok: true},
		{name: "numeric response", input: "42\r\n", op: "", key: "", ok: true},
		{name: "invalid", input: "unknown\r\n", op: "", key: "", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, ok := parseMemcachedRequests([]byte(tt.input))
			assert.Equal(t, tt.ok, ok)
			if !ok {
				return
			}

			if parsed.IsResponse {
				assert.Empty(t, tt.op)
				assert.Empty(t, tt.key)
				return
			}

			require.NotEmpty(t, parsed.Ops)
			assert.Equal(t, tt.op, parsed.Ops[0].Op)
			assert.Equal(t, tt.key, parsed.Ops[0].Key)
		})
	}
}

func TestParseMemcachedRequestsCoalescedNoreply(t *testing.T) {
	parsed, ok := parseMemcachedRequests([]byte("set session 0 300 5 noreply\r\nvalue\r\nget session\r\n"))
	require.True(t, ok)
	require.False(t, parsed.IsResponse)
	require.Len(t, parsed.Ops, 2)

	assert.Equal(t, memcachedRequestOp{Op: "SET", Key: "session", Noreply: true}, parsed.Ops[0])
	assert.Equal(t, memcachedRequestOp{Op: "GET", Key: "session", Noreply: false}, parsed.Ops[1])
}

func TestParseMemcachedRequestsDeleteNoreply(t *testing.T) {
	parsed, ok := parseMemcachedRequests([]byte("delete session noreply\r\n"))
	require.True(t, ok)
	require.False(t, parsed.IsResponse)
	require.Len(t, parsed.Ops, 1)

	assert.Equal(t, memcachedRequestOp{Op: "DELETE", Key: "session", Noreply: true}, parsed.Ops[0])
}

func TestParseMemcachedRequestsRejectIncompletePayload(t *testing.T) {
	_, ok := parseMemcachedRequests([]byte("set session 0 300 5 noreply\r\nval"))
	assert.False(t, ok)
}

func TestParseMemcachedRequestsRejectInvalidArity(t *testing.T) {
	for _, tc := range []string{
		"get\r\n",
		"gat session\r\n",
		"gat notanumber key\r\n",
		"delete\r\n",
		"delete session extra\r\n",
		"touch session\r\n",
		"touch session 60 extra\r\n",
		"incr counter\r\n",
		"incr counter 1 extra\r\n",
		"version extra\r\n",
		"flush_all 10 extra unexpected\r\n",
		"set key 0 notanumber 5\r\nvalue\r\n",
		"set key 0 300 notanumber\r\nvalue\r\n",
	} {
		_, ok := parseMemcachedRequests([]byte(tc))
		assert.False(t, ok, tc)
	}
}

func TestMemcachedCommandKeyField(t *testing.T) {
	tests := []struct {
		name string
		op   string
		want int
	}{
		{name: "get", op: "GET", want: 1},
		{name: "set", op: "SET", want: 1},
		{name: "gat", op: "GAT", want: 2},
		{name: "flush all", op: "FLUSH_ALL", want: -1},
		{name: "stats", op: "STATS", want: -1},
		{name: "version", op: "VERSION", want: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, memcachedCommandKeyField(tt.op))
		})
	}
}

func TestMemcachedValidRequestFields(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		op      string
		noreply bool
		want    bool
	}{
		{name: "get requires key", line: "get session", op: "GET", want: true},
		{name: "get missing key", line: "get", op: "GET", want: false},
		{name: "gat with ttl", line: "gat 60 session", op: "GAT", want: true},
		{name: "gat ttl must be int", line: "gat nope session", op: "GAT", want: false},
		{name: "set storage fields", line: "set session 0 300 5", op: "SET", want: true},
		{name: "set noreply extra token", line: "set session 0 300 5 noreply", op: "SET", noreply: true, want: true},
		{name: "set wrong field count", line: "set session 0 300", op: "SET", want: false},
		{name: "set bytes must be int", line: "set session 0 300 nope", op: "SET", want: false},
		{name: "delete noreply", line: "delete session noreply", op: "DELETE", noreply: true, want: true},
		{name: "delete extra arg", line: "delete session extra", op: "DELETE", want: false},
		{name: "touch with ttl", line: "touch session 60", op: "TOUCH", want: true},
		{name: "touch ttl must be int", line: "touch session nope", op: "TOUCH", want: false},
		{name: "flush all delay", line: "flush_all 10", op: "FLUSH_ALL", want: true},
		{name: "flush all noreply", line: "flush_all 10 noreply", op: "FLUSH_ALL", noreply: true, want: true},
		{name: "flush all too many args", line: "flush_all 10 noreply extra", op: "FLUSH_ALL", noreply: true, want: false},
		{name: "version no args", line: "version", op: "VERSION", want: true},
		{name: "version extra args", line: "version extra", op: "VERSION", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, memcachedValidRequestFields(bytes.Fields([]byte(tt.line)), tt.op, tt.noreply))
		})
	}
}

func TestMemcachedMatchesFieldCount(t *testing.T) {
	tests := []struct {
		name       string
		fieldCount int
		noreply    bool
		base       int
		want       bool
	}{
		{name: "exact base", fieldCount: 3, base: 3, want: true},
		{name: "too many without noreply", fieldCount: 4, base: 3, want: false},
		{name: "noreply adds one", fieldCount: 4, noreply: true, base: 3, want: true},
		{name: "noreply still exact", fieldCount: 3, noreply: true, base: 3, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, memcachedMatchesFieldCount(tt.fieldCount, tt.noreply, tt.base))
		})
	}
}

func TestMemcachedSignedIntField(t *testing.T) {
	tests := []struct {
		name  string
		field string
		want  bool
	}{
		{name: "positive", field: "60", want: true},
		{name: "zero", field: "0", want: true},
		{name: "negative", field: "-1", want: true},
		{name: "empty", field: "", want: false},
		{name: "minus only", field: "-", want: false},
		{name: "alpha", field: "abc", want: false},
		{name: "mixed", field: "12x", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, memcachedSignedIntField([]byte(tt.field)))
		})
	}
}

func TestMemcachedCommandBytesField(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		op     string
		want   int
		wantOK bool
	}{
		{name: "set bytes", line: "set session 0 300 5", op: "SET", want: 5, wantOK: true},
		{name: "set bytes with noreply", line: "set session 0 300 5 noreply", op: "SET", want: 5, wantOK: true},
		{name: "cas bytes", line: "cas session 0 300 5 42", op: "CAS", want: 5, wantOK: true},
		{name: "cas requires cas unique", line: "cas session 0 300 5", op: "CAS", wantOK: false},
		{name: "missing bytes field", line: "set session 0 300", op: "SET", wantOK: false},
		{name: "bytes must be int", line: "set session 0 300 nope", op: "SET", wantOK: false},
		{name: "bytes cannot be negative", line: "set session 0 300 -1", op: "SET", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := memcachedCommandBytesField(bytes.Fields([]byte(tt.line)), tt.op)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMemcachedStoragePayloadSize(t *testing.T) {
	tests := []struct {
		name   string
		buf    string
		line   string
		op     string
		want   int
		wantOK bool
	}{
		{name: "set payload", buf: "value\r\n", line: "set session 0 300 5", op: "SET", want: 7, wantOK: true},
		{name: "cas payload", buf: "value\r\n", line: "cas session 0 300 5 42", op: "CAS", want: 7, wantOK: true},
		{name: "empty payload", buf: "\r\n", line: "set session 0 300 0", op: "SET", want: 2, wantOK: true},
		{name: "truncated payload", buf: "val", line: "set session 0 300 5", op: "SET", wantOK: false},
		{name: "missing delimiter", buf: "valueXX", line: "set session 0 300 5", op: "SET", wantOK: false},
		{name: "invalid bytes field", buf: "value\r\n", line: "set session 0 300 nope", op: "SET", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := memcachedStoragePayloadSize([]byte(tt.buf), bytes.Fields([]byte(tt.line)), tt.op)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseMemcachedExplicitNoreply(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []memcachedRequestOp
		ok       bool
	}{
		{
			name:     "delete noreply",
			input:    "delete session noreply\r\n",
			expected: []memcachedRequestOp{{Op: "DELETE", Key: "session", Noreply: true}},
			ok:       true,
		},
		{
			name:  "multiple explicit noreply ops",
			input: "delete session noreply\r\ntouch session 60 noreply\r\n",
			expected: []memcachedRequestOp{
				{Op: "DELETE", Key: "session", Noreply: true},
				{Op: "TOUCH", Key: "session", Noreply: true},
			},
			ok: true,
		},
		{
			name:  "mixed reply backed request",
			input: "set session 0 300 5 noreply\r\nvalue\r\nget session\r\n",
			ok:    false,
		},
		{
			name:  "request only version rejected",
			input: "version\r\n",
			ok:    false,
		},
		{
			name:  "request only stats rejected",
			input: "stats slabs\r\n",
			ok:    false,
		},
		{
			name:  "incomplete payload rejected",
			input: "set session 0 300 5 noreply\r\nval",
			ok:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops, ok := parseMemcachedExplicitNoreply([]byte(tt.input))
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.expected, ops)
		})
	}
}

func TestMemcachedReplyBackedOps(t *testing.T) {
	leading, replyOp, ok := memcachedReplyBackedOps([]memcachedRequestOp{
		{Op: "SET", Key: "session", Noreply: true},
		{Op: "GET", Key: "session"},
	})
	require.True(t, ok)
	assert.Equal(t, []memcachedRequestOp{{Op: "SET", Key: "session", Noreply: true}}, leading)
	assert.Equal(t, memcachedRequestOp{Op: "GET", Key: "session"}, replyOp)

	_, _, ok = memcachedReplyBackedOps([]memcachedRequestOp{{Op: "SET", Key: "session", Noreply: true}})
	assert.False(t, ok)
}

func TestMemcachedStatus(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    int
		expectedErr request.DBError
	}{
		{name: "stored", input: "STORED\r\n", expected: 0},
		{name: "touched", input: "TOUCHED\r\n", expected: 0},
		{name: "not found", input: "NOT_FOUND\r\n", expected: 0},
		{name: "value", input: "VALUE session 0 5\r\nvalue\r\nEND\r\n", expected: 0},
		{name: "numeric", input: "42\r\n", expected: 0},
		{name: "error", input: "ERROR\r\n", expected: 1, expectedErr: request.DBError{ErrorCode: "ERROR", Description: "ERROR"}},
		{name: "client error", input: "CLIENT_ERROR bad command line format\r\n", expected: 1, expectedErr: request.DBError{ErrorCode: "CLIENT_ERROR", Description: "CLIENT_ERROR bad command line format"}},
		{name: "server error", input: "SERVER_ERROR out of memory\r\n", expected: 1, expectedErr: request.DBError{ErrorCode: "SERVER_ERROR", Description: "SERVER_ERROR out of memory"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err, status := memcachedStatus(largebuf.NewLargeBufferFrom([]byte(tt.input)))
			assert.Equal(t, tt.expected, status)
			assert.Equal(t, tt.expectedErr, err)
		})
	}
}

func TestProcessPossibleMemcachedEventReversedBuffers(t *testing.T) {
	event := makeTCPReq("VALUE session-key 0 5\r\nvalue\r\nEND\r\n", 11211)
	requestBuffer := largebuf.NewLargeBufferFrom([]byte("VALUE session-key 0 5\r\nvalue\r\nEND\r\n"))
	responseBuffer := largebuf.NewLargeBufferFrom([]byte("gat 60 session-key\r\n"))

	span, err := ProcessPossibleMemcachedEvent(NewEBPFParseContext(nil, nil, nil), &event, requestBuffer, responseBuffer)
	require.NoError(t, err)
	assert.Equal(t, request.EventTypeMemcachedServer, span.Type)
	assert.Equal(t, "GAT", span.Method)
	assert.Equal(t, "session-key", span.Path)
	assert.Equal(t, uint16(8080), event.ConnInfo.S_port)
	assert.Equal(t, uint16(11211), event.ConnInfo.D_port)
}

func TestProcessPossibleMemcachedEventReversedBuffersClientDirection(t *testing.T) {
	event := makeTCPReq("VALUE session-key 0 5\r\nvalue\r\nEND\r\n", 11211)
	event.Direction = directionRecv
	requestBuffer := largebuf.NewLargeBufferFrom([]byte("VALUE session-key 0 5\r\nvalue\r\nEND\r\n"))
	responseBuffer := largebuf.NewLargeBufferFrom([]byte("get session-key\r\n"))

	span, err := ProcessPossibleMemcachedEvent(NewEBPFParseContext(nil, nil, nil), &event, requestBuffer, responseBuffer)
	require.NoError(t, err)
	assert.Equal(t, request.EventTypeMemcachedClient, span.Type)
	assert.Equal(t, "GET", span.Method)
	assert.Equal(t, "session-key", span.Path)
}
