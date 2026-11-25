// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

func TestRedisSanitizedText(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "key only", args: []string{"GET", "user:1"}, want: "GET user:1"},
		{name: "multiple keys", args: []string{"DEL", "a", "b"}, want: "DEL a b"},
		{name: "no arguments", args: []string{"PING"}, want: "PING"},
		{name: "lowercase command", args: []string{"set", "user:1", "secret"}, want: "set user:1 ?"},
		{name: "value and options", args: []string{"SET", "user:1", "secret", "EX", "10"}, want: "SET user:1 ? ? ?"},
		{name: "value with spaces", args: []string{"SET", "user:1", "a b c"}, want: "SET user:1 ?"},
		{name: "list push", args: []string{"LPUSH", "queue", "a", "b"}, want: "LPUSH queue ? ?"},
		{name: "two kept arguments", args: []string{"SETEX", "user:1", "10", "secret"}, want: "SETEX user:1 10 ?"},
		{name: "hash fields", args: []string{"HSET", "user:1", "name", "Jane Doe", "age", "42"}, want: "HSET user:1 name ? age ?"},
		{name: "hash field without value", args: []string{"HMSET", "user:1", "name"}, want: "HMSET user:1 name"},
		{name: "keys and values", args: []string{"MSET", "a", "1", "b", "2"}, want: "MSET a ? b ?"},
		{name: "stream entry", args: []string{"XADD", "events", "*", "field", "secret"}, want: "XADD events * field ?"},
		{name: "stream entry with trimming", args: []string{"XADD", "events", "NOMKSTREAM", "MAXLEN", "~", "1000", "LIMIT", "10", "1-1", "a", "x", "b", "y"}, want: "XADD events NOMKSTREAM MAXLEN ~ 1000 LIMIT 10 1-1 a ? b ?"},
		{name: "stream entry with exact minid", args: []string{"XADD", "events", "MINID", "5-0", "*", "field", "secret"}, want: "XADD events MINID 5-0 * field ?"},
		{name: "sharded publish", args: []string{"SPUBLISH", "channel", "secret"}, want: "SPUBLISH channel ?"},
		{name: "eval keys", args: []string{"EVAL", "return 1", "1", "key", "secret"}, want: "EVAL return 1 1 key ?"},
		{name: "eval without numkeys", args: []string{"EVAL", "return 1"}, want: "EVAL return 1"},
		{name: "eval bad numkeys", args: []string{"EVALSHA", "abc", "x", "secret"}, want: "EVALSHA abc x ?"},
		{name: "eval numkeys too large", args: []string{"EVAL", "s", "5", "key"}, want: "EVAL s 5 key"},
		{name: "auth", args: []string{"AUTH", "user", "password"}, want: "AUTH ? ?"},
		{name: "config set", args: []string{"CONFIG", "SET", "requirepass", "secret"}, want: "CONFIG SET requirepass ?"},
		{name: "unknown command", args: []string{"JSON.SET", "doc", "$", `{"a":1}`}, want: "JSON.SET ? ? ?"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmds := parseRedisCommands(respArray(tt.args...))
			require.Len(t, cmds, 1)
			assert.Equal(t, tt.want, cmds[0].sanitizedText)
		})
	}
}

func TestRedisSanitizedTextStopsWithText(t *testing.T) {
	cmds := parseRedisCommands(respArray("SET", "user:1", "\x00\x01", "EX", "10"))
	require.Len(t, cmds, 1)
	assert.Equal(t, "SET user:1", cmds[0].text)
	assert.Equal(t, "SET user:1", cmds[0].sanitizedText)

	truncated := []byte("*3\r\n$4\r\nHSET\r\n$6\r\nuser:1\r\n$4\r\nna")
	cmds = parseRedisCommands(truncated)
	require.Len(t, cmds, 1)
	assert.Equal(t, "HSET user:1", cmds[0].sanitizedText)
}

func TestRedisSpanCarriesSanitizedText(t *testing.T) {
	span, _, _, matched := runMatchRedis(t, 1, respArray("SET", "user:1", "secret"), []byte("+OK\r\n"))
	require.True(t, matched)
	assert.Equal(t, "SET user:1 secret", span.Path)
	assert.Equal(t, "SET user:1 ?", span.DBQueryTextSanitized)
}

func TestGoRedisSpanCarriesSanitizedText(t *testing.T) {
	cmd := respArray("HSET", "user:1", "name", "secret")
	event := GoRedisClientInfo{BufLen: uint16(len(cmd))}
	copy(event.Buf[:], cmd)

	var raw bytes.Buffer
	require.NoError(t, binary.Write(&raw, binary.LittleEndian, event))

	span, ignore, err := ReadGoRedisRequestIntoSpan(NewEBPFParseContext(nil, nil, nil), &ringbuf.Record{RawSample: raw.Bytes()})
	require.NoError(t, err)
	require.False(t, ignore)
	assert.Equal(t, "HSET user:1 name secret", span.Path)
	assert.Equal(t, "HSET user:1 name ?", span.DBQueryTextSanitized)
}
