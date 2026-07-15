// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

type crlfTest struct {
	testStr string
	result  bool
}

func TestCRLFMatching(t *testing.T) {
	for _, ts := range []crlfTest{
		{testStr: "Not a sql or any known protocol", result: false},
		{testStr: "Not a sql or any known protocol\r\n", result: true},
		{testStr: "123\r\n", result: false},
		{testStr: "\r\n", result: true},
		{testStr: "\n", result: false},
		{testStr: "\r", result: false},
		{testStr: "", result: false},
	} {
		res := crlfTerminatedMatch([]uint8(ts.testStr), func(c uint8) bool {
			return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '.' || c == ' ' || c == '-' || c == '_'
		})
		assert.Equal(t, res, ts.result)
	}
}

func TestIsRedis(t *testing.T) {
	buf := []byte{42, 51, 13, 10, 36, 52, 13, 10, 72, 71, 69, 84, 13, 10, 36, 51, 54, 13, 10, 56, 97, 100, 48, 101, 56, 99, 97, 45, 101, 97, 49, 57, 45, 52, 50, 97, 57, 45, 98, 51, 55, 48, 45, 98, 99, 97, 102, 102, 50, 55, 54, 55, 98, 56, 54, 13, 10, 36, 52, 13, 10, 99, 97, 114, 116, 13, 10, 103, 58, 32, 34, 51, 49, 117, 50, 107, 97, 100, 98, 108, 113, 53, 106, 34, 13, 10, 99, 111, 110, 116, 101, 110, 116, 45, 108, 101, 110, 103, 116, 104, 58, 32, 49, 57, 57, 13, 10, 118, 97, 114, 121, 58, 32, 65, 99, 99, 101, 112, 116, 45, 69, 110, 99, 111, 100, 105, 110, 103, 13, 10, 100, 97, 116, 101, 58, 32, 87, 101, 100, 44, 32, 48, 51, 32, 74, 117, 108, 32, 50, 48, 50, 52, 32, 49, 55, 58, 52, 54, 58, 49, 55, 32, 71, 77, 84, 13, 10, 120, 45, 101, 110, 118, 111, 121, 45, 117, 112, 115, 116, 114, 101, 97, 109, 45, 115, 101, 114, 118, 105, 99, 101, 45, 116, 105, 109, 101, 58, 32, 51, 13, 10, 115, 101, 114, 118, 101, 114, 58, 32, 101, 110, 118, 111, 121, 13, 10, 13, 10, 91, 34, 90, 65, 82, 34, 44, 34, 73, 83, 75, 34, 44, 34, 73, 76, 83, 34, 44, 34, 82, 79, 78, 34, 44, 34, 71, 66, 80, 34, 44, 34, 66, 82, 76, 34, 44, 34}
	rbuf := []byte{36, 45, 49, 13, 10, 1, 0, 15, 0, 3, 89, 130, 0, 32, 99, 111, 110, 115, 117, 109, 101, 114, 45, 102, 114, 97, 117, 100, 100, 101, 116, 101, 99, 116, 105, 111, 110, 115, 101, 114, 118, 105, 99, 101, 45, 49, 0, 0, 0, 1, 244, 0, 0, 0, 1, 3, 32, 0, 0, 0, 17, 170, 173, 222, 0, 0, 141, 2, 1, 1, 1, 0, 101, 112, 116, 45, 114, 97, 110, 103, 101, 115, 58, 32, 98, 121, 116, 101, 115, 13, 10, 108, 97, 115, 116, 45, 109, 111, 100, 105, 102, 105, 101, 100, 58, 32, 70, 114, 105, 44, 32, 48, 55, 32, 74, 117, 110, 32, 50, 48, 50, 52, 32, 48, 48, 58, 53, 55}
	assert.True(t, isRedis(largebuf.NewLargeBufferFrom(buf)))
	assert.True(t, isRedis(largebuf.NewLargeBufferFrom(rbuf)))
}

func TestGetRedisDb(t *testing.T) {
	cache, _ := simplelru.NewLRU[BpfConnectionInfoT, int](1000, nil)
	connInfo := BpfConnectionInfoT{
		S_addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1},
		D_addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8},
		S_port: 6379,
		D_port: 6379,
	}
	var db int
	var found bool

	_, found = getRedisDB(connInfo, "GET", "GET obi", cache)
	assert.False(t, found, "Expected Redis DB to not be found for non tracked connection")

	_, found = getRedisDB(connInfo, "SELECT", "SELECT 0", cache)
	assert.False(t, found, "Expected Redis DB to be when selecting a db")
	db, found = getRedisDB(connInfo, "GET", "GET obi", cache)
	assert.True(t, found, "Expected Redis DB to be 0 after selecting db 0")
	assert.Equal(t, 0, db, "Expected Redis DB to be 0 after selecting db 0")

	db, found = getRedisDB(connInfo, "SELECT", "SELECT 1", cache)
	assert.True(t, found, "Expected Redis DB to be 0 after selecting a db")
	assert.Equal(t, 0, db, "Expected Redis DB to be 0 after selecting a db")

	db, found = getRedisDB(connInfo, "GET", "GET obi", cache)
	assert.True(t, found, "Expected Redis DB to be 1 after selecting a db 1")
	assert.Equal(t, 1, db, "Expected Redis DB to be 1 after selecting a db 1")

	connInfo2 := BpfConnectionInfoT{
		S_addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1},
		D_addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8},
		S_port: 6380,
		D_port: 6380,
	}
	_, found = getRedisDB(connInfo2, "GET", "GET obi", cache)
	assert.False(t, found, "Expected Redis DB to not be found for different connection")

	db, found = getRedisDB(connInfo, "QUIT", "QUIT", cache)
	assert.True(t, found, "Expected Redis DB to be found when quitting the connection")
	assert.Equal(t, 1, db, "Expected Redis DB to be 1 when quitting the connection")
	// After quitting the connection, the db should be removed from the cache
	_, found = getRedisDB(connInfo, "GET", "GET OBI", cache)
	assert.False(t, found, "Expected Redis DB to not be found after quitting the connection")
}

var benchmarkRedisCmds []redisCommand

func BenchmarkParseRedisCommands(b *testing.B) {
	tests := []struct {
		name     string
		input    []byte
		wantCmds int
	}{
		{
			name:     "get",
			input:    redisBenchmarkCommand("GET", "session-key"),
			wantCmds: 1,
		},
		{
			name:     "set",
			input:    redisBenchmarkCommand("SET", "session-key", "session-value"),
			wantCmds: 1,
		},
		{
			name:     "mget_many_keys",
			input:    redisBenchmarkMGet(32),
			wantCmds: 1,
		},
		{
			name:     "pipeline_get",
			input:    redisBenchmarkPipeline(16, "GET", "session-key"),
			wantCmds: 16,
		},
		{
			name: "client_setinfo",
			input: []byte(fmt.Sprintf(
				"*4\r\n$6\r\nclient\r\n$7\r\nsetinfo\r\n$8\r\nLIB-NAME\r\n$19\r\n%s(,go1.22.2)\r\n*4\r\n$6\r\nclient\r\n$7\r\nsetinfo\r\n$7\r\nLIB-VER\r\n$5\r\n9.5.1\r\n",
				"go-redis",
			)),
			wantCmds: 2,
		},
		{
			name:     "short_invalid",
			input:    []byte("2"),
			wantCmds: 0,
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(tt.input)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				cmds := parseRedisCommands(tt.input)
				if len(cmds) != tt.wantCmds {
					b.Fatalf("parseRedisCommands len = %d, want %d", len(cmds), tt.wantCmds)
				}
				benchmarkRedisCmds = cmds
			}
		})
	}
}

func redisBenchmarkCommand(args ...string) []byte {
	buf := bytes.Buffer{}
	fmt.Fprintf(&buf, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&buf, "$%d\r\n%s\r\n", len(arg), arg)
	}

	return buf.Bytes()
}

func redisBenchmarkMGet(keys int) []byte {
	args := make([]string, 0, keys+1)
	args = append(args, "MGET")
	for i := 0; i < keys; i++ {
		args = append(args, fmt.Sprintf("session-key:%02d", i))
	}

	return redisBenchmarkCommand(args...)
}

func redisBenchmarkPipeline(commands int, args ...string) []byte {
	buf := bytes.Buffer{}
	for i := 0; i < commands; i++ {
		buf.Write(redisBenchmarkCommand(args...))
	}

	return buf.Bytes()
}

func TestRedisParsing(t *testing.T) {
	// declared $5 but only 3 bytes captured: the truncated token is dropped
	proper := []byte("*2\r\n$3\r\nGET\r\n$5\r\nobi")
	cmds := parseRedisCommands(proper)
	require.Len(t, cmds, 1)
	assert.Equal(t, "GET", cmds[0].op)
	assert.Equal(t, "GET", cmds[0].text)

	complete := []byte("*2\r\n$3\r\nGET\r\n$3\r\nobi\r\n")
	cmds = parseRedisCommands(complete)
	require.Len(t, cmds, 1)
	assert.Equal(t, "GET", cmds[0].op)
	assert.Equal(t, "GET obi", cmds[0].text)

	weird := []byte("*2\r\nGET\r\nobi")
	assert.Empty(t, parseRedisCommands(weird))

	unknown := []byte("2\r\nGET\r\nobi")
	assert.Empty(t, parseRedisCommands(unknown))

	assert.Empty(t, parseRedisCommands([]byte("2")))

	multi := []byte(fmt.Sprintf("*4\r\n$6\r\nclient\r\n$7\r\nsetinfo\r\n$8\r\nLIB-NAME\r\n$19\r\n%s(,go1.22.2)\r\n*4\r\n$6\r\nclient\r\n$7\r\nsetinfo\r\n$7\r\nLIB-VER\r\n$5\r\n9.5.1\r\n", "go-redis"))
	cmds = parseRedisCommands(multi)
	require.Len(t, cmds, 2)
	assert.Equal(t, "client", cmds[0].op)
	assert.Equal(t, "client setinfo LIB-NAME go-redis(,go1.22.2)", cmds[0].text)
	assert.Equal(t, "client", cmds[1].op)
	assert.Equal(t, "client setinfo LIB-VER 9.5.1", cmds[1].text)

	hmset := []byte{42, 52, 13, 10, 36, 53, 13, 10, 72, 77, 83, 69, 84, 13, 10, 36, 51, 54, 13, 10, 48, 99, 57, 102, 97, 56, 97, 97, 45, 50, 56, 49, 102, 45, 49, 49, 101, 102, 45, 57, 55, 98, 57, 45, 98, 101, 57, 54, 48, 48, 99, 97, 48, 102, 50, 55, 13, 10, 36, 52, 13, 10, 99, 97, 114, 116, 13, 10, 36, 53, 52, 13, 10, 10, 36, 48, 99, 57, 102, 97, 56, 97, 97, 45, 50, 56, 49, 102, 45, 49, 49, 101, 102, 45, 57, 55, 98, 57, 45, 98, 101, 57, 54, 48, 48, 99, 97, 48, 102, 50, 55, 18, 14, 10, 10, 79, 76, 74, 67, 69, 83, 80, 67, 55, 90, 16, 5, 13, 10, 0, 10, 72, 81, 84, 71, 87, 71, 80, 78, 72, 52, 16, 1, 13, 10, 0, 10, 49, 89, 77, 87, 87, 78, 49, 78, 52, 79, 16, 5, 13, 10, 0, 10, 10, 57, 83, 73, 81, 84, 56, 84, 79, 74, 79, 16, 5, 13, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	cmds = parseRedisCommands(hmset)
	require.Len(t, cmds, 1)
	assert.Equal(t, "HMSET", cmds[0].op)
	assert.Equal(t, "HMSET 0c9fa8aa-281f-11ef-97b9-be9600ca0f27 cart", cmds[0].text)
}

// respArray encodes args as a single RESP command array (the client wire format)
func respArray(args ...string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	return []byte(b.String())
}

func respPipeline(cmds ...[]byte) []byte {
	var out []byte
	for _, c := range cmds {
		out = append(out, c...)
	}
	return out
}

func makeRedisTCPEvent(direction uint8) *TCPRequestInfo {
	i := &TCPRequestInfo{
		StartMonotimeNs: 2000 * 1000000,
		EndMonotimeNs:   2000 * 2 * 1000000,
		Direction:       direction,
	}
	i.ConnInfo.S_addr[15] = 1
	i.ConnInfo.S_port = 51234
	i.ConnInfo.D_addr[15] = 2
	i.ConnInfo.D_port = 6379
	return i
}

func runMatchRedis(t *testing.T, direction uint8, reqBuf, respBuf []byte) (request.Span, []request.Span, bool, bool) {
	t.Helper()
	ctx := NewEBPFParseContext(nil, nil, nil)
	var extra []request.Span
	ctx.emitSpans = func(spans []request.Span) { extra = append(extra, spans...) }

	event := makeRedisTCPEvent(direction)
	span, ignore, matched, err := matchRedis(ctx, event,
		largebuf.NewLargeBufferFrom(reqBuf), largebuf.NewLargeBufferFrom(respBuf))
	require.NoError(t, err)
	return span, extra, ignore, matched
}

func TestRedisMatchSimpleCommands(t *testing.T) {
	t.Run("get with simple string reply", func(t *testing.T) {
		span, extra, ignore, matched := runMatchRedis(t, directionSend,
			respArray("GET", "session-key"), []byte("$5\r\nvalue\r\n"))
		assert.True(t, matched)
		assert.False(t, ignore)
		assert.Empty(t, extra)
		assert.Equal(t, request.EventTypeRedisClient, span.Type)
		assert.Equal(t, "GET", span.Method)
		assert.Equal(t, "GET session-key", span.Path)
		assert.Equal(t, 0, span.Status)
	})

	t.Run("lowercase ioredis wire format", func(t *testing.T) {
		span, _, _, matched := runMatchRedis(t, directionSend,
			respArray("get", "blk5:business"), []byte("$2\r\nv1\r\n"))
		assert.True(t, matched)
		assert.Equal(t, "get", span.Method)
	})

	t.Run("blocking bzpopmin with null array timeout reply", func(t *testing.T) {
		span, _, ignore, matched := runMatchRedis(t, directionSend,
			respArray("bzpopmin", "blk5:queue", "5"), []byte("*-1\r\n"))
		assert.True(t, matched)
		assert.False(t, ignore)
		assert.Equal(t, request.EventTypeRedisClient, span.Type)
		assert.Equal(t, "bzpopmin", span.Method)
	})

	t.Run("blocking bzpopmin with array reply", func(t *testing.T) {
		reply := []byte("*3\r\n$10\r\nblk5:queue\r\n$4\r\njob1\r\n$13\r\n1720000000000\r\n")
		span, _, _, matched := runMatchRedis(t, directionSend,
			respArray("bzpopmin", "blk5:queue", "5"), reply)
		assert.True(t, matched)
		assert.Equal(t, "bzpopmin", span.Method)
	})

	t.Run("evalsha bullmq style", func(t *testing.T) {
		sha := strings.Repeat("6c4c6de2", 5)
		span, _, _, matched := runMatchRedis(t, directionSend,
			respArray("evalsha", sha, "1", "blk5:key"), []byte(":1\r\n"))
		assert.True(t, matched)
		assert.Equal(t, "evalsha", span.Method)
		assert.Contains(t, span.Path, sha)
	})

	t.Run("unknown command word with error reply", func(t *testing.T) {
		span, _, _, matched := runMatchRedis(t, directionSend,
			respArray("INVALID_COMMAND"),
			[]byte("-ERR unknown command 'INVALID_COMMAND', with args beginning with: \r\n"))
		assert.True(t, matched)
		assert.Equal(t, request.EventTypeRedisClient, span.Type)
		assert.Equal(t, "INVALID_COMMAND", span.Method)
		assert.Equal(t, 1, span.Status)
		assert.Equal(t, "ERR", span.DBError.ErrorCode)
		assert.Equal(t, "ERR unknown command 'INVALID_COMMAND', with args beginning with: ", span.DBError.Description)
	})

	t.Run("noscript error reply sets status and db error", func(t *testing.T) {
		span, _, _, matched := runMatchRedis(t, directionSend,
			respArray("evalsha", "0000000000000000000000000000000000000000", "1", "blk5:key"),
			[]byte("-NOSCRIPT No matching script. Please use EVAL.\r\n"))
		assert.True(t, matched)
		assert.Equal(t, "evalsha", span.Method)
		assert.Equal(t, 1, span.Status)
		assert.Equal(t, "NOSCRIPT", span.DBError.ErrorCode)
	})
}

// mid-flight attach pairs a reply buffer with a command buffer: the command must
// be recovered from the response side and never named after reply payload tokens
func TestRedisMatchReversedEvent(t *testing.T) {
	t.Run("simple string reply as request", func(t *testing.T) {
		span, _, ignore, matched := runMatchRedis(t, directionRecv,
			[]byte("+PONG\r\n"), respArray("ping"))
		assert.True(t, matched)
		assert.False(t, ignore)
		assert.Equal(t, request.EventTypeRedisClient, span.Type)
		assert.Equal(t, "ping", span.Method)
	})

	t.Run("null array reply as request", func(t *testing.T) {
		// bzpopmin timeout on a pre-agent connection: *-1 arrives receive-first
		span, _, ignore, matched := runMatchRedis(t, directionRecv,
			[]byte("*-1\r\n"), respArray("evalsha", strings.Repeat("ab", 20), "1", "blk5:key"))
		assert.True(t, matched, "reversed event with null array request must still match")
		assert.False(t, ignore)
		assert.Equal(t, request.EventTypeRedisClient, span.Type)
		assert.Equal(t, "evalsha", span.Method)
	})

	t.Run("array reply as request must not become op", func(t *testing.T) {
		reply := []byte("*3\r\n$10\r\nblk5:queue\r\n$4\r\njob1\r\n$13\r\n1720000000000\r\n")
		span, _, ignore, matched := runMatchRedis(t, directionRecv,
			reply, respArray("get", "blk5:business"))
		assert.True(t, matched)
		assert.False(t, ignore)
		assert.NotEqual(t, "blk5:queue", span.Method,
			"span named after reply payload token is the reversal artifact")
		assert.Equal(t, request.EventTypeRedisClient, span.Type)
		assert.Equal(t, "get", span.Method)
	})

	t.Run("error reply as request", func(t *testing.T) {
		span, _, _, matched := runMatchRedis(t, directionRecv,
			[]byte("-NOSCRIPT No matching script. Please use EVAL.\r\n"),
			respArray("get", "blk5:business"))
		assert.True(t, matched)
		assert.Equal(t, "get", span.Method)
		assert.Equal(t, request.EventTypeRedisClient, span.Type)
	})

	t.Run("both sides replies is ignored", func(t *testing.T) {
		_, _, ignore, matched := runMatchRedis(t, directionRecv,
			[]byte("+OK\r\n"), []byte("+PONG\r\n"))
		assert.True(t, matched)
		assert.True(t, ignore)
	})
}

// N pipelined commands in one write must produce N spans with positional statuses
func TestRedisMatchPipeline(t *testing.T) {
	collect := func(first request.Span, extra []request.Span) []request.Span {
		return append([]request.Span{first}, extra...)
	}

	t.Run("three commands three replies", func(t *testing.T) {
		req := respPipeline(
			respArray("SET", "k1", "v1"),
			respArray("GET", "k2"),
			respArray("HGETALL", "users_sessions"),
		)
		resp := []byte("+OK\r\n$2\r\nv2\r\n*2\r\n$1\r\nf\r\n$1\r\nv\r\n")

		first, extra, ignore, matched := runMatchRedis(t, directionSend, req, resp)
		require.True(t, matched)
		require.False(t, ignore)

		spans := collect(first, extra)
		require.Len(t, spans, 3)
		assert.Equal(t, "SET", spans[0].Method)
		assert.Equal(t, "SET k1 v1", spans[0].Path)
		assert.Equal(t, "GET", spans[1].Method)
		assert.Equal(t, "GET k2", spans[1].Path)
		assert.Equal(t, "HGETALL", spans[2].Method)
		for _, s := range spans {
			assert.Equal(t, request.EventTypeRedisClient, s.Type)
			assert.Equal(t, 0, s.Status)
		}
	})

	t.Run("error reply in the middle is attributed to its command", func(t *testing.T) {
		req := respPipeline(
			respArray("SET", "k1", "v1"),
			respArray("LPUSH", "k1", "x"),
			respArray("GET", "k1"),
		)
		resp := []byte("+OK\r\n-WRONGTYPE Operation against a key holding the wrong kind of value\r\n$2\r\nv1\r\n")

		first, extra, _, matched := runMatchRedis(t, directionSend, req, resp)
		require.True(t, matched)

		spans := collect(first, extra)
		require.Len(t, spans, 3)
		assert.Equal(t, 0, spans[0].Status)
		assert.Equal(t, 1, spans[1].Status)
		assert.Equal(t, "WRONGTYPE", spans[1].DBError.ErrorCode)
		assert.Equal(t, 0, spans[2].Status)
	})

	t.Run("client setinfo pair from go-redis", func(t *testing.T) {
		req := respPipeline(
			respArray("client", "setinfo", "LIB-NAME", "go-redis(,go1.22.2)"),
			respArray("client", "setinfo", "LIB-VER", "9.5.1"),
		)
		resp := []byte("+OK\r\n+OK\r\n")

		first, extra, _, matched := runMatchRedis(t, directionSend, req, resp)
		require.True(t, matched)

		spans := collect(first, extra)
		require.Len(t, spans, 2)
		assert.Equal(t, "client", spans[0].Method)
		assert.Equal(t, "client", spans[1].Method)
	})

	t.Run("truncated trailing command does not corrupt earlier spans", func(t *testing.T) {
		full := respPipeline(
			respArray("GET", "k1"),
			respArray("SET", "some-long-key-name", "some-long-value"),
		)
		// cut inside the second command's bulk string, as the capture buffer does
		req := full[:len(respArray("GET", "k1"))+10]
		resp := []byte("$2\r\nv1\r\n")

		first, extra, _, matched := runMatchRedis(t, directionSend, req, resp)
		require.True(t, matched)

		spans := collect(first, extra)
		assert.Equal(t, "GET", spans[0].Method)
		assert.Equal(t, "GET k1", spans[0].Path)
		for _, s := range spans {
			assert.NotContains(t, s.Path, ";")
		}
	})

	t.Run("more commands than captured replies", func(t *testing.T) {
		req := respPipeline(
			respArray("GET", "k1"),
			respArray("GET", "k2"),
			respArray("GET", "k3"),
		)
		resp := []byte("$2\r\nv1\r\n")

		first, extra, _, matched := runMatchRedis(t, directionSend, req, resp)
		require.True(t, matched)

		spans := collect(first, extra)
		require.Len(t, spans, 3)
		for i, s := range spans {
			assert.Equal(t, "GET", s.Method, "span %d", i)
			assert.Equal(t, 0, s.Status, "span %d has no observed error", i)
		}
	})
}

// capture can cut the stream at any byte: every prefix must parse without
// panicking and never yield a command with an empty op
func TestRedisParsingTruncationSweep(t *testing.T) {
	full := respPipeline(
		respArray("SET", "key", strings.Repeat("v", 300)),
		respArray("bzpopmin", "blk5:queue", "5"),
		respArray("evalsha", strings.Repeat("ab", 20), "1", "blk5:key"),
	)
	for i := 0; i <= len(full); i++ {
		for _, cmd := range parseRedisCommands(full[:i]) {
			assert.NotEmpty(t, cmd.op, "prefix len %d", i)
		}
	}

	replies := []byte("+OK\r\n-ERR boom\r\n$5\r\nhello\r\n*2\r\n$1\r\na\r\n:1\r\n%1\r\n+k\r\n_\r\n>2\r\n+p\r\n+q\r\n,3.14\r\n#t\r\n(42\r\n=5\r\ntxt:x\r\n!8\r\nERR boom\r\n|1\r\n+k\r\n,90\r\n$-1\r\n*-1\r\n")
	for i := 0; i <= len(replies); i++ {
		parseRedisReplies(replies[:i], 32)
	}
}

func FuzzParseRedisCommands(f *testing.F) {
	f.Add([]byte("*2\r\n$3\r\nGET\r\n$3\r\nobi\r\n"))
	f.Add([]byte("*-1\r\n"))
	f.Add([]byte("*3\r\n$10\r\nblk5:queue\r\n$4\r\njob1\r\n$13\r\n1720000000000\r\n"))
	f.Add([]byte("-NOSCRIPT No matching script. Please use EVAL.\r\n"))
	f.Add([]byte("%2\r\n+a\r\n:1\r\n+b\r\n:2\r\n"))
	f.Add([]byte("*1000000000\r\n$5\r\n"))
	f.Add([]byte("$1073741823\r\nx\r\n"))
	f.Add([]byte(">2\r\n+p\r\n+q\r\n*1\r\n$7\r\nZUNION\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, cmd := range parseRedisCommands(data) {
			if cmd.op == "" {
				t.Fatalf("command with empty op from %q", data)
			}
		}
		parseRedisReplies(data, 32)
	})
}

func FuzzMatchRedis(f *testing.F) {
	f.Add([]byte("*2\r\n$3\r\nGET\r\n$3\r\nobi\r\n"), []byte("+OK\r\n"))
	f.Add([]byte("*-1\r\n"), []byte("*1\r\n$4\r\nping\r\n"))
	f.Add([]byte("-NOSCRIPT nope\r\n"), []byte("*2\r\n$3\r\nget\r\n$1\r\nk\r\n"))
	f.Fuzz(func(_ *testing.T, req, resp []byte) {
		ctx := NewEBPFParseContext(nil, nil, nil)
		event := makeRedisTCPEvent(directionSend)
		_, _, _, _ = matchRedis(ctx, event, largebuf.NewLargeBufferFrom(req), largebuf.NewLargeBufferFrom(resp))
	})
}

// RESP3 servers (go-redis v9, redis-py protocol=3) reply with map/set/push/
// boolean/double/null/big-number/verbatim/bulk-error/attribute frames; the
// detector and the reply splitter must accept all of them
func TestRedisRESP3(t *testing.T) {
	t.Run("resp3 reply frames pass detection", func(t *testing.T) {
		for _, reply := range []string{
			"%2\r\n$4\r\nrole\r\n$6\r\nmaster\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n",
			"~2\r\n$1\r\na\r\n$1\r\nb\r\n",
			">2\r\n$7\r\nmessage\r\n$5\r\nhello\r\n",
			"#t\r\n",
			"#f\r\n",
			"_\r\n",
			",3.14\r\n",
			",-inf\r\n",
			"(123456789012345678901234567890\r\n",
			"=15\r\ntxt:Some string\r\n",
			"!21\r\nSYNTAX invalid syntax\r\n",
			"|1\r\n+key-popularity\r\n,90.0\r\n",
		} {
			assert.True(t, isRedis(largebuf.NewLargeBufferFrom([]byte(reply))),
				"reply %q must be detected as redis", reply)
		}
	})

	t.Run("garbage after resp3 markers is still rejected", func(t *testing.T) {
		for _, buf := range []string{
			"%abc\r\n",
			"#x\r\n",
			",abc\r\n",
			"_x\r\n",
			"~foo\r\n",
		} {
			assert.False(t, isRedisOp([]byte(buf)), "%q must not be detected as redis", buf)
		}
	})

	t.Run("hello with map reply matches", func(t *testing.T) {
		span, _, ignore, matched := runMatchRedis(t, directionSend,
			respArray("hello", "3"),
			[]byte("%2\r\n$4\r\nrole\r\n$6\r\nmaster\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n"))
		assert.True(t, matched)
		assert.False(t, ignore)
		assert.Equal(t, "hello", span.Method)
		assert.Equal(t, 0, span.Status)
	})

	t.Run("boolean double and null replies pair positionally", func(t *testing.T) {
		req := respPipeline(
			respArray("SISMEMBER", "s", "m"),
			respArray("ZSCORE", "z", "m"),
			respArray("GET", "missing"),
		)
		resp := []byte("#t\r\n,3.14\r\n_\r\n")

		first, extra, _, matched := runMatchRedis(t, directionSend, req, resp)
		require.True(t, matched)
		spans := append([]request.Span{first}, extra...)
		require.Len(t, spans, 3)
		for i, s := range spans {
			assert.Equal(t, 0, s.Status, "span %d", i)
		}
	})

	t.Run("resp3 bulk error sets status and db error", func(t *testing.T) {
		span, _, _, matched := runMatchRedis(t, directionSend,
			respArray("GET", "k"), []byte("!13\r\nERR bad thing\r\n"))
		assert.True(t, matched)
		assert.Equal(t, 1, span.Status)
		assert.Equal(t, "ERR", span.DBError.ErrorCode)
		assert.Equal(t, "ERR bad thing", span.DBError.Description)
	})

	t.Run("push frame between replies does not shift pairing", func(t *testing.T) {
		req := respPipeline(respArray("GET", "k1"), respArray("GET", "k2"))
		resp := []byte("$2\r\nv1\r\n>3\r\n$7\r\nmessage\r\n$2\r\nch\r\n$2\r\nhi\r\n-ERR boom\r\n")

		first, extra, _, matched := runMatchRedis(t, directionSend, req, resp)
		require.True(t, matched)
		spans := append([]request.Span{first}, extra...)
		require.Len(t, spans, 2)
		assert.Equal(t, 0, spans[0].Status)
		assert.Equal(t, 1, spans[1].Status)
		assert.Equal(t, "ERR", spans[1].DBError.ErrorCode)
	})

	t.Run("attribute frame decorates the next reply without shifting pairing", func(t *testing.T) {
		req := respPipeline(respArray("GET", "k1"), respArray("GET", "k2"))
		resp := []byte("|1\r\n$14\r\nkey-popularity\r\n%1\r\n$7\r\nkey:123\r\n,90.0\r\n:1\r\n-ERR boom\r\n")

		first, extra, _, matched := runMatchRedis(t, directionSend, req, resp)
		require.True(t, matched)
		spans := append([]request.Span{first}, extra...)
		require.Len(t, spans, 2)
		assert.Equal(t, 0, spans[0].Status)
		assert.Equal(t, 1, spans[1].Status)
	})

	t.Run("reversed event with resp3 map reply as request", func(t *testing.T) {
		span, _, ignore, matched := runMatchRedis(t, directionRecv,
			[]byte("%1\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n"), respArray("hello", "3"))
		assert.True(t, matched)
		assert.False(t, ignore)
		assert.Equal(t, request.EventTypeRedisClient, span.Type)
		assert.Equal(t, "hello", span.Method)
	})
}

func TestRedisReplyShapesAreNotCommands(t *testing.T) {
	for _, reply := range []string{
		"*-1\r\n",
		"$-1\r\n",
		"*3\r\n$10\r\nblk5:queue\r\n$4\r\njob1\r\n$13\r\n1720000000000\r\n",
		"+OK\r\n",
		"-ERR unknown command\r\n",
		":42\r\n",
	} {
		assert.Empty(t, parseRedisCommands([]byte(reply)), "reply %q must not yield a command", reply)
	}
}
