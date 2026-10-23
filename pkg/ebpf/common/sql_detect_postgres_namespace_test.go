// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func TestPostgresNamespaceString(t *testing.T) {
	assert.Equal(t, "db|schema", postgresNamespace{db: "db", schema: "schema"}.String())
	assert.Equal(t, "db", postgresNamespace{db: "db"}.String())
	assert.Equal(t, "schema", postgresNamespace{schema: "schema"}.String())
	assert.Empty(t, postgresNamespace{}.String())
}

func TestParsePostgresStartupSearchPath(t *testing.T) {
	tests := []struct {
		name   string
		params []string
		want   string
	}{
		{name: "no search_path", params: []string{"user", "app", "database", "conformance"}, want: "conformance"},
		{name: "single schema", params: []string{"database", "conformance", "search_path", "conformance"}, want: "conformance|conformance"},
		{name: "user entry skipped", params: []string{"database", "db", "search_path", `"$user", public`}, want: "db|public"},
		{name: "only user entry", params: []string{"database", "db", "search_path", `"$user"`}, want: "db"},
		{name: "unquoted user entry skipped", params: []string{"database", "db", "search_path", "$user,app"}, want: "db|app"},
		{name: "quoted keeps case and commas", params: []string{"database", "db", "search_path", ` "My ""Schema"", x" , other`}, want: `db|My "Schema", x`},
		{name: "unquoted is folded and trimmed", params: []string{"database", "db", "search_path", "  Sales ,public"}, want: "db|sales"},
		{name: "unquoted with dollar", params: []string{"database", "db", "search_path", "My$App"}, want: "db|my$app"},
		{name: "unquoted folds only ASCII", params: []string{"database", "db", "search_path", "CAFÉ,public"}, want: "db|cafÉ"},
		{name: "empty search_path", params: []string{"database", "db", "search_path", ""}, want: "db"},
		{name: "empty entries skipped", params: []string{"database", "db", "search_path", " , ,app"}, want: "db|app"},
		{name: "options -c", params: []string{"database", "db", "options", "-c search_path=app,public"}, want: "db|app"},
		{name: "options -c joined", params: []string{"database", "db", "options", "-csearch_path=app"}, want: "db|app"},
		{name: "options long form", params: []string{"database", "db", "options", "-c statement_timeout=5 --search_path=app"}, want: "db|app"},
		{name: "options escaped space", params: []string{"database", "db", "options", `-c search_path="$user",\ public`}, want: "db|public"},
		{name: "options escaped space in schema", params: []string{"database", "db", "options", `-c search_path=my\ app,public`}, want: "db|my app"},
		{name: "options literal backslash", params: []string{"database", "db", "options", `-c search_path=my\\app`}, want: `db|my\app`},
		{name: "options tab separated", params: []string{"database", "db", "options", "-c\tsearch_path=app"}, want: "db|app"},
		{name: "options without search_path", params: []string{"database", "db", "options", "-c statement_timeout=5"}, want: "db"},
		{name: "search_path param wins over options", params: []string{"database", "db", "options", "-c search_path=fromopts", "search_path", "fromparam"}, want: "db|fromparam"},
		{name: "database defaults to user", params: []string{"user", "app", "search_path", "s"}, want: "app|s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, ok := parsePostgresStartup(largebuf.NewLargeBufferFrom(pgStartupMessage(tt.params...)))
			require.True(t, ok)
			assert.Equal(t, tt.want, ns.String())
			assert.Equal(t, ns.schema, ns.startupSchema)
		})
	}
}

func TestParsePostgresSearchPathChange(t *testing.T) {
	set := func(schema string) postgresSearchPathChange {
		return postgresSearchPathChange{action: postgresSearchPathSet, schema: schema}
	}
	reset := postgresSearchPathChange{action: postgresSearchPathReset}
	none := postgresSearchPathChange{}

	tests := []struct {
		query string
		want  postgresSearchPathChange
	}{
		{query: "SET search_path TO app", want: set("app")},
		{query: "set search_path = app, public", want: set("app")},
		{query: "SET search_path TO App", want: set("app")},
		{query: `SET search_path TO "App"`, want: set("App")},
		{query: "SET search_path TO 'App'", want: set("App")},
		{query: "SET search_path TO 'it''s'", want: set("it's")},
		{query: "SET search_path TO my$app", want: set("my$app")},
		{query: "SET search_path TO café", want: set("café")},
		{query: "SET search_path TO CAFÉ", want: set("cafÉ")},
		{query: "SET search_path TO app -- trailing", want: set("app")},
		{query: `SET search_path TO "$user", public`, want: set("public")},
		{query: `SET search_path TO "$user"`, want: set("")},
		{query: "SET search_path TO 'a, b'", want: set("a, b")},
		{query: "SET search_path TO status", want: set("status")},
		{query: "SET search_path TO app;", want: set("app")},
		{query: "/* c */ SET search_path TO app", want: set("app")},
		{query: "  set search_path to app\x00", want: set("app")},
		{query: "SET SCHEMA 'app'", want: set("app")},
		{query: "SET SESSION search_path TO app", want: set("app")},
		{query: "SET SESSION SCHEMA 'app'", want: set("app")},
		{query: "SET search_path TO DEFAULT", want: reset},
		{query: "SET search_path = default", want: reset},
		{query: "RESET search_path", want: reset},
		{query: "RESET ALL", want: reset},
		{query: "DISCARD ALL", want: reset},
		{query: "SET LOCAL search_path TO app", want: none},
		{query: "SET LOCAL SCHEMA 'app'", want: none},
		{query: "SET search_path TO app; SELECT 1", want: none},
		{query: "SET search_path TO app, public; DROP TABLE x", want: none},
		{query: "SET SCHEMA 'a', 'b'", want: none},
		{query: "SET search_path app", want: none},
		{query: "SET search_path TO", want: none},
		{query: "SET search_path TO $user", want: none},
		{query: "SET search_path TO a-b", want: none},
		{query: "SET search_path TO 'app", want: none},
		{query: "SET search_path TO app /* open", want: none},
		{query: "SET statement_timeout TO 5", want: none},
		{query: "RESET statement_timeout", want: none},
		{query: "DISCARD PLANS", want: none},
		{query: "SELECT * FROM accounts", want: none},
		{query: "", want: none},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			assert.Equal(t, tt.want, parsePostgresSearchPathChange([]byte(tt.query)))
		})
	}
}

func pgExtendedQuery(query string) []byte {
	var buf []byte
	buf = append(buf, pgWireMsg(kPostgresParse, "\x00"+query+"\x00\x00")...)
	buf = append(buf, pgWireMsg(kPostgresBind, "\x00\x00\x00\x00\x00\x00\x00")...)
	buf = append(buf, pgWireMsg('E', "\x00\x00\x00\x00")...)
	return append(buf, 'S', 0, 0, 0, 4)
}

func pgParseDescribe(stmtName, query string) []byte {
	buf := pgWireMsg(kPostgresParse, stmtName+"\x00"+query+"\x00\x00")
	buf = append(buf, pgWireMsg('D', "S"+stmtName)...)
	return append(buf, 'S', 0, 0, 0, 4)
}

func pgBindExecute(stmtName string) []byte {
	buf := pgWireMsg(kPostgresBind, "\x00"+stmtName+"\x00\x00\x00\x00\x00\x00\x00")
	buf = append(buf, pgWireMsg('E', "\x00\x00\x00\x00")...)
	return append(buf, 'S', 0, 0, 0, 4)
}

func TestReadTCPRequestIntoSpan_PostgresSchemaInNamespace(t *testing.T) {
	cfg := config.EBPFTracer{HeuristicSQLDetect: true, PostgresPreparedStatementsCacheSize: 16}
	ctx := NewEBPFParseContext(&cfg, nil, nil)
	fltr := TestPidsFilter{services: map[app.PID]svc.Attrs{}}

	readSpan := func(t *testing.T, r TCPRequestInfo) (request.Span, bool) {
		binaryRecord := bytes.Buffer{}
		require.NoError(t, binary.Write(&binaryRecord, binary.LittleEndian, r))
		span, ignore, err := ReadTCPRequestIntoSpan(ctx, &cfg, &ringbuf.Record{RawSample: binaryRecord.Bytes()}, &fltr)
		require.NoError(t, err)
		return span, ignore
	}

	pgRequest := func(req, resp []byte) TCPRequestInfo {
		r := makeTCPReq(string(req), 5432)
		r.ProtocolType = ProtocolTypePostgres
		r.RespLen = uint32(len(resp))
		copy(r.Rbuf[:], resp)
		return r
	}

	selectNamespace := func(t *testing.T) string {
		span, ignore := readSpan(t, pgRequest(pgWireMsg(kPostgresQuery, "SELECT * FROM accounts"), pgWireMsg(kPostgresCommand, "SELECT 1")))
		require.False(t, ignore)
		require.Equal(t, "SELECT", span.Method)
		return span.DBNamespace
	}

	var ignore bool
	setOK := pgWireMsg(kPostgresCommand, "SET")
	extendedSetOK := append(append([]byte{'1', 0, 0, 0, 4, '2', 0, 0, 0, 4}, setOK...), 'Z', 0, 0, 0, 5, 'I')
	setFailed := pgWireMsg(kPostgresErrorResponse, "SERROR\x00C25P02\x00Mcurrent transaction is aborted, commands ignored until end of transaction block\x00")
	parseDescribeOK := []byte{'1', 0, 0, 0, 4, 't', 0, 0, 0, 6, 0, 0, 'n', 0, 0, 0, 4, 'Z', 0, 0, 0, 5, 'I'}

	_, ignore = readSpan(t, makeTCPReq(string(pgStartupMessage("user", "app", "database", "conformance", "search_path", "conformance")), 5432))
	require.True(t, ignore)
	assert.Equal(t, "conformance|conformance", selectNamespace(t))

	readSpan(t, pgRequest(pgWireMsg(kPostgresQuery, "SET search_path TO sales, public"), setOK))
	assert.Equal(t, "conformance|sales", selectNamespace(t))

	readSpan(t, pgRequest(pgWireMsg(kPostgresQuery, "SET LOCAL search_path TO tx"), setOK))
	assert.Equal(t, "conformance|sales", selectNamespace(t))

	readSpan(t, pgRequest(pgWireMsg(kPostgresQuery, "SET search_path TO missing"), setFailed))
	assert.Equal(t, "conformance|sales", selectNamespace(t))

	readSpan(t, pgRequest(pgExtendedQuery("SET SESSION SCHEMA 'Billing'"), extendedSetOK))
	assert.Equal(t, "conformance|Billing", selectNamespace(t))

	readSpan(t, pgRequest(pgParseDescribe("", "SET search_path TO deferred"), parseDescribeOK))
	assert.Equal(t, "conformance|Billing", selectNamespace(t))
	readSpan(t, pgRequest(pgBindExecute(""), extendedSetOK))
	assert.Equal(t, "conformance|deferred", selectNamespace(t))

	unexecutedSet := append(pgWireMsg(kPostgresParse, "s1\x00SET search_path TO named\x00\x00"), pgExtendedQuery("SELECT * FROM accounts")...)
	selectOK := append(append([]byte{'1', 0, 0, 0, 4, '1', 0, 0, 0, 4, '2', 0, 0, 0, 4}, pgWireMsg(kPostgresCommand, "SELECT 1")...), 'Z', 0, 0, 0, 5, 'I')
	span, ignore := readSpan(t, pgRequest(unexecutedSet, selectOK))
	require.False(t, ignore)
	assert.Equal(t, "SELECT", span.Method)
	assert.Equal(t, "conformance|deferred", span.DBNamespace)
	assert.Equal(t, "conformance|deferred", selectNamespace(t))

	readSpan(t, pgRequest(pgBindExecute("s1"), extendedSetOK))
	assert.Equal(t, "conformance|named", selectNamespace(t))

	readSpan(t, pgRequest(pgWireMsg(kPostgresQuery, "RESET search_path"), pgWireMsg(kPostgresCommand, "RESET")))
	assert.Equal(t, "conformance|conformance", selectNamespace(t))

	readSpan(t, pgRequest(pgWireMsg(kPostgresQuery, `SET search_path TO "$user"`), setOK))
	assert.Equal(t, "conformance", selectNamespace(t))
}

func TestHandlePostgresRejectedParseKeepsCachedStatement(t *testing.T) {
	parseComplete := postgresTestPacket('1', nil)
	bindComplete := postgresTestPacket('2', nil)
	ready := postgresTestPacket('Z', []byte{'I'})
	selectDone := postgresTestPacket(kPostgresCommandComplete, []byte("SELECT 1\x00"))
	setDone := postgresTestPacket(kPostgresCommandComplete, []byte("SET\x00"))
	duplicate := postgresErrorResponse("42P05", `prepared statement "x" already exists`)

	newCtx := func() (*EBPFParseContext, *TCPRequestInfo) {
		ctx := newPostgresTestContext()
		event := &TCPRequestInfo{}
		ctx.postgresNamespaces.Add(event.ConnInfo, postgresNamespace{db: "db", startupSchema: "public", schema: "public"})
		return ctx, event
	}

	handle := func(ctx *EBPFParseContext, event *TCPRequestInfo, req []byte, resp ...[]byte) (request.Span, error) {
		return handlePostgres(ctx, event, largebuf.NewLargeBufferFrom(req), largebuf.NewLargeBufferFrom(bytes.Join(resp, nil)))
	}

	cached := func(ctx *EBPFParseContext, event *TCPRequestInfo, stmtName string) (postgresPreparedStatement, bool) {
		return ctx.postgresPreparedStatements.Get(postgresPreparedStatementsKey{connInfo: event.ConnInfo, stmtName: stmtName})
	}

	t.Run("duplicate named Parse keeps the original statement", func(t *testing.T) {
		ctx, event := newCtx()

		_, err := handle(ctx, event, pgParseDescribe("x", "SELECT * FROM accounts"), parseComplete, ready)
		require.ErrorIs(t, err, errIgnore)

		_, err = handle(ctx, event, pgParseDescribe("x", "SET search_path TO phantom"), duplicate, ready)
		require.ErrorIs(t, err, errIgnore)
		prepared, found := cached(ctx, event, "x")
		require.True(t, found)
		assert.Equal(t, postgresPreparedStatement{query: "SELECT * FROM accounts"}, prepared)

		span, err := handle(ctx, event, pgBindExecute("x"), bindComplete, selectDone, ready)
		require.NoError(t, err)
		assert.Equal(t, "SELECT", span.Method)
		assert.Equal(t, "SELECT * FROM accounts", span.Statement)
		assert.Equal(t, "db|public", span.DBNamespace)
	})

	t.Run("rejected Parse after a Sync in the same packet is not cached", func(t *testing.T) {
		ctx, event := newCtx()

		req := append(pgParseDescribe("x", "SELECT * FROM accounts"), pgParseDescribe("x", "SET search_path TO phantom")...)
		_, err := handle(ctx, event, req, parseComplete, ready, duplicate, ready)
		require.ErrorIs(t, err, errIgnore)
		prepared, found := cached(ctx, event, "x")
		require.True(t, found)
		assert.Equal(t, postgresPreparedStatement{query: "SELECT * FROM accounts"}, prepared)
	})

	t.Run("rejected Parse reports its error on the Execute in the same packet", func(t *testing.T) {
		ctx, event := newCtx()

		req := append(pgWireMsg(kPostgresParse, "x\x00SELECT * FROM accounts\x00\x00"), pgBindExecute("x")...)
		span, err := handle(ctx, event, req, postgresErrorResponse("42P01", `relation "accounts" does not exist`), ready)
		require.NoError(t, err)
		assert.Equal(t, "SELECT * FROM accounts", span.Statement)
		require.NotNil(t, span.SQLError)
		assert.Equal(t, "42P01", span.SQLError.SQLState)

		_, found := cached(ctx, event, "x")
		assert.False(t, found)
	})

	t.Run("Parse with a failing Execute is cached without changing the schema", func(t *testing.T) {
		ctx, event := newCtx()

		req := append(pgWireMsg(kPostgresParse, "s1\x00SET search_path TO named\x00\x00"), pgBindExecute("s1")...)
		_, _ = handle(ctx, event, req, parseComplete, bindComplete, postgresErrorResponse("25P02", "current transaction is aborted"), ready)
		assert.Equal(t, "db|public", postgresNamespaceForConn(ctx, event.ConnInfo))
		prepared, found := cached(ctx, event, "s1")
		require.True(t, found)
		assert.Equal(t, postgresSearchPathChange{action: postgresSearchPathSet, schema: "named"}, prepared.searchPathChange)

		_, _ = handle(ctx, event, pgBindExecute("s1"), bindComplete, setDone, ready)
		assert.Equal(t, "db|named", postgresNamespaceForConn(ctx, event.ConnInfo))
	})
}
