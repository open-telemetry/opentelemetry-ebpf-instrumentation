// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestHasN1QLVersion(t *testing.T) {
	tests := []struct {
		name     string
		resp     *http.Response
		expected bool
	}{
		{
			name: "SQL++ response with N1QL version suffix",
			resp: &http.Response{
				Header: http.Header{
					"Content-Type": []string{"application/json; version=2.0.0-N1QL"},
				},
			},
			expected: true,
		},
		{
			name: "SQL++ response with version not ending in -N1QL",
			resp: &http.Response{
				Header: http.Header{
					"Content-Type": []string{"application/json; version=2.0.0 N1QL"},
				},
			},
			expected: false,
		},
		{
			name: "SQL++ response without version parameter",
			resp: &http.Response{
				Header: http.Header{
					"Content-Type": []string{"application/json; N1QL"},
				},
			},
			expected: false,
		},
		{
			name: "plain JSON response",
			resp: &http.Response{
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			},
			expected: false,
		},
		{
			name:     "nil response",
			resp:     nil,
			expected: false,
		},
		{
			name: "version with different N1QL suffix",
			resp: &http.Response{
				Header: http.Header{
					"Content-Type": []string{"application/json; version=1.0.0-N1QL"},
				},
			},
			expected: true,
		},
		{
			name: "version without hyphen before N1QL",
			resp: &http.Response{
				Header: http.Header{
					"Content-Type": []string{"application/json; version=2.0.0N1QL"},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hasN1QLVersion(tt.resp))
		})
	}
}

func TestMatchesEndpointPattern(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		patterns []string
		expected bool
	}{
		{
			name:     "exact match",
			path:     "/query",
			patterns: []string{"/query"},
			expected: true,
		},
		{
			name:     "suffix match",
			path:     "/api/v1/query",
			patterns: []string{"/query"},
			expected: true,
		},
		{
			name:     "no match",
			path:     "/api/v1/search",
			patterns: []string{"/query"},
			expected: false,
		},
		{
			name:     "multiple patterns - first matches",
			path:     "/query",
			patterns: []string{"/query", "/query/service"},
			expected: true,
		},
		{
			name:     "multiple patterns - second matches",
			path:     "/query/service",
			patterns: []string{"/query", "/query/service"},
			expected: true,
		},
		{
			name:     "empty patterns",
			path:     "/query",
			patterns: []string{},
			expected: false,
		},
		{
			name:     "nil request",
			path:     "",
			patterns: []string{"/query"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.path != "" {
				req = &http.Request{
					URL: &url.URL{Path: tt.path},
				}
			}
			assert.Equal(t, tt.expected, matchesEndpointPattern(req, tt.patterns))
		})
	}
}

func TestParseSQLPPRequest(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		contentType string
		expected    *sqlppRequest
		expectErr   bool
	}{
		{
			name:        "JSON request with statement",
			body:        `{"statement": "SELECT * FROM mybucket"}`,
			contentType: "application/json",
			expected: &sqlppRequest{
				Statement: "SELECT * FROM mybucket",
			},
			expectErr: false,
		},
		{
			name:        "JSON request with query_context",
			body:        `{"statement": "SELECT * FROM mycollection", "query_context": "default:mybucket.myscope"}`,
			contentType: "application/json",
			expected: &sqlppRequest{
				Statement: "SELECT * FROM mycollection",
				QueryCtx:  "default:mybucket.myscope",
			},
			expectErr: false,
		},
		{
			name:        "form-encoded request",
			body:        "statement=SELECT+*+FROM+mybucket&timeout=30s",
			contentType: "application/x-www-form-urlencoded",
			expected: &sqlppRequest{
				Statement: "SELECT * FROM mybucket",
			},
			expectErr: false,
		},
		{
			name:        "empty body",
			body:        "",
			contentType: "application/json",
			expected:    nil,
			expectErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
				Body: io.NopCloser(bytes.NewBufferString(tt.body)),
			}

			result, err := parseSQLPPRequest(req)

			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.Statement, result.Statement)
				if tt.expected.QueryCtx != "" {
					assert.Equal(t, tt.expected.QueryCtx, result.QueryCtx)
				}
			}
		})
	}
}

func TestSQLPPSpan(t *testing.T) {
	endpointPatterns := []string{"/query", "/query/service"}

	tests := []struct {
		name               string
		reqPath            string
		reqBody            string
		reqContentType     string
		respContentType    string
		expectedDetected   bool
		expectedDBSystem   string
		expectedOperation  string
		expectedNamespace  string
		expectedCollection string
	}{
		{
			name:               "Couchbase SQL++ SELECT query with N1QL header",
			reqPath:            "/query/service",
			reqBody:            "{\"statement\": \"SELECT * FROM `mybucket`.`myscope`.`mycollection` WHERE id = '123'\"}",
			reqContentType:     "application/json",
			respContentType:    "application/json; version=2.0.0-N1QL",
			expectedDetected:   true,
			expectedDBSystem:   "couchbase",
			expectedOperation:  "SELECT",
			expectedNamespace:  "mybucket",
			expectedCollection: "myscope.mycollection",
		},
		{
			name:               "Generic SQL++ SELECT query without N1QL header",
			reqPath:            "/query/service",
			reqBody:            "{\"statement\": \"SELECT * FROM `mybucket`.`myscope`.`mycollection` WHERE id = '123'\"}",
			reqContentType:     "application/json",
			respContentType:    "application/json",
			expectedDetected:   true,
			expectedDBSystem:   "other_sql",
			expectedOperation:  "SELECT",
			expectedNamespace:  "mybucket",
			expectedCollection: "myscope.mycollection",
		},
		{
			name:               "Couchbase SQL++ INSERT query",
			reqPath:            "/query/service",
			reqBody:            `{"statement": "INSERT INTO mybucket (KEY, VALUE) VALUES ('key1', {'name': 'test'})"}`,
			reqContentType:     "application/json",
			respContentType:    "application/json; version=2.0.0-N1QL",
			expectedDetected:   true,
			expectedDBSystem:   "couchbase",
			expectedOperation:  "INSERT",
			expectedNamespace:  "mybucket",
			expectedCollection: "",
		},
		{
			name:               "SQL++ with query_context",
			reqPath:            "/query/service",
			reqBody:            `{"statement": "SELECT * FROM mycollection", "query_context": "default:mybucket.myscope"}`,
			reqContentType:     "application/json",
			respContentType:    "application/json; version=2.0.0-N1QL",
			expectedDetected:   true,
			expectedDBSystem:   "couchbase",
			expectedOperation:  "SELECT",
			expectedNamespace:  "mybucket",
			expectedCollection: "mycollection",
		},
		{
			name:               "SQL++ with backtick-quoted query_context",
			reqPath:            "/query/service",
			reqBody:            "{\"statement\": \"SELECT * FROM `test-collection`\", \"query_context\": \"default:`test-bucket`.`test-scope`\"}",
			reqContentType:     "application/json",
			respContentType:    "application/json; version=2.0.0-N1QL",
			expectedDetected:   true,
			expectedDBSystem:   "couchbase",
			expectedOperation:  "SELECT",
			expectedNamespace:  "test-bucket",
			expectedCollection: "test-collection",
		},
		{
			name:               "Endpoint does not match patterns",
			reqPath:            "/api/search",
			reqBody:            `{"statement": "SELECT * FROM mybucket"}`,
			reqContentType:     "application/json",
			respContentType:    "application/json; version=2.0.0-N1QL",
			expectedDetected:   false,
			expectedDBSystem:   "",
			expectedOperation:  "",
			expectedNamespace:  "",
			expectedCollection: "",
		},
		{
			name:               "AsterixDB-style endpoint",
			reqPath:            "/query/service",
			reqBody:            `{"statement": "SELECT * FROM mydata"}`,
			reqContentType:     "application/json",
			respContentType:    "application/json",
			expectedDetected:   true,
			expectedDBSystem:   "other_sql",
			expectedOperation:  "SELECT",
			expectedNamespace:  "mydata",
			expectedCollection: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				URL: &url.URL{Path: tt.reqPath},
				Header: http.Header{
					"Content-Type": []string{tt.reqContentType},
				},
				Body: io.NopCloser(bytes.NewBufferString(tt.reqBody)),
			}

			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.respContentType},
				},
			}

			baseSpan := &request.Span{}
			resultSpan, detected := SQLPPSpan(baseSpan, req, resp, endpointPatterns, nil)

			assert.Equal(t, tt.expectedDetected, detected)

			if tt.expectedDetected {
				assert.Equal(t, request.HTTPSubtypeSQLPP, resultSpan.SubType)
				assert.Equal(t, tt.expectedDBSystem, resultSpan.DBSystem)
				assert.Equal(t, tt.expectedOperation, resultSpan.Method)
				assert.Equal(t, tt.expectedNamespace, resultSpan.DBNamespace)
				assert.Equal(t, tt.expectedCollection, resultSpan.Route)
				assert.NotEmpty(t, resultSpan.Statement)
			}
		})
	}
}

func TestParseSQLPPResponse(t *testing.T) {
	tests := []struct {
		name              string
		respBody          string
		expectedErrorCode string
		expectedErrorMsg  string
		expectError       bool
	}{
		{
			name:        "successful response",
			respBody:    `{"requestID": "abc", "results": [], "status": "success"}`,
			expectError: false,
		},
		{
			name:              "response with error",
			respBody:          `{"requestID": "abc", "errors": [{"code": 12003, "msg": "Keyspace not found"}], "status": "fatal"}`,
			expectedErrorCode: "12003",
			expectedErrorMsg:  "Keyspace not found",
			expectError:       true,
		},
		{
			name:              "response with multiple errors",
			respBody:          `{"requestID": "abc", "errors": [{"code": 5000, "msg": "First error"}, {"code": 5001, "msg": "Second error"}], "status": "errors"}`,
			expectedErrorCode: "5000",
			expectedErrorMsg:  "First error",
			expectError:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSQLPPResponse([]byte(tt.respBody))

			if tt.expectError {
				require.NotNil(t, result)
				assert.Equal(t, tt.expectedErrorCode, result.ErrorCode)
				assert.Equal(t, tt.expectedErrorMsg, result.Description)
			} else {
				assert.Nil(t, result)
			}
		})
	}
}

func TestSQLPPSpanWithError(t *testing.T) {
	endpointPatterns := []string{"/query/service"}

	req := &http.Request{
		URL: &url.URL{Path: "/query/service"},
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewBufferString(`{"statement": "SELECT * FROM nonexistent"}`)),
	}

	resp := &http.Response{
		Header: http.Header{
			"Content-Type": []string{"application/json; version=2.0.0-N1QL"},
		},
		Body: io.NopCloser(bytes.NewBufferString(`{"requestID": "abc", "errors": [{"code": 12003, "msg": "Keyspace not found in CB datastore"}], "status": "fatal"}`)),
	}

	baseSpan := &request.Span{}
	resultSpan, detected := SQLPPSpan(baseSpan, req, resp, endpointPatterns, nil)

	assert.True(t, detected)
	assert.Equal(t, request.HTTPSubtypeSQLPP, resultSpan.SubType)
	assert.Equal(t, "12003", resultSpan.DBError.ErrorCode)
	assert.Equal(t, "Keyspace not found in CB datastore", resultSpan.DBError.Description)
}

func TestParseSQLPPTablePath(t *testing.T) {
	tests := []struct {
		name               string
		table              string
		hasQueryContext    bool
		expectedBucket     string
		expectedCollection string
	}{
		{
			name:               "empty table",
			table:              "",
			hasQueryContext:    false,
			expectedBucket:     "",
			expectedCollection: "",
		},
		{
			name:               "single identifier without query context",
			table:              "mybucket",
			hasQueryContext:    false,
			expectedBucket:     "mybucket",
			expectedCollection: "",
		},
		{
			name:               "single identifier with query context",
			table:              "mycollection",
			hasQueryContext:    true,
			expectedBucket:     "",
			expectedCollection: "mycollection",
		},
		{
			name:               "three-part path",
			table:              "mybucket.myscope.mycollection",
			hasQueryContext:    false,
			expectedBucket:     "mybucket",
			expectedCollection: "myscope.mycollection",
		},
		{
			name:               "three-part path with query context",
			table:              "mybucket.myscope.mycollection",
			hasQueryContext:    true,
			expectedBucket:     "mybucket",
			expectedCollection: "myscope.mycollection",
		},
		{
			name:               "two-part path returns as-is",
			table:              "bucket.collection",
			hasQueryContext:    false,
			expectedBucket:     "",
			expectedCollection: "bucket.collection",
		},
		{
			name:               "four-part path returns as-is",
			table:              "a.b.c.d",
			hasQueryContext:    false,
			expectedBucket:     "",
			expectedCollection: "a.b.c.d",
		},
		{
			name:               "backtick-quoted single identifier without query context",
			table:              "`my-bucket`",
			hasQueryContext:    false,
			expectedBucket:     "`my-bucket`",
			expectedCollection: "",
		},
		{
			name:               "backtick-quoted single identifier with query context",
			table:              "`my-collection`",
			hasQueryContext:    true,
			expectedBucket:     "",
			expectedCollection: "`my-collection`",
		},
		{
			name:               "backtick-quoted three-part path",
			table:              "`my-bucket`.`my-scope`.`my-collection`",
			hasQueryContext:    false,
			expectedBucket:     "`my-bucket`",
			expectedCollection: "`my-scope`.`my-collection`",
		},
		{
			name:               "mixed quoted and unquoted three-part path",
			table:              "mybucket.`my-scope`.mycollection",
			hasQueryContext:    false,
			expectedBucket:     "mybucket",
			expectedCollection: "`my-scope`.mycollection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket, collection := parseSQLPPTablePath(tt.table, tt.hasQueryContext)
			assert.Equal(t, tt.expectedBucket, bucket)
			assert.Equal(t, tt.expectedCollection, collection)
		})
	}
}

func TestExtractSQLPPNamespace(t *testing.T) {
	tests := []struct {
		name              string
		queryContext      string
		expectedNamespace string
	}{
		{
			name:              "unquoted with default prefix",
			queryContext:      "default:mybucket.myscope",
			expectedNamespace: "mybucket",
		},
		{
			name:              "unquoted without default prefix",
			queryContext:      "mybucket.myscope",
			expectedNamespace: "mybucket",
		},
		{
			name:              "backtick-quoted with default prefix",
			queryContext:      "default:`test-bucket`.`test-scope`",
			expectedNamespace: "test-bucket",
		},
		{
			name:              "backtick-quoted without default prefix",
			queryContext:      "`test-bucket`.`test-scope`",
			expectedNamespace: "test-bucket",
		},
		{
			name:              "backtick-quoted bucket only",
			queryContext:      "default:`my-bucket`",
			expectedNamespace: "my-bucket",
		},
		{
			name:              "empty query context",
			queryContext:      "",
			expectedNamespace: "",
		},
		{
			name:              "unquoted bucket only",
			queryContext:      "default:mybucket",
			expectedNamespace: "mybucket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &sqlppRequest{
				Statement: "SELECT * FROM test",
				QueryCtx:  tt.queryContext,
			}
			result := extractSQLPPNamespace(req)
			assert.Equal(t, tt.expectedNamespace, result)
		})
	}
}

func TestParseSQLPPRequestPrepared(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		contentType string
		expected    sqlppRequest
	}{
		{
			name:        "execute by prepared name",
			body:        `{"prepared": "p1", "query_context": "default:b.s"}`,
			contentType: "application/json",
			expected:    sqlppRequest{Prepared: "p1", QueryCtx: "default:b.s"},
		},
		{
			name:        "legacy execute with encoded plan",
			body:        `{"prepared": "p2", "encoded_plan": "H4sIAAAA"}`,
			contentType: "application/json",
			expected:    sqlppRequest{Prepared: "p2"},
		},
		{
			name:        "enhanced prepare with auto execute",
			body:        `{"statement": "PREPARE SELECT * FROM b", "auto_execute": true}`,
			contentType: "application/json",
			expected:    sqlppRequest{Statement: "PREPARE SELECT * FROM b", AutoExecute: true},
		},
		{
			name:        "non-string prepared is ignored",
			body:        `{"statement": "SELECT 1", "prepared": {"name": "x"}}`,
			contentType: "application/json",
			expected:    sqlppRequest{Statement: "SELECT 1"},
		},
		{
			name:        "form-encoded prepared",
			body:        `prepared="p3"&auto_execute=true`,
			contentType: "application/x-www-form-urlencoded",
			expected:    sqlppRequest{Prepared: "p3", AutoExecute: true},
		},
		{
			name:        "url-encoded prepared",
			body:        `prepared=%22p4%22&auto_execute=%22true%22`,
			contentType: "application/x-www-form-urlencoded",
			expected:    sqlppRequest{Prepared: "p4", AutoExecute: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Header: http.Header{"Content-Type": []string{tt.contentType}},
				Body:   io.NopCloser(bytes.NewBufferString(tt.body)),
			}
			result, err := parseSQLPPRequest(req)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, *result)
		})
	}
}

func TestParseSQLPPPrepare(t *testing.T) {
	tests := []struct {
		statement string
		ok        bool
		name      string
		inner     string
	}{
		{statement: "PREPARE SELECT * FROM b", ok: true, inner: "SELECT * FROM b"},
		{statement: "  prepare\nSELECT * FROM b", ok: true, inner: "SELECT * FROM b"},
		{statement: "PREPARE FORCE SELECT * FROM b", ok: true, inner: "SELECT * FROM b"},
		{statement: "PREPARE q1 FROM SELECT * FROM b", ok: true, name: "q1", inner: "SELECT * FROM b"},
		{statement: "PREPARE `my q` AS SELECT * FROM b", ok: true, name: "my q", inner: "SELECT * FROM b"},
		{statement: "PREPARE FORCE q1 from SELECT a FROM b", ok: true, name: "q1", inner: "SELECT a FROM b"},
		{statement: "PREPARE SELECT a AS x FROM b", ok: true, inner: "SELECT a AS x FROM b"},
		{statement: "PREPARE DELETE FROM `b`.`s`.`c` WHERE id = $1", ok: true, inner: "DELETE FROM `b`.`s`.`c` WHERE id = $1"},
		{statement: "PREPARE FORCE DELETE FROM b", ok: true, inner: "DELETE FROM b"},
		{statement: "prepare delete from b where x = 1", ok: true, inner: "delete from b where x = 1"},
		{statement: "PREPARE q1 FROM DELETE FROM b", ok: true, name: "q1", inner: "DELETE FROM b"},
		{statement: "PREPARE q1 AS (SELECT 1)", ok: true, name: "q1", inner: "(SELECT 1)"},
		{statement: "PREPARE q1 FROM WITH x AS (SELECT 1) SELECT * FROM x", ok: true, name: "q1", inner: "WITH x AS (SELECT 1) SELECT * FROM x"},
		{statement: "PREPARE", ok: false},
		{statement: "PREPARED SELECT 1", ok: false},
		{statement: "SELECT * FROM b", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.statement, func(t *testing.T) {
			name, inner, ok := parseSQLPPPrepare(tt.statement)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.name, name)
			assert.Equal(t, tt.inner, inner)
		})
	}
}

func TestParseSQLPPExecute(t *testing.T) {
	tests := []struct {
		statement string
		ok        bool
		name      string
	}{
		{statement: "EXECUTE q1", ok: true, name: "q1"},
		{statement: "execute `q1` USING [1]", ok: true, name: "q1"},
		{statement: `EXECUTE "q1"`, ok: true, name: "q1"},
		{statement: "EXECUTE FUNCTION add(1, 2)", ok: false},
		{statement: "EXECUTE", ok: false},
		{statement: "SELECT 1", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.statement, func(t *testing.T) {
			name, ok := parseSQLPPExecute(tt.statement)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.name, name)
		})
	}
}

type sqlppExchange struct {
	pid      app.PID
	host     string
	status   int
	reqBody  string
	respBody string
}

func runSQLPPExchange(t *testing.T, prepared *SQLPPPreparedStatements, ex sqlppExchange) (request.Span, bool) {
	t.Helper()
	req := &http.Request{
		URL:    &url.URL{Path: "/query/service"},
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   io.NopCloser(bytes.NewBufferString(ex.reqBody)),
	}
	status := ex.status
	if status == 0 {
		status = http.StatusOK
	}
	resp := &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json; version=2.0.0-N1QL"}},
		Body:       io.NopCloser(bytes.NewBufferString(ex.respBody)),
	}
	baseSpan := &request.Span{
		Pid:      request.PidInfo{HostPID: ex.pid},
		Host:     ex.host,
		HostPort: sqlppTestQueryPort,
	}
	return SQLPPSpan(baseSpan, req, resp, []string{"/query/service"}, prepared)
}

const sqlppTestQueryPort = 8093

func newTestSQLPPPreparedStatements(t *testing.T) *SQLPPPreparedStatements {
	t.Helper()
	prepared, err := NewSQLPPPreparedStatements(16)
	require.NoError(t, err)
	return prepared
}

func TestSQLPPSpanPreparedStatements(t *testing.T) {
	const statement = "SELECT * FROM `b`.`s`.`c` WHERE id = $1"
	prepare := `{"statement": "PREPARE ` + statement + `"`

	type expectation struct {
		statement  string
		operation  string
		namespace  string
		collection string
	}
	resolved := expectation{statement: statement, operation: "SELECT", namespace: "b", collection: "s.c"}

	tests := []struct {
		name      string
		exchanges []sqlppExchange
		expected  []expectation
	}{
		{
			name: "enhanced prepare learns the name from the response",
			exchanges: []sqlppExchange{
				{
					reqBody:  prepare + `, "auto_execute": true, "args": [1]}`,
					respBody: `{"requestID": "r1", "signature": {"*": "*"}, "prepared": "p1", "results": [{"id": 1}], "status": "success"}`,
				},
				{
					reqBody:  `{"prepared": "p1", "args": [2]}`,
					respBody: `{"requestID": "r2", "results": [{"id": 2}], "status": "success"}`,
				},
			},
			expected: []expectation{resolved, resolved},
		},
		{
			name: "enhanced prepare tolerates a truncated response",
			exchanges: []sqlppExchange{
				{
					reqBody:  prepare + `, "auto_execute": true}`,
					respBody: `{"requestID": "r1", "prepared": "p1", "results": [{"id": 1}, {"i`,
				},
				{reqBody: `{"prepared": "p1"}`},
			},
			expected: []expectation{resolved, resolved},
		},
		{
			name: "legacy prepare learns the name from the results",
			exchanges: []sqlppExchange{
				{
					reqBody:  prepare + `}`,
					respBody: `{"requestID": "r1", "results": [{"encoded_plan": "H4sI", "name": "p2", "text": "PREPARE ..."}], "status": "success"}`,
				},
				{reqBody: `{"prepared": "p2", "encoded_plan": "H4sI"}`},
			},
			expected: []expectation{
				{statement: statement, operation: "PREPARE", namespace: "b", collection: "s.c"},
				resolved,
			},
		},
		{
			name: "auto executed result rows never name the statement",
			exchanges: []sqlppExchange{
				{
					reqBody:  prepare + `, "auto_execute": true}`,
					respBody: `{"requestID": "r1", "results": [{"name": "row"}], "status": "success"}`,
				},
				{reqBody: `{"prepared": "row"}`},
			},
			expected: []expectation{resolved, {operation: "EXECUTE"}},
		},
		{
			name: "anonymous prepared DELETE learns the server name",
			exchanges: []sqlppExchange{
				{
					reqBody:  "{\"statement\": \"PREPARE DELETE FROM `b`.`s`.`c` WHERE id = $1\", \"auto_execute\": true}",
					respBody: `{"requestID": "r1", "prepared": "srv-name", "results": [], "status": "success"}`,
				},
				{reqBody: `{"prepared": "srv-name"}`},
			},
			expected: []expectation{
				{statement: "DELETE FROM `b`.`s`.`c` WHERE id = $1", operation: "DELETE", namespace: "b", collection: "s.c"},
				{statement: "DELETE FROM `b`.`s`.`c` WHERE id = $1", operation: "DELETE", namespace: "b", collection: "s.c"},
			},
		},
		{
			name: "server-named prepare is cached when its execution fails",
			exchanges: []sqlppExchange{
				{
					reqBody:  "{\"statement\": \"PREPARE INSERT INTO `b`.`s`.`c` (KEY, VALUE) VALUES ($1, $2)\", \"auto_execute\": true}",
					respBody: `{"requestID": "r1", "prepared": "srv-insert", "errors": [{"code": 12009, "msg": "Duplicate Key"}], "status": "errors"}`,
				},
				{reqBody: `{"prepared": "srv-insert"}`},
			},
			expected: []expectation{
				{statement: "INSERT INTO `b`.`s`.`c` (KEY, VALUE) VALUES ($1, $2)", operation: "INSERT", namespace: "b", collection: "s.c"},
				{statement: "INSERT INTO `b`.`s`.`c` (KEY, VALUE) VALUES ($1, $2)", operation: "INSERT", namespace: "b", collection: "s.c"},
			},
		},
		{
			name: "rejected prepare is not cached",
			exchanges: []sqlppExchange{
				{
					reqBody:  `{"statement": "PREPARE q1 FROM SELECT * FROM c"}`,
					respBody: `{"requestID": "r1", "errors": [{"code": 3000, "msg": "syntax error"}], "status": "fatal"}`,
				},
				{reqBody: `{"prepared": "q1"}`},
			},
			expected: []expectation{
				{statement: "SELECT * FROM c", operation: "PREPARE", namespace: "c"},
				{operation: "EXECUTE"},
			},
		},
		{
			name: "names are scoped by process",
			exchanges: []sqlppExchange{
				{pid: 1, reqBody: `{"statement": "PREPARE q1 FROM SELECT * FROM c1"}`},
				{pid: 2, reqBody: `{"statement": "PREPARE q1 FROM SELECT * FROM c2"}`},
				{pid: 1, reqBody: `{"prepared": "q1"}`},
				{pid: 3, reqBody: `{"prepared": "q1"}`},
			},
			expected: []expectation{
				{statement: "SELECT * FROM c1", operation: "PREPARE", namespace: "c1"},
				{statement: "SELECT * FROM c2", operation: "PREPARE", namespace: "c2"},
				{statement: "SELECT * FROM c1", operation: "SELECT", namespace: "c1"},
				{operation: "EXECUTE"},
			},
		},
		{
			name: "client-chosen names are scoped by destination",
			exchanges: []sqlppExchange{
				{host: "10.0.0.1", reqBody: `{"statement": "PREPARE q1 FROM SELECT * FROM c1"}`},
				{host: "10.0.0.2", reqBody: `{"statement": "PREPARE q1 FROM SELECT * FROM c2"}`},
				{host: "10.0.0.1", reqBody: `{"prepared": "q1"}`},
				{host: "10.0.0.2", reqBody: `{"prepared": "q1"}`},
			},
			expected: []expectation{
				{statement: "SELECT * FROM c1", operation: "PREPARE", namespace: "c1"},
				{statement: "SELECT * FROM c2", operation: "PREPARE", namespace: "c2"},
				{statement: "SELECT * FROM c1", operation: "SELECT", namespace: "c1"},
				{statement: "SELECT * FROM c2", operation: "SELECT", namespace: "c2"},
			},
		},
		{
			name: "server-assigned names resolve on every query node",
			exchanges: []sqlppExchange{
				{
					host:     "10.0.0.1",
					reqBody:  `{"statement": "PREPARE SELECT * FROM c", "auto_execute": true}`,
					respBody: `{"requestID": "r1", "prepared": "srv-name", "results": [], "status": "success"}`,
				},
				{host: "10.0.0.2", reqBody: `{"prepared": "srv-name"}`},
			},
			expected: []expectation{
				{statement: "SELECT * FROM c", operation: "SELECT", namespace: "c"},
				{statement: "SELECT * FROM c", operation: "SELECT", namespace: "c"},
			},
		},
		{
			name: "non-200 prepare response is not cached",
			exchanges: []sqlppExchange{
				{
					status:   http.StatusServiceUnavailable,
					reqBody:  `{"statement": "PREPARE SELECT * FROM c", "auto_execute": true}`,
					respBody: `{"requestID": "r1", "prepared": "srv-name", "errors": [{"code": 1000, "msg": "unavailable"}], "status": "fatal"}`,
				},
				{reqBody: `{"prepared": "srv-name"}`},
			},
			expected: []expectation{
				{statement: "SELECT * FROM c", operation: "SELECT", namespace: "c"},
				{operation: "EXECUTE"},
			},
		},
		{
			name: "unknown EXECUTE statement keeps its text",
			exchanges: []sqlppExchange{
				{reqBody: `{"statement": "EXECUTE q9 USING [1]"}`},
			},
			expected: []expectation{{statement: "EXECUTE q9 USING [1]", operation: "EXECUTE"}},
		},
		{
			name: "named prepare and EXECUTE statement",
			exchanges: []sqlppExchange{
				{reqBody: `{"statement": "PREPARE q1 FROM ` + statement + `"}`},
				{reqBody: "{\"statement\": \"EXECUTE `q1` USING [1]\"}"},
			},
			expected: []expectation{
				{statement: statement, operation: "PREPARE", namespace: "b", collection: "s.c"},
				resolved,
			},
		},
		{
			name: "unknown prepared name is still a SQL++ span",
			exchanges: []sqlppExchange{
				{reqBody: `{"prepared": "unknown", "query_context": "default:b.s"}`},
			},
			expected: []expectation{{operation: "EXECUTE", namespace: "b"}},
		},
		{
			name: "names are scoped by query context",
			exchanges: []sqlppExchange{
				{reqBody: `{"statement": "PREPARE q1 FROM SELECT * FROM c", "query_context": "default:b1.s"}`},
				{reqBody: `{"prepared": "q1", "query_context": "default:b2.s"}`},
				{reqBody: `{"prepared": "q1", "query_context": "default:b1.s"}`},
			},
			expected: []expectation{
				{statement: "SELECT * FROM c", operation: "PREPARE", namespace: "b1", collection: "c"},
				{operation: "EXECUTE", namespace: "b2"},
				{statement: "SELECT * FROM c", operation: "SELECT", namespace: "b1", collection: "c"},
			},
		},
		{
			name: "EXECUTE FUNCTION is a plain statement",
			exchanges: []sqlppExchange{
				{reqBody: `{"statement": "EXECUTE FUNCTION add(1, 2)"}`},
			},
			expected: []expectation{{statement: "EXECUTE FUNCTION add(1, 2)", operation: "query"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prepared := newTestSQLPPPreparedStatements(t)
			for i, ex := range tt.exchanges {
				span, detected := runSQLPPExchange(t, prepared, ex)
				require.True(t, detected, "exchange %d", i)
				assert.Equal(t, request.HTTPSubtypeSQLPP, span.SubType, "exchange %d", i)
				assert.Equal(t, "couchbase", span.DBSystem, "exchange %d", i)
				assert.Equal(t, tt.expected[i].statement, span.Statement, "exchange %d", i)
				assert.Equal(t, tt.expected[i].operation, span.Method, "exchange %d", i)
				assert.Equal(t, tt.expected[i].namespace, span.DBNamespace, "exchange %d", i)
				assert.Equal(t, tt.expected[i].collection, span.Route, "exchange %d", i)
			}
		})
	}
}

func TestSQLPPSpanPreparedWithoutCache(t *testing.T) {
	span, detected := runSQLPPExchange(t, nil, sqlppExchange{reqBody: `{"prepared": "p1"}`})
	require.True(t, detected)
	assert.Equal(t, "EXECUTE", span.Method)
	assert.Empty(t, span.Statement)
}

func TestSQLPPPreparedStatementsEviction(t *testing.T) {
	prepared, err := NewSQLPPPreparedStatements(1)
	require.NoError(t, err)
	prepared.store(sqlppPreparedKey{name: "p1"}, "SELECT 1")
	prepared.store(sqlppPreparedKey{name: "p2"}, "SELECT 2")
	_, ok := prepared.lookup(sqlppPreparedKey{name: "p1"})
	assert.False(t, ok)
	text, ok := prepared.lookup(sqlppPreparedKey{name: "p2"})
	assert.True(t, ok)
	assert.Equal(t, "SELECT 2", text)
}

func TestSQLPPSpanLearnsNameFromTruncatedResponse(t *testing.T) {
	const capturedPrefix = `{"requestID": "r1", "prepared": "srv-name", "results": [{"id": 1}, {"i`
	rawResponse := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json; version=2.0.0-N1QL\r\n" +
		"Content-Length: 4096\r\n\r\n" + capturedPrefix

	req := &http.Request{
		URL:    &url.URL{Path: "/query/service"},
		Header: http.Header{"Content-Type": []string{"application/json"}},
		Body:   io.NopCloser(bytes.NewBufferString(`{"statement": "PREPARE SELECT * FROM c", "auto_execute": true}`)),
	}
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(rawResponse)), req)
	require.NoError(t, err)

	prepared := newTestSQLPPPreparedStatements(t)
	_, detected := SQLPPSpan(&request.Span{}, req, resp, []string{"/query/service"}, prepared)
	require.True(t, detected)

	span, detected := runSQLPPExchange(t, prepared, sqlppExchange{reqBody: `{"prepared": "srv-name"}`})
	require.True(t, detected)
	assert.Equal(t, "SELECT * FROM c", span.Statement)
	assert.Equal(t, "SELECT", span.Method)
}
