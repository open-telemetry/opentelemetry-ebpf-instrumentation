// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func tocstr(s string) []byte {
	b := []byte(s)
	return append(b, 0)
}

func makeHTTPRequestTrace(
	method, path string,
	status uint16,
	contentLength, responseLength int64,
	durationMs uint64,
) HTTPRequestTrace {
	m := [7]uint8{}
	copy(m[:], tocstr(method))
	p := [100]uint8{}
	copy(p[:], tocstr(path))

	return HTTPRequestTrace{
		Type:              1, // transform.EventTypeHTTP
		Method:            m,
		Path:              p,
		Status:            status,
		ContentLength:     contentLength,
		ResponseLength:    responseLength,
		GoStartMonotimeNs: 0,
		StartMonotimeNs:   durationMs * 1000000,
		EndMonotimeNs:     durationMs * 2 * 1000000,
	}
}

func makeGRPCRequestTrace(path string, status uint16, durationMs uint64) HTTPRequestTrace {
	p := [100]uint8{}
	copy(p[:], tocstr(path))

	return HTTPRequestTrace{
		Type:              2, // transform.EventTypeGRPC
		Path:              p,
		Status:            status,
		GoStartMonotimeNs: 0,
		StartMonotimeNs:   durationMs * 1000000,
		EndMonotimeNs:     durationMs * 2 * 1000000,
	}
}

func assertMatches(
	t *testing.T,
	span *request.Span,
	method, path string,
	contentLength, responseLength int64,
	status int,
	durationMs uint64,
) {
	assert.Equal(t, method, span.Method)
	assert.Equal(t, path, span.Path)
	assert.Equal(t, path, span.FullPath)
	assert.Equal(t, status, span.Status)
	assert.Equal(t, contentLength, span.ContentLength)
	assert.Equal(t, responseLength, span.ResponseLength)
	assert.Equal(t, int64(durationMs*1000000), span.End-span.Start)
	assert.Equal(t, int64(durationMs*1000000), span.Start-span.RequestStart)
}

func TestRequestTraceParsing(t *testing.T) {
	t.Run("Test basic parsing", func(t *testing.T) {
		tr := makeHTTPRequestTrace("POST", "/users", 200, 1024, 2048, 5)
		s := HTTPRequestTraceToSpan(&tr)
		assertMatches(t, &s, "POST", "/users", 1024, 2048, 200, 5)
	})

	t.Run("Test with empty path, missing peer host and empty response body size", func(t *testing.T) {
		tr := makeHTTPRequestTrace("GET", "", 403, 1024, 0, 6)
		s := HTTPRequestTraceToSpan(&tr)
		assertMatches(t, &s, "GET", "", 1024, 0, 403, 6)
	})

	t.Run("Test with missing peer port and empty content length", func(t *testing.T) {
		tr := makeHTTPRequestTrace("GET", "/posts/1/1", 500, 0, 2048, 1)
		s := HTTPRequestTraceToSpan(&tr)
		assertMatches(t, &s, "GET", "/posts/1/1", 0, 2048, 500, 1)
	})

	t.Run("Test with invalid peer port", func(t *testing.T) {
		tr := makeHTTPRequestTrace("GET", "/posts/1/1", 500, 1024, 2048, 1)
		s := HTTPRequestTraceToSpan(&tr)
		assertMatches(t, &s, "GET", "/posts/1/1", 1024, 2048, 500, 1)
	})

	t.Run("Test with GRPC request", func(t *testing.T) {
		tr := makeGRPCRequestTrace("/posts/1/1", 2, 1)
		s := HTTPRequestTraceToSpan(&tr)
		assertMatches(t, &s, "", "/posts/1/1", 0, 0, 2, 1)
	})
}

func makeSpanWithTimings(goStart, start, end uint64) request.Span {
	tr := HTTPRequestTrace{
		Type:              1,
		Path:              [100]uint8{},
		Status:            0,
		GoStartMonotimeNs: goStart,
		StartMonotimeNs:   start,
		EndMonotimeNs:     end,
	}

	return HTTPRequestTraceToSpan(&tr)
}

func TestSpanNesting(t *testing.T) {
	a := makeSpanWithTimings(10000, 20000, 30000)
	b := makeSpanWithTimings(10000, 30000, 40000)
	assert.True(t, (&a).Inside(&b))
	a = makeSpanWithTimings(10000, 20000, 30000)
	b = makeSpanWithTimings(10000, 30000, 30000)
	assert.True(t, (&a).Inside(&b))
	a = makeSpanWithTimings(11000, 11000, 30000)
	b = makeSpanWithTimings(10000, 30000, 30000)
	assert.True(t, (&a).Inside(&b))
	a = makeSpanWithTimings(11000, 11000, 30001)
	b = makeSpanWithTimings(10000, 30000, 30000)
	assert.False(t, (&a).Inside(&b))
	a = makeSpanWithTimings(9999, 11000, 19999)
	b = makeSpanWithTimings(10000, 30000, 30000)
	assert.False(t, (&a).Inside(&b))
}

func Test_EmptyHostInfo(t *testing.T) {
	tr := HTTPRequestTrace{}
	src, dest := (*BPFConnInfo)(&tr.Conn).reqHostInfo()

	assert.Empty(t, src)
	assert.Empty(t, dest)
}

func makeSQLRequestTrace(sql string, subType uint8, dPort uint16, hostname string) SQLRequestTrace {
	s := [500]uint8{}
	copy(s[:], tocstr(sql))
	h := [96]uint8{}
	copy(h[:], tocstr(hostname))

	return SQLRequestTrace{
		Type:     5, // EventTypeSQLClient
		SubType:  subType,
		Sql:      s,
		Hostname: h,
		Conn: BpfConnectionInfoT{
			D_port: dPort,
		},
	}
}

func TestSQLRequestTraceToSpan(t *testing.T) {
	t.Run("returns empty span for wrong event type", func(t *testing.T) {
		tr := makeSQLRequestTrace("SELECT 1", uint8(request.DBPostgres), 5432, "")
		tr.Type = 1
		span := SQLRequestTraceToSpan(&tr)
		assert.Equal(t, request.Span{}, span)
	})

	t.Run("uses trace SubType when already detected", func(t *testing.T) {
		tr := makeSQLRequestTrace("SELECT id FROM users", uint8(request.DBPostgres), 5432, "db:5432")
		span := SQLRequestTraceToSpan(&tr)
		assert.Equal(t, int(request.DBPostgres), span.SubType)
	})

	t.Run("trace SubType wins over port heuristic", func(t *testing.T) {
		tr := makeSQLRequestTrace("SELECT id FROM users", uint8(request.DBMySQL), 5432, "")
		span := SQLRequestTraceToSpan(&tr)
		assert.Equal(t, int(request.DBMySQL), span.SubType)
	})

	t.Run("falls back to postgres when SubType is generic and port is 5432", func(t *testing.T) {
		tr := makeSQLRequestTrace("SELECT id FROM users", uint8(request.DBGeneric), 5432, "")
		span := SQLRequestTraceToSpan(&tr)
		assert.Equal(t, int(request.DBPostgres), span.SubType)
	})

	t.Run("falls back to mysql when SubType is generic and port is 3306", func(t *testing.T) {
		tr := makeSQLRequestTrace("SELECT id FROM users", uint8(request.DBGeneric), 3306, "")
		span := SQLRequestTraceToSpan(&tr)
		assert.Equal(t, int(request.DBMySQL), span.SubType)
	})

	t.Run("falls back to mssql when SubType is generic and port is 1434", func(t *testing.T) {
		tr := makeSQLRequestTrace("SELECT id FROM users", uint8(request.DBGeneric), 1434, "")
		span := SQLRequestTraceToSpan(&tr)
		assert.Equal(t, int(request.DBMSSQL), span.SubType)
	})

	t.Run("stays generic when SubType is generic and port is unknown", func(t *testing.T) {
		tr := makeSQLRequestTrace("SELECT id FROM users", uint8(request.DBGeneric), 9999, "")
		span := SQLRequestTraceToSpan(&tr)
		assert.Equal(t, int(request.DBGeneric), span.SubType)
	})

	t.Run("stays generic when SubType is generic and port is zero", func(t *testing.T) {
		tr := makeSQLRequestTrace("SELECT id FROM users", uint8(request.DBGeneric), 0, "")
		span := SQLRequestTraceToSpan(&tr)
		assert.Equal(t, int(request.DBGeneric), span.SubType)
	})

	t.Run("strips port from hostname", func(t *testing.T) {
		tr := makeSQLRequestTrace("SELECT 1", uint8(request.DBGeneric), 0, "db-host:5432")
		span := SQLRequestTraceToSpan(&tr)
		assert.Equal(t, "db-host", span.HostName)
	})

	t.Run("hostname without colon is kept", func(t *testing.T) {
		tr := makeSQLRequestTrace("SELECT 1", uint8(request.DBGeneric), 0, "db-host")
		span := SQLRequestTraceToSpan(&tr)
		assert.Equal(t, "db-host", span.HostName)
	})

	t.Run("sets timing fields", func(t *testing.T) {
		tr := makeSQLRequestTrace("SELECT 1", uint8(request.DBGeneric), 0, "")
		tr.StartMonotimeNs = 100
		tr.EndMonotimeNs = 200
		span := SQLRequestTraceToSpan(&tr)
		assert.Equal(t, int64(100), span.RequestStart)
		assert.Equal(t, int64(100), span.Start)
		assert.Equal(t, int64(200), span.End)
	})

	t.Run("sets connection peer and host ports", func(t *testing.T) {
		tr := makeSQLRequestTrace("SELECT 1", uint8(request.DBPostgres), 5432, "")
		tr.Conn.S_port = 45678
		span := SQLRequestTraceToSpan(&tr)
		assert.Equal(t, 45678, span.PeerPort)
		assert.Equal(t, 5432, span.HostPort)
	})

	t.Run("sets statement from sql", func(t *testing.T) {
		tr := makeSQLRequestTrace("INSERT INTO t VALUES (1)", uint8(request.DBGeneric), 0, "")
		span := SQLRequestTraceToSpan(&tr)
		assert.Equal(t, "INSERT INTO t VALUES (1)", span.Statement)
	})
}

func TestStripPattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "already starts with slash",
			input:    "/api/users",
			expected: "/api/users",
		},
		{
			name:     "GET prefix",
			input:    "GET /api/users",
			expected: "/api/users",
		},
		{
			name:     "POST prefix",
			input:    "POST /api/users",
			expected: "/api/users",
		},
		{
			name:     "PUT prefix",
			input:    "PUT /api/users",
			expected: "/api/users",
		},
		{
			name:     "PATCH prefix",
			input:    "PATCH /api/users",
			expected: "/api/users",
		},
		{
			name:     "DELETE prefix",
			input:    "DELETE /api/users",
			expected: "/api/users",
		},
		{
			name:     "OPTIONS prefix",
			input:    "OPTIONS /api/users",
			expected: "/api/users",
		},
		{
			name:     "HEAD prefix",
			input:    "HEAD /api/users",
			expected: "/api/users",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "no prefix no slash",
			input:    "api/users",
			expected: "",
		},
		{
			name:     "root path",
			input:    "/",
			expected: "/",
		},
		{
			name:     "GET with root path",
			input:    "GET /",
			expected: "/",
		},
		{
			name:     "method without trailing space (not matched)",
			input:    "GET/api/users",
			expected: "",
		},
		{
			name:     "lowercase method (not matched)",
			input:    "get /api/users",
			expected: "",
		},
		{
			name:     "path with parameters",
			input:    "GET /api/users/:id",
			expected: "/api/users/:id",
		},
		{
			name:     "path with wildcard",
			input:    "POST /api/files/*path",
			expected: "/api/files/*path",
		},
		{
			name:     "nonsense",
			input:    "THIS IS A TEST",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripPattern(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
