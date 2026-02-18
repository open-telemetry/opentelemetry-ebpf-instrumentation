// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
			resultSpan, detected := SQLPPSpan(baseSpan, req, resp, endpointPatterns)

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
			resp := &http.Response{
				Body: io.NopCloser(bytes.NewBufferString(tt.respBody)),
			}

			result := parseSQLPPResponse(resp)

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
	resultSpan, detected := SQLPPSpan(baseSpan, req, resp, endpointPatterns)

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
