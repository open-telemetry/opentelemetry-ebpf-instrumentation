// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestParseElasticsearchRequest(t *testing.T) {
	newRequest := func(method, target, body string) *http.Request {
		return httptest.NewRequest(method, target, strings.NewReader(body))
	}

	tests := []struct {
		name     string
		input    *http.Request
		expected elasticsearchOperation
		wantErr  bool
	}{
		{
			name:  "Valid POST request for a search query",
			input: newRequest(http.MethodPost, "/test_index/_search", `{"query": {"match_all": {}}}`),
			expected: elasticsearchOperation{
				DBQueryText:      "{\"query\": {\"match_all\": {}}}",
				DBCollectionName: "test_index",
			},
			wantErr: false,
		},
		{
			name:  "Valid GET request for a search query",
			input: newRequest(http.MethodGet, "/test_index/_search", `{"query":{"term":{"user.id":"kimchy"}}}`),
			expected: elasticsearchOperation{
				DBQueryText:      "{\"query\":{\"term\":{\"user.id\":\"kimchy\"}}}",
				DBCollectionName: "test_index",
			},
			wantErr: false,
		},
		{
			name:  "Valid GET request for a search query with multiple indexes",
			input: newRequest(http.MethodGet, "/test_index,test_index_two/_search", `{"query":{"match_all":{}}}`),
			expected: elasticsearchOperation{
				DBQueryText:      "{\"query\":{\"match_all\":{}}}",
				DBCollectionName: "test_index,test_index_two",
			},
			wantErr: false,
		},
		{
			name:  "Valid GET request for a search with no query",
			input: newRequest(http.MethodGet, "/test_index/_search?from=40&size=20", ""),
			expected: elasticsearchOperation{
				DBQueryText:      "",
				DBCollectionName: "test_index",
			},
			wantErr: false,
		},
		{
			name:  "Valid Post request with wrong query JSON type",
			input: newRequest(http.MethodPost, "/test_index/_search", `{"query": "not_object"}`),
			expected: elasticsearchOperation{
				DBQueryText:      "{\"query\": \"not_object\"}",
				DBCollectionName: "test_index",
			},
			wantErr: false,
		},
		{
			name:  "Missing index in request URL",
			input: newRequest(http.MethodGet, "/_search", `{"query":{"match_all":{}}}`),
			expected: elasticsearchOperation{
				DBQueryText:      "{\"query\":{\"match_all\":{}}}",
				DBCollectionName: "",
			},
			wantErr: false,
		},
		{
			name: "Valid POST request for a msearch query",
			input: newRequest(http.MethodPost, "/_msearch", `{}
{"query":{"match":{"message":"this is a test"}}}
{"index":"my-index-000002"}
{"query":{"match_all":{}}}
`),
			expected: elasticsearchOperation{
				DBQueryText:      "{}\n{\"query\":{\"match\":{\"message\":\"this is a test\"}}}\n{\"index\":\"my-index-000002\"}\n{\"query\":{\"match_all\":{}}}\n",
				DBCollectionName: "",
			},
			wantErr: false,
		},
		{
			name: "Valid POST request for a bulk operation with one action",
			input: newRequest(http.MethodPost, "/test_index/_bulk", `{"index":{"_index":"aaa","_id":"1"}}
{"field1":"value1"}
{"index":{"_index":"bbb","_id":"2"}}
{"field2":"value2"}
`),
			expected: elasticsearchOperation{
				DBQueryText:      "{\"index\":{\"_index\":\"aaa\",\"_id\":\"1\"}}\n{\"field1\":\"value1\"}\n{\"index\":{\"_index\":\"bbb\",\"_id\":\"2\"}}\n{\"field2\":\"value2\"}\n",
				DBCollectionName: "test_index",
			},
			wantErr: false,
		},
		{
			name:  "Valid GET request for a doc operation",
			input: newRequest(http.MethodGet, "/test_index/_doc/1?stored_fields=tags,counter", ""),
			expected: elasticsearchOperation{
				DBQueryText:      "",
				DBCollectionName: "test_index",
			},
			wantErr: false,
		},
		{
			name:  "Valid POST request for a doc operation",
			input: newRequest(http.MethodPost, "/test_index/_doc/", `{"message":"hello world"}`),
			expected: elasticsearchOperation{
				DBQueryText:      "{\"message\":\"hello world\"}",
				DBCollectionName: "test_index",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, err := parseElasticsearchRequest(tt.input)
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.wantErr {
				if op.DBCollectionName != tt.expected.DBCollectionName {
					t.Errorf("DBCollectionName = %q, want %q", op.DBCollectionName, tt.expected.DBCollectionName)
				}
				if op.DBQueryText != tt.expected.DBQueryText {
					t.Errorf("DBQueryText = %q, want %q", op.DBQueryText, tt.expected.DBQueryText)
				}
			}
		})
	}
}

func TestExtractElasticsearchOperationName(t *testing.T) {
	newRequest := func(method, target string) *http.Request {
		return httptest.NewRequest(method, target, nil)
	}

	tests := []struct {
		name     string
		input    *http.Request
		expected string
		wantErr  bool
	}{
		{
			name:     "Valid _search operation with single index",
			input:    newRequest(http.MethodPost, "/test_index/_search"),
			expected: "search",
			wantErr:  false,
		},
		{
			name:     "Valid _search operation with two indexes",
			input:    newRequest(http.MethodGet, "/test_index,test_index_two/_search"),
			expected: "search",
			wantErr:  false,
		},
		{
			name:     "Valid _search operation with URL parameters",
			input:    newRequest(http.MethodGet, "/test_index/_search?from=40&size=20"),
			expected: "search",
			wantErr:  false,
		},
		{
			name:     "Valid _search operation with missing index in request URL",
			input:    newRequest(http.MethodGet, "/_search"),
			expected: "search",
			wantErr:  false,
		},
		{
			name:     "Valid _msearch operation request for a msearch query",
			input:    newRequest(http.MethodPost, "/_msearch"),
			expected: "msearch",
			wantErr:  false,
		},
		{
			name:     "Valid _bulk operation",
			input:    newRequest(http.MethodPost, "/test_index/_bulk"),
			expected: "bulk",
			wantErr:  false,
		},
		{
			name:     "Valid _doc operation with index and URL parameters",
			input:    newRequest(http.MethodGet, "/test_index/_doc/1?stored_fields=tags,counter"),
			expected: "doc",
			wantErr:  false,
		},
		{
			name:     "Valid _doc operation",
			input:    newRequest(http.MethodPost, "/test_index/_doc/"),
			expected: "doc",
			wantErr:  false,
		},
		{
			name:     "Non supported operation with _",
			input:    newRequest(http.MethodPost, "/test_index/_hello/"),
			expected: "",
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			operationName := extractElasticsearchOperationName(tt.input)

			if operationName != tt.expected {
				t.Errorf("OperationName = %q, want %q", operationName, tt.expected)
			}
		})
	}
}

func TestElasticsearchSpan(t *testing.T) {
	newResponse := func(headers map[string]string) *http.Response {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Set("X-Elastic-Product", "Elasticsearch")
		for k, v := range headers {
			resp.Header.Set(k, v)
		}
		return resp
	}

	tests := []struct {
		name              string
		target            string
		headers           map[string]string
		expectedNamespace string
		expectedNodeName  string
		expectedIndex     string
	}{
		{
			name:   "Elastic Cloud response reports cluster and node",
			target: "/test_index/_search",
			headers: map[string]string{
				"X-Found-Handling-Cluster":  "8b3f5a1c9d2e4f6a",
				"X-Found-Handling-Instance": "instance-0000000001",
			},
			expectedNamespace: "8b3f5a1c9d2e4f6a",
			expectedNodeName:  "instance-0000000001",
			expectedIndex:     "test_index",
		},
		{
			name:              "Elastic Cloud response without an index",
			target:            "/_search",
			headers:           map[string]string{"X-Found-Handling-Cluster": "8b3f5a1c9d2e4f6a"},
			expectedNamespace: "8b3f5a1c9d2e4f6a",
		},
		{
			name:          "self-hosted response reports no cluster",
			target:        "/test_index/_search",
			expectedIndex: "test_index",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.target, strings.NewReader(`{"query":{"match_all":{}}}`))

			span, ok := ElasticsearchSpan(&request.Span{Type: request.EventTypeHTTPClient}, req, newResponse(tt.headers))
			if !ok {
				t.Fatalf("expected an Elasticsearch span")
			}
			if span.SubType != request.HTTPSubtypeElasticsearch {
				t.Errorf("SubType = %d, want %d", span.SubType, request.HTTPSubtypeElasticsearch)
			}
			if span.DBNamespace != tt.expectedNamespace {
				t.Errorf("DBNamespace = %q, want %q", span.DBNamespace, tt.expectedNamespace)
			}
			if span.Elasticsearch.NodeName != tt.expectedNodeName {
				t.Errorf("NodeName = %q, want %q", span.Elasticsearch.NodeName, tt.expectedNodeName)
			}
			if span.Elasticsearch.DBCollectionName != tt.expectedIndex {
				t.Errorf("DBCollectionName = %q, want %q", span.Elasticsearch.DBCollectionName, tt.expectedIndex)
			}
			if span.Elasticsearch.DBOperationName != "search" {
				t.Errorf("DBOperationName = %q, want %q", span.Elasticsearch.DBOperationName, "search")
			}
			if span.Elasticsearch.DBSystemName != "elasticsearch" {
				t.Errorf("DBSystemName = %q, want %q", span.Elasticsearch.DBSystemName, "elasticsearch")
			}
		})
	}
}
