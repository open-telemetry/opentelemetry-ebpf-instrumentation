// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
				DBQueryText:      "{\"query\":{\"match_all\":{}}}",
				DBOperationName:  "search",
				DBCollectionName: "test_index",
			},
			wantErr: false,
		},
		{
			name:  "Valid GET request for a search query",
			input: newRequest(http.MethodGet, "/test_index/_search", `{"query":{"term":{"user.id":"kimchy"}}}`),
			expected: elasticsearchOperation{
				DBQueryText:      "{\"query\":{\"term\":{\"user.id\":\"kimchy\"}}}",
				DBOperationName:  "search",
				DBCollectionName: "test_index",
			},
			wantErr: false,
		},
		{
			name:  "Valid GET request for a search query with multiple indexes",
			input: newRequest(http.MethodGet, "/test_index,test_index_two/_search", `{"query":{"match_all":{}}}`),
			expected: elasticsearchOperation{
				DBQueryText:      "{\"query\":{\"match_all\":{}}}",
				DBOperationName:  "search",
				DBCollectionName: "test_index,test_index_two",
			},
			wantErr: false,
		},
		{
			name:  "Valid GET request for a search with no query",
			input: newRequest(http.MethodGet, "/test_index/_search?from=40&size=20", ""),
			expected: elasticsearchOperation{
				DBQueryText:      "",
				DBOperationName:  "search",
				DBCollectionName: "test_index",
			},
			wantErr: false,
		},
		{
			name:     "Malformed JSON",
			input:    newRequest(http.MethodGet, "/test_index/_search", `{`),
			expected: elasticsearchOperation{},
			wantErr:  true,
		},
		{
			name:  "Valid Post request with wrong query JSON type",
			input: newRequest(http.MethodPost, "/test_index/_search", `{"query": "not_object"}`),
			expected: elasticsearchOperation{
				DBQueryText:      "{\"query\":\"not_object\"}",
				DBOperationName:  "search",
				DBCollectionName: "test_index",
			},
			wantErr: false,
		},
		{
			name:  "Missing index in request URL",
			input: newRequest(http.MethodGet, "/_search", `{"query":{"match_all":{}}}`),
			expected: elasticsearchOperation{
				DBQueryText:      "{\"query\":{\"match_all\":{}}}",
				DBOperationName:  "search",
				DBCollectionName: "",
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
				if op.DBOperationName != tt.expected.DBOperationName {
					t.Errorf("DBOperationName = %q, want %q", op.DBOperationName, tt.expected.DBOperationName)
				}
				if op.DBQueryText != tt.expected.DBQueryText {
					t.Errorf("DBQueryText = %q, want %q", op.DBQueryText, tt.expected.DBQueryText)
				}
			}
		})
	}
}
