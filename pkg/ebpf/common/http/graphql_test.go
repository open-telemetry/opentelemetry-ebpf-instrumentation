// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestParseGraphQLRequest(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected graphQLOperation
		wantErr  bool
	}{
		{
			name:  "Valid query operation",
			input: []byte(`{"query":"query MyQuery { hello }"}`),
			expected: graphQLOperation{
				Type:     "query",
				Name:     "MyQuery",
				Document: "query MyQuery { hello }",
			},
			wantErr: false,
		},
		{
			name:  "Valid mutation operation",
			input: []byte(`{"mutation":"mutation DoSomething { doSomething }"}`),
			expected: graphQLOperation{
				Type:     "mutation",
				Name:     "DoSomething",
				Document: "mutation DoSomething { doSomething }",
			},
			wantErr: false,
		},
		{
			name:  "Valid subscription operation",
			input: []byte(`{"subscription":"subscription Sub { newData }"}`),
			expected: graphQLOperation{
				Type:     "subscription",
				Name:     "Sub",
				Document: "subscription Sub { newData }",
			},
			wantErr: false,
		},
		{
			name:  "Multiple fields, query preferred",
			input: []byte(`{"query":"{ hello }","mutation":"mutation { doSomething }"}`),
			expected: graphQLOperation{
				Type:     "mutation", // mutation field overwrites query if present
				Name:     "",
				Document: "mutation { doSomething }",
			},
			wantErr: false,
		},
		{
			name:     "Empty JSON body",
			input:    []byte(`{}`),
			expected: graphQLOperation{},
			wantErr:  true,
		},
		{
			name:     "Malformed JSON",
			input:    []byte(`{`),
			expected: graphQLOperation{},
			wantErr:  true,
		},
		{
			name:     "No operation fields",
			input:    []byte(`{"foo":"bar"}`),
			expected: graphQLOperation{},
			wantErr:  true,
		},
		{
			name:     "Invalid GraphQL document",
			input:    []byte(`{"query":"not valid graphql"}`),
			expected: graphQLOperation{},
			wantErr:  true,
		},
		{
			name:  "Valid query with no operation name",
			input: []byte(`{"query":"{ hello }"}`),
			expected: graphQLOperation{
				Type:     "query",
				Name:     "",
				Document: "{ hello }",
			},
			wantErr: false,
		},
		{
			name:  "Valid mutation with no operation name",
			input: []byte(`{"mutation":"mutation { doSomething }"}`),
			expected: graphQLOperation{
				Type:     "mutation",
				Name:     "",
				Document: "mutation { doSomething }",
			},
			wantErr: false,
		},
		{
			name:  "Valid subscription with no operation name",
			input: []byte(`{"subscription":"subscription { newData }"}`),
			expected: graphQLOperation{
				Type:     "subscription",
				Name:     "",
				Document: "subscription { newData }",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, err := parseGraphQLRequest(tt.input)
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.wantErr {
				if op.Type != tt.expected.Type {
					t.Errorf("Type = %q, want %q", op.Type, tt.expected.Type)
				}
				if op.Name != tt.expected.Name {
					t.Errorf("Name = %q, want %q", op.Name, tt.expected.Name)
				}
				if op.Document != tt.expected.Document {
					t.Errorf("Document = %q, want %q", op.Document, tt.expected.Document)
				}
			}
		})
	}
}

func TestGraphQLSpanExtractsOperationMetadata(t *testing.T) {
	const document = `mutation ChangeEmail { updateUser(email: "secret@example.com") { id } }`

	body, err := json.Marshal(graphQLRequest{Query: document})
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://example.com/graphql", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	span, ok := GraphQLSpan(&request.Span{Type: request.EventTypeHTTP}, req, nil)
	if !ok {
		t.Fatal("expected GraphQL span")
	}
	if span.SubType != request.HTTPSubtypeGraphQL {
		t.Fatalf("SubType = %d, want %d", span.SubType, request.HTTPSubtypeGraphQL)
	}
	if span.GraphQL == nil {
		t.Fatal("GraphQL metadata is nil")
	}
	if span.GraphQL.OperationType != "mutation" {
		t.Errorf("OperationType = %q, want mutation", span.GraphQL.OperationType)
	}
	if span.GraphQL.OperationName != "ChangeEmail" {
		t.Errorf("OperationName = %q, want ChangeEmail", span.GraphQL.OperationName)
	}

	restoredBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("failed to read restored body: %v", err)
	}
	if string(restoredBody) != string(body) {
		t.Errorf("restored body = %q, want %q", restoredBody, body)
	}
}
