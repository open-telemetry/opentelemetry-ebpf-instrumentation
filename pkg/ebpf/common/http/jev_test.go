// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const jevRequestBody = `{
  "model": "jev-1.13",
  "state": "Order #8814 arrived with a cracked screen. Third time this quarter.",
  "questions": {
    "refund_requested": {
      "type": "noul",
      "instructions": "Is the customer asking for a refund?"
    }
  }
}`

const jevResponseBody = `{
  "id": "dec_24088aa50f8c6c46361f8a2a",
  "model": "jev-1.13-20260917",
  "provider": "jev-ai.org",
  "answers": {
    "refund_requested": {
      "type": "noul",
      "noul": 0.92
    }
  },
  "usage": {
    "input_tokens": 503,
    "output_tokens": 70,
    "charged_tokens": 503
  },
  "latency_ms": 1056
}`

const jevRequestBodyWithObjectState = `{
  "model": "jev-latest",
  "state": {
    "ticket": "I was charged twice. Please refund one charge.",
    "account": {
      "matchingCharges": "two",
      "authenticated": "yes"
    }
  },
  "questions": {
    "is_bug": {
      "type": "noul",
      "instructions": "Is this a bug report?"
    },
    "team": {
      "type": "choice",
      "instructions": "Which team should handle this?",
      "criteria": {
        "billing": "Charges and refunds",
        "technical": "Product errors"
      }
    }
  }
}`

const jevResponseBodyWithChoice = `{
  "id": "dec_1234567890",
  "model": "jev-1.14-20261014",
  "provider": "typesafe",
  "answers": {
    "is_bug": {
      "type": "noul",
      "noul": 0.85
    },
    "team": {
      "type": "choice",
      "choice": "billing",
      "confidence": 0.88,
      "probabilities": {
        "billing": 0.88,
        "technical": 0.12
      }
    }
  },
  "usage": {
    "input_tokens": 312,
    "output_tokens": 48
  }
}`

const jevErrorResponse = `{
  "error": "Invalid request",
  "details": {
    "field": "questions",
    "_errors": ["Field is required"]
  }
}`

const jevTruncatedAnswersResponse = `{
  "id": "dec_123",
  "model": "jev-1.13",
  "answers": {`

func makeJevRequest(t *testing.T, url, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	return req
}

// makeJevSDKRequest builds a request carrying the headers official TypeSafe
// SDKs send on every call, for gateways and hosts that are not typesafe.ai.
func makeJevSDKRequest(t *testing.T, url, body string) *http.Request {
	t.Helper()
	req := makeJevRequest(t, url, body)
	req.Header.Set("X-TypeSafe-SDK", "typesafe-sdk/1.0.0-test")
	req.Header.Set("User-Agent", "typesafe-sdk/1.0.0-test")
	return req
}

func makeJevResponse(headers http.Header, body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     headers,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestJevSpan_BasicRequest(t *testing.T) {
	req := makeJevRequest(t, "https://api.typesafe.ai/api/v1/systemone", jevRequestBody)
	resp := makeJevResponse(http.Header{
		"Content-Type": []string{"application/json"},
	}, jevResponseBody)

	base := &request.Span{}
	base.Path = "/api/v1/systemone"
	span, ok := JevSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.Jev)
	assert.Equal(t, request.HTTPSubtypeJev, span.SubType)

	jev := span.GenAI.Jev
	assert.Equal(t, "dec_24088aa50f8c6c46361f8a2a", jev.ID)
	assert.Equal(t, "jev-1.13-20260917", jev.Model)
	assert.Equal(t, "typesafe", jev.Provider)
	assert.Equal(t, "decision", jev.OperationName)
	assert.Equal(t, 503, tokenValue(jev.Usage.InputTokens))
	assert.Equal(t, 70, tokenValue(jev.Usage.OutputTokens))
	assert.Equal(t, 1056, jev.LatencyMs)

	// Request fields
	assert.Equal(t, "jev-1.13", jev.Request.Model)
	assert.JSONEq(t, `"Order #8814 arrived with a cracked screen. Third time this quarter."`, string(jev.Request.State))
}

func TestJevSpan_OpenRouterPath(t *testing.T) {
	// Gateways are detected through the official SDK headers, not the host.
	req := makeJevSDKRequest(t, "https://openrouter.ai/api/v1/systemone", jevRequestBody)
	resp := makeJevResponse(http.Header{
		"Content-Type": []string{"application/json"},
	}, jevResponseBody)

	base := &request.Span{}
	base.Path = "/api/v1/systemone"
	span, ok := JevSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.Jev)
	assert.Equal(t, request.HTTPSubtypeJev, span.SubType)
}

func TestJevSpan_ChoiceQuestion(t *testing.T) {
	req := makeJevRequest(t, "https://api.typesafe.ai/api/v1/systemone", jevRequestBodyWithObjectState)
	resp := makeJevResponse(http.Header{
		"Content-Type": []string{"application/json"},
	}, jevResponseBodyWithChoice)

	base := &request.Span{}
	base.Path = "/api/v1/systemone"
	span, ok := JevSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.Jev)

	jev := span.GenAI.Jev
	assert.Equal(t, "jev-1.14-20261014", jev.Model)
	assert.Equal(t, "typesafe", jev.Provider)
	assert.Equal(t, 312, tokenValue(jev.Usage.InputTokens))
	assert.Equal(t, 48, tokenValue(jev.Usage.OutputTokens))
}

func TestJevSpan_NotJev(t *testing.T) {
	req := makeJevRequest(t, "https://api.example.com/v1/chat", `{"messages":[{"role":"user","content":"hello"}]}`)
	resp := makeJevResponse(http.Header{
		"Content-Type": []string{"application/json"},
	}, `{"choices":[{"message":{"content":"hi"}}]}`)

	base := &request.Span{}
	_, ok := JevSpan(base, req, resp)

	assert.False(t, ok, "should not be detected as Jev when path and body don't match")
}

func TestJevSpan_MalformedResponseBody(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	resp := makeJevResponse(h, `not-json`)

	req := makeJevRequest(t, "https://api.typesafe.ai/api/v1/systemone", jevRequestBody)
	base := &request.Span{}
	base.Path = "/api/v1/systemone" // Set the path so Jev detection works
	span, ok := JevSpan(base, req, resp)

	// When path matches, Jev should be detected even with malformed response
	// The body read should succeed even if JSON is invalid
	if !ok {
		t.Logf("JevSpan returned false. Path: %s, GenAI: %v", base.Path, span.GenAI)
	}
	require.True(t, ok, "JevSpan should return true when path matches even with malformed response")
	require.NotNil(t, span.GenAI, "GenAI should not be nil")
	require.NotNil(t, span.GenAI.Jev, "Jev should not be nil")
	// but no meaningful fields are populated from the response
	assert.Empty(t, span.GenAI.Jev.ID)
	// request fields should still be populated
	assert.Equal(t, "jev-1.13", span.GenAI.Jev.Request.Model)
	// provider should default to typesafe
	assert.Equal(t, "typesafe", span.GenAI.Jev.Provider)
}

func TestJevSpan_PartialRequestBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://api.typesafe.ai/api/v1/systemone", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(jevRequestBody))

	truncated := jevRequestBody[:len(jevRequestBody)-len(`}`)]
	req.Body = &partialReadCloser{
		data: []byte(truncated),
		err:  io.ErrUnexpectedEOF,
	}

	resp := makeJevResponse(http.Header{
		"Content-Type": []string{"application/json"},
	}, jevResponseBody)
	base := &request.Span{ContentLength: int64(len(jevRequestBody))}
	base.Path = "/api/v1/systemone"
	span, ok := JevSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.Jev)
	assert.Equal(t, "dec_24088aa50f8c6c46361f8a2a", span.GenAI.Jev.ID)
}

func TestJevSpan_PartialResponseBody(t *testing.T) {
	req := makeJevRequest(t, "https://api.typesafe.ai/api/v1/systemone", jevRequestBody)

	truncated := jevResponseBody[:300]
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	resp := makeJevResponse(h, truncated)

	base := &request.Span{}
	base.Path = "/api/v1/systemone"
	span, ok := JevSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.Jev)
	assert.Equal(t, "decision", span.GenAI.Jev.OperationName)
}

func TestJevSpan_NonSystemOnePath(t *testing.T) {
	// Even with SDK headers and a Jev-shaped body, requests outside the
	// System One paths are not classified as Jev.
	req := makeJevSDKRequest(t, "https://api.typesafe.ai/decisions", jevRequestBody)
	resp := makeJevResponse(http.Header{
		"Content-Type": []string{"application/json"},
	}, jevResponseBody)

	base := &request.Span{}
	_, ok := JevSpan(base, req, resp)

	assert.False(t, ok, "should not detect Jev outside the System One paths")
}

func TestJevSpan_ProviderDefault(t *testing.T) {
	// Response without provider field should default to "typesafe"
	respBodyWithoutProvider := `{
  "id": "dec_123",
  "model": "jev-1.13",
  "answers": {"q": {"type": "noul", "noul": 0.5}},
  "usage": {"input_tokens": 100, "output_tokens": 10}
}`

	req := makeJevRequest(t, "https://api.typesafe.ai/api/v1/systemone", jevRequestBody)
	resp := makeJevResponse(http.Header{
		"Content-Type": []string{"application/json"},
	}, respBodyWithoutProvider)

	base := &request.Span{}
	base.Path = "/api/v1/systemone"
	span, ok := JevSpan(base, req, resp)

	require.True(t, ok)
	assert.Equal(t, "typesafe", span.GenAI.Jev.Provider)
}

func TestJevSpan_GetInput(t *testing.T) {
	// String state (simple) - extracted and wrapped directly
	jev := &request.VendorJev{
		Request: request.JevRequest{
			State: json.RawMessage(`"simple text"`),
		},
	}
	assert.JSONEq(t, `[{"role":"user","parts":[{"type":"text","content":"simple text"}]}]`, jev.GetInput())

	// Object state - wrapped as JSON object
	jev2 := &request.VendorJev{
		Request: request.JevRequest{
			State: json.RawMessage(`{"key":"value"}`),
		},
	}
	input := jev2.GetInput()
	assert.Contains(t, input, "user")
	assert.Contains(t, input, "key")

	// State with questions - wrapped as JSON object
	jev3 := &request.VendorJev{
		Request: request.JevRequest{
			State:     json.RawMessage(`"state text"`),
			Questions: json.RawMessage(`{"q1":{"type":"noul"}}`),
		},
	}
	input3 := jev3.GetInput()
	assert.Contains(t, input3, "state")
	assert.Contains(t, input3, "questions")
	assert.Contains(t, input3, "q1")
}

func TestJevSpan_GetOutput(t *testing.T) {
	jev := &request.VendorJev{
		Answers: json.RawMessage(`{"question1":{"type":"noul","noul":0.9}}`),
	}
	// New format wraps answers as an assistant message with typed text parts
	assert.JSONEq(t, `[{"role":"assistant","parts":[{"type":"text","content":"{\"question1\":{\"type\":\"noul\",\"noul\":0.9}}"}]}]`, jev.GetOutput())

	// Empty answers
	jev2 := &request.VendorJev{}
	assert.Empty(t, jev2.GetOutput())
}

func TestJevSpan_TokenCounts(t *testing.T) {
	jev := &request.VendorJev{
		Usage: request.JevUsage{
			InputTokens:  request.NewTokenCount(100),
			OutputTokens: request.NewTokenCount(50),
		},
	}

	inputTokens, reported := jev.InputTokenCount()
	assert.Equal(t, 100, inputTokens)
	assert.True(t, reported)

	outputTokens, reported := jev.OutputTokenCount()
	assert.Equal(t, 50, outputTokens)
	assert.True(t, reported)
}

func TestIsJevHost(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{"exact match", "typesafe.ai", true},
		{"api subdomain", "api.typesafe.ai", true},
		{"multi-level subdomain", "gateway.api.typesafe.ai", true},
		{"mixed case", "TypeSafe.AI", true},
		{"subdomain mixed case", "API.TYPESAFE.AI", true},
		{"with port", "typesafe.ai:443", true},
		{"subdomain with port", "api.typesafe.ai:443", true},
		{"prefix lookalike", "mytypesafe.ai", false},
		{"typesafe.ai.example.com", "typesafe.ai.example.com", false},
		{"jev-ai.org is not the API host", "jev-ai.org", false},
		{"unrelated host", "api.example.com", false},
		{"empty", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "https://"+tc.host+"/api/v1/systemone", nil)
			require.NoError(t, err)
			result := isJevHost(req)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractHostname(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected string
	}{
		{"hostname only", "jev-ai.org", "jev-ai.org"},
		{"hostname with port", "jev-ai.org:443", "jev-ai.org"},
		{"hostname with custom port", "jev-ai.org:8080", "jev-ai.org"},
		{"localhost with port", "localhost:8080", "localhost"},
		{"IP with port", "192.168.1.1:443", "192.168.1.1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "https://"+tc.host+"/path", nil)
			require.NoError(t, err)
			result := extractHostname(req)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIsJevPath(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/api/v1/systemone", true},
		{"/api/v1/systemone/", true},
		{"https://api.typesafe.ai/api/v1/systemone", true},
		{"/v1/systemone", true},
		{"/v1/systemone/", true},
		{"/api/v1/chat", false},
		{"/v1/messages", false},
		{"/systemone", false},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			result := isJevPath(tc.path)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestJevSpan_TruncatedAnswers(t *testing.T) {
	// Test detection when answers field is present but truncated
	req := makeJevSDKRequest(t, "https://api.example.com/api/v1/systemone", jevRequestBody)
	resp := makeJevResponse(http.Header{
		"Content-Type": []string{"application/json"},
	}, jevTruncatedAnswersResponse)

	base := &request.Span{}
	base.Path = "/api/v1/systemone"
	span, ok := JevSpan(base, req, resp)

	require.True(t, ok, "should detect Jev even with truncated answers")
	require.NotNil(t, span.GenAI.Jev)
	assert.Equal(t, "jev-1.13", span.GenAI.Jev.Model)
}

func TestJevSpan_FalsePositivePath(t *testing.T) {
	// Test that unrelated services using /v1/systemone are not classified as Jev
	tests := []struct {
		name     string
		host     string
		sdk      bool
		reqBody  string
		respBody string
		expected bool
	}{
		{
			name:     "unrelated host with matching path and empty body",
			host:     "api.example.com",
			reqBody:  `{}`,
			respBody: `{}`,
			expected: false,
		},
		{
			name:     "unrelated host with matching path and non-Jev payload",
			host:     "api.example.com",
			reqBody:  `{"data":"test"}`,
			respBody: `{"result":"ok"}`,
			expected: false,
		},
		{
			name:     "known Jev host with valid path",
			host:     "api.typesafe.ai",
			reqBody:  jevRequestBody,
			respBody: jevResponseBody,
			expected: true,
		},
		{
			name:     "OpenRouter with SDK headers",
			host:     "openrouter.ai",
			sdk:      true,
			reqBody:  jevRequestBody,
			respBody: jevResponseBody,
			expected: true,
		},
		{
			name:     "gateway without SDK headers or Jev host",
			host:     "gateway.example.com",
			reqBody:  `{"model":"gpt-4","messages":[]}`,
			respBody: `{"choices":[{"message":{"content":"hi"}}]}`,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var req *http.Request
			if tc.sdk {
				req = makeJevSDKRequest(t, "https://"+tc.host+"/api/v1/systemone", tc.reqBody)
			} else {
				req = makeJevRequest(t, "https://"+tc.host+"/api/v1/systemone", tc.reqBody)
			}
			resp := makeJevResponse(http.Header{
				"Content-Type": []string{"application/json"},
			}, tc.respBody)

			base := &request.Span{}
			base.Path = "/api/v1/systemone"
			span, ok := JevSpan(base, req, resp)

			assert.Equal(t, tc.expected, ok, "should match expected detection result")
			if tc.expected {
				assert.NotNil(t, span.GenAI.Jev)
			}
		})
	}
}

func TestJevSpan_ProviderNormalization(t *testing.T) {
	tests := []struct {
		name         string
		respBody     string
		expectedProv string
	}{
		{
			name:         "missing provider",
			respBody:     `{"id":"dec_123","model":"jev-1.13","answers":{}}`,
			expectedProv: "typesafe",
		},
		{
			name:         "jev-ai.org",
			respBody:     `{"id":"dec_123","model":"jev-1.13","provider":"jev-ai.org","answers":{}}`,
			expectedProv: "typesafe",
		},
		{
			name:         "TypeSafe",
			respBody:     `{"id":"dec_123","model":"jev-1.13","provider":"TypeSafe","answers":{}}`,
			expectedProv: "typesafe",
		},
		{
			name:         "arbitrary provider string",
			respBody:     `{"id":"dec_123","model":"jev-1.13","provider":"custom-provider","answers":{}}`,
			expectedProv: "typesafe",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := makeJevRequest(t, "https://api.typesafe.ai/api/v1/systemone", jevRequestBody)
			resp := makeJevResponse(http.Header{
				"Content-Type": []string{"application/json"},
			}, tc.respBody)

			base := &request.Span{}
			base.Path = "/api/v1/systemone"
			span, ok := JevSpan(base, req, resp)

			require.True(t, ok)
			assert.Equal(t, tc.expectedProv, span.GenAI.Jev.Provider)
		})
	}
}

func TestJevSpan_ErrorParsing(t *testing.T) {
	tests := []struct {
		name          string
		respBody      string
		expectedError string
	}{
		{
			name:          "valid Jev error body",
			respBody:      jevErrorResponse,
			expectedError: "Invalid request",
		},
		{
			name:          "error body with truncated response",
			respBody:      `{"error":"rate limit"`,
			expectedError: "rate limit",
		},
		{
			name:          "successful response without error",
			respBody:      jevResponseBody,
			expectedError: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := makeJevRequest(t, "https://api.typesafe.ai/api/v1/systemone", jevRequestBody)
			resp := makeJevResponse(http.Header{
				"Content-Type": []string{"application/json"},
			}, tc.respBody)

			base := &request.Span{}
			base.Path = "/api/v1/systemone"
			span, ok := JevSpan(base, req, resp)

			require.True(t, ok)
			assert.Equal(t, tc.expectedError, span.GenAI.Jev.Error)
		})
	}
}

func TestJevSpan_PartialBodyClassification(t *testing.T) {
	tests := []struct {
		name          string
		reqBody       string
		respBody      string
		expectedModel string
		shouldDetect  bool
	}{
		{
			name:          "truncation inside state",
			reqBody:       `{"model":"jev-1.13","state":"Order #8814 arrived with a cracked","questions":{}}`,
			respBody:      jevResponseBody,
			expectedModel: "jev-1.13-20260917",
			shouldDetect:  true,
		},
		{
			name:          "truncation inside questions",
			reqBody:       `{"model":"jev-1.13","state":"test","questions":{"refund_requested":{"type":"noul"}}`,
			respBody:      jevResponseBody,
			expectedModel: "jev-1.13-20260917",
			shouldDetect:  true,
		},
		{
			name:          "complete model before request truncation",
			reqBody:       `{"model":"jev-1.13","state":"test","questions":{}}`,
			respBody:      jevResponseBody,
			expectedModel: "jev-1.13-20260917",
			shouldDetect:  true,
		},
		{
			name:          "response ID/model before response truncation",
			reqBody:       jevRequestBody,
			respBody:      `{"id":"dec_123","model":"jev-1.13"`,
			expectedModel: "jev-1.13",
			shouldDetect:  true,
		},
		{
			name:          "response read failure with valid request",
			reqBody:       jevRequestBody,
			respBody:      "",
			expectedModel: "jev-1.13",
			shouldDetect:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := makeJevRequest(t, "https://api.typesafe.ai/api/v1/systemone", tc.reqBody)
			resp := makeJevResponse(http.Header{
				"Content-Type": []string{"application/json"},
			}, tc.respBody)

			base := &request.Span{}
			base.Path = "/api/v1/systemone"
			span, ok := JevSpan(base, req, resp)

			assert.Equal(t, tc.shouldDetect, ok)
			if tc.shouldDetect && ok {
				assert.NotNil(t, span.GenAI.Jev)
				if span.GenAI.Jev != nil {
					assert.Equal(t, tc.expectedModel, span.GenAI.Jev.Model)
				}
			}
		})
	}
}

func TestJevSpan_FailedGatewayRequests(t *testing.T) {
	tests := []struct {
		name          string
		host          string
		sdk           bool
		reqBody       string
		respBody      string
		expectedError string
		shouldDetect  bool
	}{
		{
			name:          "gateway error with Jev model",
			host:          "openrouter.ai",
			sdk:           true,
			reqBody:       jevRequestBody,
			respBody:      `{"model":"jev-1.13","error":"rate limit"}`,
			expectedError: "rate limit",
			shouldDetect:  true,
		},
		{
			name:          "SDK request with truncated error response",
			host:          "openrouter.ai",
			sdk:           true,
			reqBody:       `{"model":"gpt-4","state":"test","questions":{}}`,
			respBody:      `{"error":"rat`,
			expectedError: "",
			shouldDetect:  true,
		},
		{
			name:          "generic gateway error with unrelated request model",
			host:          "api.example.com",
			reqBody:       `{"model":"gpt-4","messages":[]}`,
			respBody:      `{"error":"Invalid request"}`,
			expectedError: "",
			shouldDetect:  false,
		},
		{
			name:          "ordinary API request to /v1/systemone without Jev metadata",
			host:          "api.example.com",
			reqBody:       `{"data":"test"}`,
			respBody:      `{"result":"ok"}`,
			expectedError: "",
			shouldDetect:  false,
		},
		{
			name:          "known Jev host error response without model",
			host:          "api.typesafe.ai",
			reqBody:       jevRequestBody,
			respBody:      `{"error":"rate limit"}`,
			expectedError: "rate limit",
			shouldDetect:  true,
		},
		{
			name:          "response unavailable after Jev request",
			host:          "api.typesafe.ai",
			reqBody:       jevRequestBody,
			respBody:      "",
			expectedError: "",
			shouldDetect:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var req *http.Request
			if tc.sdk {
				req = makeJevSDKRequest(t, "https://"+tc.host+"/api/v1/systemone", tc.reqBody)
			} else {
				req = makeJevRequest(t, "https://"+tc.host+"/api/v1/systemone", tc.reqBody)
			}
			resp := makeJevResponse(http.Header{
				"Content-Type": []string{"application/json"},
			}, tc.respBody)

			base := &request.Span{}
			base.Path = "/api/v1/systemone"
			span, ok := JevSpan(base, req, resp)

			assert.Equal(t, tc.shouldDetect, ok)
			if tc.shouldDetect && ok {
				assert.NotNil(t, span.GenAI.Jev)
				if span.GenAI.Jev != nil {
					assert.Equal(t, tc.expectedError, span.GenAI.Jev.Error)
				}
			}
		})
	}
}

func TestJevSpan_ModelDiscriminator(t *testing.T) {
	tests := []struct {
		name        string
		requestBody string
		response    *http.Response
		path        string
		host        string
		want        bool
		wantModel   string
	}{
		{
			name: "non-Jev_request_model_with_error_response",
			requestBody: `{
				"model": "gpt-4",
				"state": "draft",
				"questions": []
			}`,
			response: &http.Response{
				Body: io.NopCloser(strings.NewReader(`{"error": "validation failed"}`)),
			},
			path: "/api/v1/systemone",
			host: "api.example.com",
			want: false,
		},
		{
			name: "Jev_request_model_with_error_response",
			requestBody: `{
				"model": "jev-1.13",
				"state": "Order #8814 arrived with a cracked screen",
				"questions": {"refund_requested": {"type": "noul"}}
			}`,
			response: &http.Response{
				Body: io.NopCloser(strings.NewReader(`{"error": "rate limit"}`)),
			},
			path:      "/api/v1/systemone",
			host:      "api.typesafe.ai",
			want:      true,
			wantModel: "", // Error responses don't preserve model in current implementation
		},
		{
			name: "non-Jev_request_model_without_response_model",
			requestBody: `{
				"model": "gpt-4",
				"state": "draft",
				"questions": []
			}`,
			response: &http.Response{
				Body: io.NopCloser(strings.NewReader(`{"answers": {}}`)),
			},
			path: "/api/v1/systemone",
			host: "api.example.com",
			want: false,
		},
		{
			name: "Jev_response_model_with_valid_answers",
			requestBody: `{
				"model": "jev-1.13",
				"state": "Order #8814 arrived with a cracked screen",
				"questions": {"refund_requested": {"type": "noul"}}
			}`,
			response: &http.Response{
				Body: io.NopCloser(strings.NewReader(jevResponseBody)),
			},
			path:      "/api/v1/systemone",
			host:      "api.typesafe.ai",
			want:      true,
			wantModel: "jev-1.13-20260917",
		},
		{
			name: "missing_request_model_with_error_response",
			requestBody: `{
				"state": "draft",
				"questions": []
			}`,
			response: &http.Response{
				Body: io.NopCloser(strings.NewReader(`{"error": "validation failed"}`)),
			},
			path: "/api/v1/systemone",
			host: "api.example.com",
			want: false,
		},
		{
			name: "Jev_gateway_error_with_request_model_fallback",
			requestBody: `{
				"model": "jev-1.13",
				"state": "Order #8814 arrived with a cracked screen",
				"questions": {"refund_requested": {"type": "noul"}}
			}`,
			response: &http.Response{
				Body: io.NopCloser(strings.NewReader(`{"error": "rate limit"}`)),
			},
			path:      "/api/v1/systemone",
			host:      "api.typesafe.ai",
			want:      true,
			wantModel: "", // Error responses don't preserve model in current implementation
		},
		{
			name: "non-Jev_gateway_error_with_Jev_path",
			requestBody: `{
				"model": "gpt-4",
				"state": "draft",
				"questions": []
			}`,
			response: &http.Response{
				Body: io.NopCloser(strings.NewReader(`{"error": "rate limit"}`)),
			},
			path: "/api/v1/systemone",
			host: "api.example.com",
			want: false, // No TypeSafe metadata - should not detect
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Method: http.MethodPost,
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
				Body: io.NopCloser(strings.NewReader(tt.requestBody)),
				Host: tt.host,
				URL:  &url.URL{Path: tt.path},
			}
			baseSpan := &request.Span{
				Path: tt.path,
			}

			got, ok := JevSpan(baseSpan, req, tt.response)
			assert.Equal(t, tt.want, ok)

			if tt.want {
				assert.NotNil(t, got.GenAI)
				assert.NotNil(t, got.GenAI.Jev)
				if tt.wantModel != "" {
					assert.Equal(t, tt.wantModel, got.GenAI.Jev.Model)
				}
			}
		})
	}
}

func TestJevSpan_TruncatedRequestDetection(t *testing.T) {
	tests := []struct {
		name          string
		host          string
		reqBody       string
		respBody      string
		shouldDetect  bool
		expectedModel string
	}{
		{
			name:          "truncated_request_with_state_and_questions",
			host:          "api.typesafe.ai",
			reqBody:       `{"model":"jev-1.13","state":"test","questions":{}}`,
			respBody:      jevResponseBody,
			shouldDetect:  true,
			expectedModel: "jev-1.13-20260917",
		},
		{
			name:         "truncated_request_before_state",
			host:         "api.typesafe.ai",
			reqBody:      `{"model":"jev-1.13"`,
			respBody:     jevResponseBody,
			shouldDetect: true,
		},
		{
			name:         "truncated_request_with_state_only",
			host:         "api.typesafe.ai",
			reqBody:      `{"model":"jev-1.13","state":"test"`,
			respBody:     jevResponseBody,
			shouldDetect: true,
		},
		{
			name:         "json_string_containing_state_keyword",
			host:         "api.example.com",
			reqBody:      `{"model":"gpt-4","messages":"this has state in it"}`,
			respBody:     `{"error":"invalid"}`,
			shouldDetect: false,
		},
		{
			name:         "nested_field_with_state",
			host:         "api.example.com",
			reqBody:      `{"model":"gpt-4","data":{"state":"nested"}}`,
			respBody:     `{"error":"invalid"}`,
			shouldDetect: false,
		},
		{
			name:         "malformed_json_request",
			host:         "api.typesafe.ai",
			reqBody:      `{"model":"jev-1.13","state":`,
			respBody:     jevResponseBody,
			shouldDetect: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := makeJevRequest(t, "https://"+tc.host+"/api/v1/systemone", tc.reqBody)
			resp := makeJevResponse(http.Header{
				"Content-Type": []string{"application/json"},
			}, tc.respBody)

			base := &request.Span{}
			base.Path = "/api/v1/systemone"
			span, ok := JevSpan(base, req, resp)

			assert.Equal(t, tc.shouldDetect, ok)
			if tc.shouldDetect && ok {
				assert.NotNil(t, span.GenAI.Jev)
				if tc.expectedModel != "" {
					assert.Equal(t, tc.expectedModel, span.GenAI.Jev.Model)
				}
			}
		})
	}
}

func TestJevSpan_EmptyResponseHandling(t *testing.T) {
	tests := []struct {
		name          string
		host          string
		reqBody       string
		respBody      string
		respReadError bool
		shouldDetect  bool
		expectedModel string
	}{
		{
			name:          "empty_response_with_valid_jev_request",
			host:          "api.typesafe.ai",
			reqBody:       jevRequestBody,
			respBody:      "",
			respReadError: true,
			shouldDetect:  true,
			expectedModel: "jev-1.13",
		},
		{
			name:          "empty_response_with_non_jev_model",
			host:          "api.typesafe.ai",
			reqBody:       `{"model":"gpt-4","state":"test","questions":{}}`,
			respBody:      "",
			respReadError: true,
			shouldDetect:  true,
		},
		{
			name:          "empty_response_with_missing_request_model",
			host:          "api.typesafe.ai",
			reqBody:       `{"state":"test","questions":{}}`,
			respBody:      "",
			respReadError: true,
			shouldDetect:  true,
		},
		{
			name:          "error_response_without_model",
			host:          "api.typesafe.ai",
			reqBody:       jevRequestBody,
			respBody:      `{"error":"rate limit"}`,
			respReadError: false,
			shouldDetect:  true,
			expectedModel: "jev-1.13",
		},
		{
			name:          "normal_successful_response",
			host:          "api.typesafe.ai",
			reqBody:       jevRequestBody,
			respBody:      jevResponseBody,
			respReadError: false,
			shouldDetect:  true,
			expectedModel: "jev-1.13-20260917",
		},
		{
			name:          "unrelated_http_request",
			host:          "api.example.com",
			reqBody:       `{"data":"test"}`,
			respBody:      `{"result":"ok"}`,
			respReadError: false,
			shouldDetect:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := makeJevRequest(t, "https://"+tc.host+"/api/v1/systemone", tc.reqBody)
			resp := makeJevResponse(http.Header{
				"Content-Type": []string{"application/json"},
			}, tc.respBody)

			base := &request.Span{}
			base.Path = "/api/v1/systemone"
			span, ok := JevSpan(base, req, resp)

			assert.Equal(t, tc.shouldDetect, ok)
			if tc.shouldDetect && ok {
				assert.NotNil(t, span.GenAI.Jev)
				if tc.expectedModel != "" {
					assert.Equal(t, tc.expectedModel, span.GenAI.Jev.Model)
				}
			}
		})
	}
}

func TestHasTypeSafeAgent(t *testing.T) {
	tests := []struct {
		name      string
		sdkHeader string
		userAgent string
		expected  bool
	}{
		{"X-TypeSafe-SDK official value", "typesafe-sdk/1.2.3", "", true},
		{"X-TypeSafe-SDK community Go SDK", "typesafe-sdk-go/0.4.0", "", true},
		{"User-Agent only", "", "typesafe-sdk/0.9.1", true},
		{"header value case-insensitive", "TypeSafe-SDK/1.0.0", "", true},
		{"unrelated X-TypeSafe-SDK value", "other-sdk/1.0", "", false},
		{"X-TypeSafe-Runtime is not a marker", "", "", false},
		{"unrelated user agent", "", "python-requests/2.32.3", false},
		{"empty headers", "", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := makeJevRequest(t, "https://openrouter.ai/api/v1/systemone", jevRequestBody)
			if tc.sdkHeader != "" {
				req.Header.Set("X-TypeSafe-SDK", tc.sdkHeader)
			}
			if tc.userAgent != "" {
				req.Header.Set("User-Agent", tc.userAgent)
			}
			assert.Equal(t, tc.expected, hasTypeSafeAgent(req))
		})
	}
}

func TestJevSpan_MetadataGate(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		host    string
		headers map[string]string
		want    bool
	}{
		{
			name: "SDK header on gateway host",
			path: "/api/v1/systemone",
			host: "openrouter.ai",
			headers: map[string]string{
				"X-TypeSafe-SDK": "typesafe-sdk/1.0.0",
			},
			want: true,
		},
		{
			name: "User-Agent only on gateway host",
			path: "/v1/systemone",
			host: "inference.do-ai.run",
			headers: map[string]string{
				"User-Agent": "typesafe-sdk/1.0.0",
			},
			want: true,
		},
		{
			name: "typesafe.ai host without SDK headers",
			path: "/v1/systemone",
			host: "api.typesafe.ai",
			want: true,
		},
		{
			name: "SDK header but non-systemone path",
			path: "/v1/models",
			host: "api.typesafe.ai",
			headers: map[string]string{
				"X-TypeSafe-SDK": "typesafe-sdk/1.0.0",
			},
			want: false,
		},
		{
			name: "typesafe.ai host but unrelated path",
			path: "/v1/chat",
			host: "api.typesafe.ai",
			want: false,
		},
		{
			name: "unrelated host without SDK headers",
			path: "/api/v1/systemone",
			host: "api.example.com",
			want: false,
		},
		{
			name: "unrelated SDK-like header value",
			path: "/api/v1/systemone",
			host: "api.example.com",
			headers: map[string]string{
				"X-TypeSafe-SDK": "not-typesafe/9.9",
			},
			want: false,
		},
		{
			name: "empty body still detected via metadata",
			path: "/v1/systemone",
			host: "openrouter.ai",
			headers: map[string]string{
				"X-TypeSafe-SDK": "typesafe-sdk/1.0.0",
			},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := jevRequestBody
			if tc.name == "empty body still detected via metadata" {
				body = ""
			}
			req := makeJevRequest(t, "https://"+tc.host+tc.path, body)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			resp := makeJevResponse(http.Header{
				"Content-Type": []string{"application/json"},
			}, jevResponseBody)

			base := &request.Span{}
			base.Path = tc.path
			span, ok := JevSpan(base, req, resp)

			assert.Equal(t, tc.want, ok)
			if tc.want {
				require.NotNil(t, span.GenAI.Jev)
			}
		})
	}
}
