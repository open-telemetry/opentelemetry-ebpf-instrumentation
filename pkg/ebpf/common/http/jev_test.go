// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/json"
	"io"
	"net/http"
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

func makeJevRequest(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func makeJevResponse(statusCode int, headers http.Header, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Header:     headers,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestJevSpan_BasicRequest(t *testing.T) {
	req := makeJevRequest(t, http.MethodPost, "https://jev-ai.org/api/v1/systemone", jevRequestBody)
	resp := makeJevResponse(http.StatusOK, http.Header{
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
	req := makeJevRequest(t, http.MethodPost, "https://openrouter.ai/api/v1/systemone", jevRequestBody)
	resp := makeJevResponse(http.StatusOK, http.Header{
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
	req := makeJevRequest(t, http.MethodPost, "https://jev-ai.org/api/v1/systemone", jevRequestBodyWithObjectState)
	resp := makeJevResponse(http.StatusOK, http.Header{
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
	req := makeJevRequest(t, http.MethodPost, "https://api.example.com/v1/chat", `{"messages":[{"role":"user","content":"hello"}]}`)
	resp := makeJevResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, `{"choices":[{"message":{"content":"hi"}}]}`)

	base := &request.Span{}
	_, ok := JevSpan(base, req, resp)

	assert.False(t, ok, "should not be detected as Jev when path and body don't match")
}

func TestJevSpan_MalformedResponseBody(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	resp := makeJevResponse(http.StatusOK, h, `not-json`)

	req := makeJevRequest(t, http.MethodPost, "https://jev-ai.org/api/v1/systemone", jevRequestBody)
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
	req, err := http.NewRequest(http.MethodPost, "https://jev-ai.org/api/v1/systemone", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(jevRequestBody))

	truncated := jevRequestBody[:len(jevRequestBody)-len(`}`)]
	req.Body = &partialReadCloser{
		data: []byte(truncated),
		err:  io.ErrUnexpectedEOF,
	}

	resp := makeJevResponse(http.StatusOK, http.Header{
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
	req := makeJevRequest(t, http.MethodPost, "https://jev-ai.org/api/v1/systemone", jevRequestBody)

	truncated := jevResponseBody[:300]
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	resp := makeJevResponse(http.StatusOK, h, truncated)

	base := &request.Span{}
	base.Path = "/api/v1/systemone"
	span, ok := JevSpan(base, req, resp)

	require.True(t, ok)
	require.NotNil(t, span.GenAI.Jev)
	assert.Equal(t, "decision", span.GenAI.Jev.OperationName)
}

func TestJevSpan_DetectionByBodyOnly(t *testing.T) {
	// Test detection when path doesn't match but body does
	req := makeJevRequest(t, http.MethodPost, "https://api.example.com/decisions", jevRequestBody)
	resp := makeJevResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, jevResponseBody)

	base := &request.Span{}
	span, ok := JevSpan(base, req, resp)

	require.True(t, ok, "should detect Jev by body even with non-standard path")
	require.NotNil(t, span.GenAI.Jev)
}

func TestJevSpan_ProviderDefault(t *testing.T) {
	// Response without provider field should default to "typesafe"
	respBodyWithoutProvider := `{
  "id": "dec_123",
  "model": "jev-1.13",
  "answers": {"q": {"type": "noul", "noul": 0.5}},
  "usage": {"input_tokens": 100, "output_tokens": 10}
}`

	req := makeJevRequest(t, http.MethodPost, "https://jev-ai.org/api/v1/systemone", jevRequestBody)
	resp := makeJevResponse(http.StatusOK, http.Header{
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

func TestHasJSONKey(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		key      string
		expected bool
	}{
		{
			name:     "simple key with value",
			data:     `{"answers":{}}`,
			key:      "answers",
			expected: true,
		},
		{
			name:     "key with whitespace before colon",
			data:     `{"answers" : {}}`,
			key:      "answers",
			expected: true,
		},
		{
			name:     "nested key should not match",
			data:     `{"metadata":{"answers":{}}}`,
			key:      "answers",
			expected: false,
		},
		{
			name:     "key inside string value should not match",
			data:     `{"message":"answers are here"}`,
			key:      "answers",
			expected: false,
		},
		{
			name:     "escaped quotes in string",
			data:     `{"message":"\"answers\" quoted"}`,
			key:      "answers",
			expected: false,
		},
		{
			name:     "truncated after key with whitespace",
			data:     `{"answers" `,
			key:      "answers",
			expected: false,
		},
		{
			name:     "truncated at key with whitespace before colon",
			data:     `{"answers" :`,
			key:      "answers",
			expected: true,
		},
		{
			name:     "similar key should not match",
			data:     `{"answers_extra":{}}`,
			key:      "answers",
			expected: false,
		},
		{
			name:     "key with trailing whitespace and colon",
			data:     `{"answers"   :{}}`,
			key:      "answers",
			expected: true,
		},
		{
			name:     "key with newline before colon",
			data:     `{"answers"\n:{}}`,
			key:      "answers",
			expected: true,
		},
		{
			name:     "empty data",
			data:     ``,
			key:      "answers",
			expected: false,
		},
		{
			name:     "key not present",
			data:     `{"other":{}}`,
			key:      "answers",
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := hasJSONKey([]byte(tc.data), tc.key)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestJevSpan_GetOutput(t *testing.T) {
	jev := &request.VendorJev{
		Answers: json.RawMessage(`{"question1":{"type":"noul","noul":0.9}}`),
	}
	// New format wraps answers as an assistant message with typed text parts
	assert.JSONEq(t, `[{"role":"assistant","parts":[{"type":"text","content":"{\"question1\":{\"type\":\"noul\",\"noul\":0.9}}"}]}]`, jev.GetOutput())

	// Empty answers
	jev2 := &request.VendorJev{}
	assert.Equal(t, "", jev2.GetOutput())
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

func TestLooksLikeJevBody(t *testing.T) {
	tests := []struct {
		name     string
		reqB     string
		respB    string
		expected bool
	}{
		{
			name:     "valid Jev response",
			reqB:     jevRequestBody,
			respB:    jevResponseBody,
			expected: true,
		},
		{
			name:     "missing answers field",
			reqB:     jevRequestBody,
			respB:    `{"model":"jev-1.13","usage":{}}`,
			expected: false,
		},
		{
			name:     "wrong model name",
			reqB:     jevRequestBody,
			respB:    `{"model":"gpt-4","answers":{}}`,
			expected: false,
		},
		{
			name:     "missing state in request",
			reqB:     `{"questions":{}}`,
			respB:    jevResponseBody,
			expected: false,
		},
		{
			name:     "missing questions in request",
			reqB:     `{"state":"test"}`,
			respB:    jevResponseBody,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := looksLikeJevBody([]byte(tc.reqB), []byte(tc.respB))
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIsJevHost(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{"exact match", "jev-ai.org", true},
		{"subdomain", "api.jev-ai.org", true},
		{"multi-level subdomain", "gateway.api.jev-ai.org", true},
		{"mixed case", "Jev-AI.Org", true},
		{"subdomain mixed case", "API.JEV-AI.ORG", true},
		{"with port", "jev-ai.org:443", true},
		{"subdomain with port", "api.jev-ai.org:443", true},
		{"notjev-ai.org", "notjev-ai.org", false},
		{"jev-ai.org.example.com", "jev-ai.org.example.com", false},
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
		{"https://jev-ai.org/api/v1/systemone", true},
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
	req := makeJevRequest(t, http.MethodPost, "https://api.example.com/decisions", jevRequestBody)
	resp := makeJevResponse(http.StatusOK, http.Header{
		"Content-Type": []string{"application/json"},
	}, jevTruncatedAnswersResponse)

	base := &request.Span{}
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
			host:     "jev-ai.org",
			reqBody:  jevRequestBody,
			respBody: jevResponseBody,
			expected: true,
		},
		{
			name:     "OpenRouter with valid Jev payload",
			host:     "openrouter.ai",
			reqBody:  jevRequestBody,
			respBody: jevResponseBody,
			expected: true,
		},
		{
			name:     "gateway with insufficient evidence",
			host:     "gateway.example.com",
			reqBody:  `{"model":"gpt-4","messages":[]}`,
			respBody: `{"choices":[{"message":{"content":"hi"}}]}`,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := makeJevRequest(t, http.MethodPost, "https://"+tc.host+"/api/v1/systemone", tc.reqBody)
			resp := makeJevResponse(http.StatusOK, http.Header{
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
			req := makeJevRequest(t, http.MethodPost, "https://jev-ai.org/api/v1/systemone", jevRequestBody)
			resp := makeJevResponse(http.StatusOK, http.Header{
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
			req := makeJevRequest(t, http.MethodPost, "https://jev-ai.org/api/v1/systemone", jevRequestBody)
			resp := makeJevResponse(http.StatusOK, http.Header{
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
			reqBody:       `{"model":"jev-1.13","state":"Order #8814 arrived with a cracked`,
			respBody:      jevResponseBody,
			expectedModel: "jev-1.13",
			shouldDetect:  true,
		},
		{
			name:          "truncation inside questions",
			reqBody:       `{"model":"jev-1.13","state":"test","questions":{"refund_requested":{"type":"noul"`,
			respBody:      jevResponseBody,
			expectedModel: "jev-1.13",
			shouldDetect:  true,
		},
		{
			name:          "complete model before request truncation",
			reqBody:       `{"model":"jev-1.13"`,
			respBody:      jevResponseBody,
			expectedModel: "jev-1.13",
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
			req := makeJevRequest(t, http.MethodPost, "https://jev-ai.org/api/v1/systemone", tc.reqBody)
			resp := makeJevResponse(http.StatusOK, http.Header{
				"Content-Type": []string{"application/json"},
			}, tc.respBody)

			base := &request.Span{}
			base.Path = "/api/v1/systemone"
			span, ok := JevSpan(base, req, resp)

			assert.Equal(t, tc.shouldDetect, ok)
			if tc.shouldDetect {
				assert.NotNil(t, span.GenAI.Jev)
				assert.Equal(t, tc.expectedModel, span.GenAI.Jev.Model)
			}
		})
	}
}

func TestJevSpan_FailedGatewayRequests(t *testing.T) {
	tests := []struct {
		name          string
		host          string
		reqBody       string
		respBody      string
		expectedError string
		shouldDetect  bool
	}{
		{
			name:          "valid Jev gateway request with error response",
			host:          "openrouter.ai",
			reqBody:       jevRequestBody,
			respBody:      `{"error":"Invalid request"}`,
			expectedError: "Invalid request",
			shouldDetect:  true,
		},
		{
			name:          "Jev gateway request with truncated error response",
			host:          "openrouter.ai",
			reqBody:       jevRequestBody,
			respBody:      `{"error":"rat`,
			expectedError: "rat",
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
			name:          "ordinary API request to /v1/systemone without Jev evidence",
			host:          "api.example.com",
			reqBody:       `{"data":"test"}`,
			respBody:      `{"result":"ok"}`,
			expectedError: "",
			shouldDetect:  false,
		},
		{
			name:          "known Jev host error response without model",
			host:          "jev-ai.org",
			reqBody:       jevRequestBody,
			respBody:      `{"error":"rate limit"}`,
			expectedError: "rate limit",
			shouldDetect:  true,
		},
		{
			name:          "response unavailable after sufficiently evidenced Jev request",
			host:          "jev-ai.org",
			reqBody:       jevRequestBody,
			respBody:      "",
			expectedError: "",
			shouldDetect:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := makeJevRequest(t, http.MethodPost, "https://"+tc.host+"/api/v1/systemone", tc.reqBody)
			resp := makeJevResponse(http.StatusOK, http.Header{
				"Content-Type": []string{"application/json"},
			}, tc.respBody)

			base := &request.Span{}
			base.Path = "/api/v1/systemone"
			span, ok := JevSpan(base, req, resp)

			assert.Equal(t, tc.shouldDetect, ok)
			if tc.shouldDetect {
				assert.NotNil(t, span.GenAI.Jev)
				assert.Equal(t, tc.expectedError, span.GenAI.Jev.Error)
			}
		})
	}
}
