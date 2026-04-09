// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
)

func makeReqResp(reqHeaders, respHeaders map[string]string) (*http.Request, *http.Response) {
	req := &http.Request{Header: http.Header{}}
	for k, v := range reqHeaders {
		req.Header.Set(k, v)
	}
	resp := &http.Response{Header: http.Header{}}
	for k, v := range respHeaders {
		resp.Header.Set(k, v)
	}
	return req, resp
}

// gi creates a case-insensitive GlobAttr for tests (pattern lowercased at compile).
func gi(pattern string) services.GlobAttr {
	return services.NewGlob(strings.ToLower(pattern))
}

func TestGenericParsingSpan_IncludeByDefault(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionInclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "*",
		},
	}
	span := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"Content-Type": "application/json", "X-Request-Id": "abc123"},
		map[string]string{"X-Response-Id": "resp456"},
	)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	assert.Equal(t, []string{"application/json"}, span.RequestHeaders["Content-Type"])
	assert.Equal(t, []string{"abc123"}, span.RequestHeaders["X-Request-Id"])
	assert.Equal(t, []string{"resp456"}, span.ResponseHeaders["X-Response-Id"])
}

func TestGenericParsingSpan_ExcludeByDefault(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "*",
		},
	}
	span := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"Content-Type": "application/json"},
		map[string]string{"X-Response-Id": "resp456"},
	)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	assert.False(t, ok)
}

func TestGenericParsingSpan_IncludeRule(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "*",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match: config.HTTPParsingMatch{
					Patterns: []services.GlobAttr{gi("X-Request-Id")},
				},
			},
		},
	}
	span := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"Content-Type": "application/json", "X-Request-Id": "abc123"},
		map[string]string{"X-Response-Id": "resp456"},
	)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	assert.Equal(t, []string{"abc123"}, span.RequestHeaders["X-Request-Id"])
	_, hasContentType := span.RequestHeaders["Content-Type"]
	assert.False(t, hasContentType)
	assert.Nil(t, span.ResponseHeaders)
}

func TestGenericParsingSpan_ObfuscateRule(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionObfuscate,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match: config.HTTPParsingMatch{
					Patterns: []services.GlobAttr{gi("Authorization")},
				},
			},
		},
	}
	span := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"Authorization": "Bearer secret-token", "Content-Type": "text/plain"},
		nil,
	)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	assert.Equal(t, []string{"***"}, span.RequestHeaders["Authorization"])
	_, hasContentType := span.RequestHeaders["Content-Type"]
	assert.False(t, hasContentType)
}

func TestGenericParsingSpan_ScopeRequest(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "*",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeRequest,
				Match: config.HTTPParsingMatch{
					Patterns: []services.GlobAttr{gi("X-Custom")},
				},
			},
		},
	}
	span := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"X-Custom": "req-value"},
		map[string]string{"X-Custom": "resp-value"},
	)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	assert.Equal(t, []string{"req-value"}, span.RequestHeaders["X-Custom"])
}

func TestGenericParsingSpan_ScopeResponse(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "*",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeResponse,
				Match: config.HTTPParsingMatch{
					Patterns: []services.GlobAttr{gi("X-Custom")},
				},
			},
		},
	}
	span := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"X-Custom": "req-value"},
		map[string]string{"X-Custom": "resp-value"},
	)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	assert.Equal(t, []string{"resp-value"}, span.ResponseHeaders["X-Custom"])
}

func TestGenericParsingSpan_CaseInsensitiveMatch(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "*",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match: config.HTTPParsingMatch{
					Patterns: []services.GlobAttr{gi("x-custom")},
				},
			},
		},
	}
	span := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"X-Custom": "value"},
		nil,
	)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	assert.Equal(t, []string{"value"}, span.RequestHeaders["X-Custom"])
}

func TestGenericParsingSpan_FirstMatchWins(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionObfuscate,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match: config.HTTPParsingMatch{
					Patterns: []services.GlobAttr{gi("Authorization")},
				},
			},
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match: config.HTTPParsingMatch{
					Patterns: []services.GlobAttr{gi("*")},
				},
			},
		},
	}
	span := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"Authorization": "Bearer token", "Content-Type": "application/json"},
		nil,
	)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	assert.Equal(t, []string{"***"}, span.RequestHeaders["Authorization"])
	assert.Equal(t, []string{"application/json"}, span.RequestHeaders["Content-Type"])
}

func TestGenericParsingSpan_MultipleGlobsInRule(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "*",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match: config.HTTPParsingMatch{
					Patterns: []services.GlobAttr{gi("Content-Type"), gi("X-Request-Id")},
				},
			},
		},
	}
	span := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"Content-Type": "text/html", "X-Request-Id": "123", "Authorization": "secret"},
		nil,
	)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	assert.Equal(t, []string{"text/html"}, span.RequestHeaders["Content-Type"])
	assert.Equal(t, []string{"123"}, span.RequestHeaders["X-Request-Id"])
	_, hasAuth := span.RequestHeaders["Authorization"]
	assert.False(t, hasAuth)
}

func TestGenericParsingSpan_RuleOrderExcludeBeforeInclude(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "*",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionExclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{Patterns: []services.GlobAttr{gi("X-Secret")}},
			},
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{Patterns: []services.GlobAttr{gi("X-*")}},
			},
		},
	}
	span := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"X-Secret": "hidden", "X-Request-Id": "abc123"},
		nil,
	)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	assert.Equal(t, []string{"abc123"}, span.RequestHeaders["X-Request-Id"])
	_, hasSecret := span.RequestHeaders["X-Secret"]
	assert.False(t, hasSecret, "X-Secret should be excluded by the first rule")
}

func TestGenericParsingSpan_RuleOrderIncludeBeforeExclude(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "*",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{Patterns: []services.GlobAttr{gi("X-*")}},
			},
			{
				Action: config.HTTPParsingActionExclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{Patterns: []services.GlobAttr{gi("X-Secret")}},
			},
		},
	}
	span := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"X-Secret": "visible-now", "X-Request-Id": "abc123"},
		nil,
	)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	assert.Equal(t, []string{"abc123"}, span.RequestHeaders["X-Request-Id"])
	assert.Equal(t, []string{"visible-now"}, span.RequestHeaders["X-Secret"],
		"X-Secret should be included because the include rule comes first")
}

func TestGenericParsingSpan_RuleOrderObfuscateBeforeInclude(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "[REDACTED]",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionObfuscate,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{Patterns: []services.GlobAttr{gi("Authorization"), gi("Cookie")}},
			},
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{Patterns: []services.GlobAttr{gi("*")}},
			},
		},
	}
	span := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{
			"Authorization": "Bearer token",
			"Cookie":        "session=abc",
			"Content-Type":  "application/json",
		},
		nil,
	)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	assert.Equal(t, []string{"[REDACTED]"}, span.RequestHeaders["Authorization"])
	assert.Equal(t, []string{"[REDACTED]"}, span.RequestHeaders["Cookie"])
	assert.Equal(t, []string{"application/json"}, span.RequestHeaders["Content-Type"])
}

func TestGenericParsingSpan_ExplicitExcludeRule(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionInclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "*",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionExclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{Patterns: []services.GlobAttr{gi("Authorization")}},
			},
		},
	}
	span := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"Authorization": "Bearer secret", "Content-Type": "text/plain"},
		nil,
	)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	assert.Equal(t, []string{"text/plain"}, span.RequestHeaders["Content-Type"])
	_, hasAuth := span.RequestHeaders["Authorization"]
	assert.False(t, hasAuth)
}

func TestGenericParsingSpan_MixedScopeRuleOrder(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionObfuscate,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeRequest,
				Match:  config.HTTPParsingMatch{Patterns: []services.GlobAttr{gi("Authorization")}},
			},
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{Patterns: []services.GlobAttr{gi("*")}},
			},
		},
	}
	span := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"Authorization": "Bearer token", "X-Foo": "bar"},
		map[string]string{"Authorization": "Bearer resp-token", "X-Bar": "baz"},
	)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	assert.Equal(t, []string{"***"}, span.RequestHeaders["Authorization"])
	assert.Equal(t, []string{"bar"}, span.RequestHeaders["X-Foo"])
	assert.Equal(t, []string{"Bearer resp-token"}, span.ResponseHeaders["Authorization"],
		"response Authorization should be included, not obfuscated")
	assert.Equal(t, []string{"baz"}, span.ResponseHeaders["X-Bar"])
}

func TestGenericParsingSpan_MultipleHeaderValues(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionInclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
	}
	span := &request.Span{Method: "GET", Path: "/test"}
	req := &http.Request{Header: http.Header{}}
	req.Header.Add("Set-Cookie", "session=abc")
	req.Header.Add("Set-Cookie", "theme=dark")
	resp := &http.Response{Header: http.Header{}}

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	assert.Equal(t, []string{"session=abc", "theme=dark"}, span.RequestHeaders["Set-Cookie"])
}

// makeReqRespWithBody creates an http.Request and http.Response with JSON bodies and headers.
func makeReqRespWithBody(reqBody, respBody string) (*http.Request, *http.Response) {
	req := &http.Request{Header: http.Header{}}
	if reqBody != "" {
		req.Body = io.NopCloser(strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
	}
	resp := &http.Response{Header: http.Header{}}
	if respBody != "" {
		resp.Body = io.NopCloser(strings.NewReader(respBody))
		resp.Header.Set("Content-Type", "application/json")
	}
	return req, resp
}

// jp creates a JSONPathExpr from a string, panicking on error. Test-only helper.
func jp(path string) config.JSONPathExpr {
	e, err := config.NewJSONPathExpr(path)
	if err != nil {
		panic("invalid JSONPath in test: " + path + ": " + err.Error())
	}
	return e
}

func TestBodyExtraction_IncludeRawJSON(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{},
			},
		},
	}
	span := &request.Span{Method: "POST", Path: "/api/users"}
	req, resp := makeReqRespWithBody(
		`{"name":"Alice","email":"alice@example.com"}`,
		`{"id":1,"status":"created"}`,
	)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	assert.JSONEq(t, `{"name":"Alice","email":"alice@example.com"}`, span.RequestBodyContent)
	assert.JSONEq(t, `{"id":1,"status":"created"}`, span.ResponseBodyContent)
}

func TestBodyExtraction_ObfuscateJSONPaths(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionObfuscate,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeAll,
				Match: config.HTTPParsingMatch{
					ObfuscationJSONPaths: []config.JSONPathExpr{jp("$.password"), jp("$.user.ssn")},
				},
			},
		},
	}
	span := &request.Span{Method: "POST", Path: "/api/auth"}
	req, resp := makeReqRespWithBody(
		`{"username":"alice","password":"secret123","user":{"ssn":"123-45-6789","name":"Alice"}}`,
		"",
	)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	assert.Contains(t, span.RequestBodyContent, `"***"`)
	assert.NotContains(t, span.RequestBodyContent, "secret123")
	assert.NotContains(t, span.RequestBodyContent, "123-45-6789")
	assert.Contains(t, span.RequestBodyContent, `"alice"`)
	assert.Contains(t, span.RequestBodyContent, `"Alice"`)
}

func TestBodyExtraction_ExcludeByDefault(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionInclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
	}
	span := &request.Span{Method: "POST", Path: "/api/data"}
	req, resp := makeReqRespWithBody(`{"key":"value"}`, `{"result":"ok"}`)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	// ok may be true because headers are included by default
	assert.Empty(t, span.RequestBodyContent)
	assert.Empty(t, span.ResponseBodyContent)
	_ = ok
}

func TestBodyExtraction_NonJSONSkipped(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{},
			},
		},
	}
	span := &request.Span{Method: "POST", Path: "/api/data"}
	req := &http.Request{Header: http.Header{}}
	req.Body = io.NopCloser(strings.NewReader("name=Alice&age=30"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := &http.Response{Header: http.Header{}}

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	assert.False(t, ok)
	assert.Empty(t, span.RequestBodyContent)
}

func TestBodyExtraction_InvalidJSONSkipped(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{},
			},
		},
	}
	span := &request.Span{Method: "POST", Path: "/api/data"}
	req := &http.Request{Header: http.Header{}}
	req.Body = io.NopCloser(strings.NewReader(`{"truncated": "val`))
	req.Header.Set("Content-Type", "application/json")
	resp := &http.Response{Header: http.Header{}}

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	assert.False(t, ok)
	assert.Empty(t, span.RequestBodyContent)
}

func TestBodyExtraction_ArrayElementRedaction(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "[REDACTED]",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionObfuscate,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeRequest,
				Match: config.HTTPParsingMatch{
					ObfuscationJSONPaths: []config.JSONPathExpr{jp("$.users[*].email")},
				},
			},
		},
	}
	span := &request.Span{Method: "POST", Path: "/api/bulk"}
	req, resp := makeReqRespWithBody(
		`{"users":[{"name":"Alice","email":"alice@test.com"},{"name":"Bob","email":"bob@test.com"}]}`,
		"",
	)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	assert.NotContains(t, span.RequestBodyContent, "alice@test.com")
	assert.NotContains(t, span.RequestBodyContent, "bob@test.com")
	assert.Contains(t, span.RequestBodyContent, `"Alice"`)
	assert.Contains(t, span.RequestBodyContent, `"Bob"`)
	assert.Contains(t, span.RequestBodyContent, `"[REDACTED]"`)
}

func TestBodyExtraction_MergeMultipleRules(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionObfuscate,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeAll,
				Match: config.HTTPParsingMatch{
					ObfuscationJSONPaths: []config.JSONPathExpr{jp("$.password")},
				},
			},
			{
				Action: config.HTTPParsingActionObfuscate,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeAll,
				Match: config.HTTPParsingMatch{
					ObfuscationJSONPaths: []config.JSONPathExpr{jp("$.ssn")},
					URLPathPatterns:      []services.GlobAttr{services.NewGlob("/api/users*")},
				},
			},
		},
	}
	span := &request.Span{Method: "POST", Path: "/api/users"}
	req, resp := makeReqRespWithBody(
		`{"username":"alice","password":"secret","ssn":"123-45-6789"}`,
		"",
	)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	assert.NotContains(t, span.RequestBodyContent, "secret")
	assert.NotContains(t, span.RequestBodyContent, "123-45-6789")
	assert.Contains(t, span.RequestBodyContent, `"alice"`)
}

func TestBodyExtraction_RouteFiltering(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeAll,
				Match: config.HTTPParsingMatch{
					URLPathPatterns: []services.GlobAttr{services.NewGlob("/api/v1/*")},
				},
			},
		},
	}

	// Matching route
	span1 := &request.Span{Method: "POST", Path: "/api/v1/users"}
	req1, resp1 := makeReqRespWithBody(`{"key":"value"}`, "")
	ok := NewHTTPEnricher(cfg).Enrich(span1, req1, resp1)
	require.True(t, ok)
	assert.JSONEq(t, `{"key":"value"}`, span1.RequestBodyContent)

	// Non-matching route
	span2 := &request.Span{Method: "POST", Path: "/api/v2/users"}
	req2, resp2 := makeReqRespWithBody(`{"key":"value"}`, "")
	ok = NewHTTPEnricher(cfg).Enrich(span2, req2, resp2)
	assert.False(t, ok)
	assert.Empty(t, span2.RequestBodyContent)
}

func TestBodyExtraction_MethodFiltering(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeAll,
				Match: config.HTTPParsingMatch{
					Methods: []config.HTTPMethod{config.HTTPMethodPOST, config.HTTPMethodPUT},
				},
			},
		},
	}

	// POST matches
	span1 := &request.Span{Method: "POST", Path: "/api/data"}
	req1, resp1 := makeReqRespWithBody(`{"key":"value"}`, "")
	ok := NewHTTPEnricher(cfg).Enrich(span1, req1, resp1)
	require.True(t, ok)
	assert.JSONEq(t, `{"key":"value"}`, span1.RequestBodyContent)

	// GET does not match
	span2 := &request.Span{Method: "GET", Path: "/api/data"}
	req2, resp2 := makeReqRespWithBody(`{"key":"value"}`, "")
	ok = NewHTTPEnricher(cfg).Enrich(span2, req2, resp2)
	assert.False(t, ok)
	assert.Empty(t, span2.RequestBodyContent)
}

func TestBodyExtraction_ScopeRequestOnly(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeRequest,
				Match:  config.HTTPParsingMatch{},
			},
		},
	}
	span := &request.Span{Method: "POST", Path: "/api/data"}
	req, resp := makeReqRespWithBody(`{"request":"data"}`, `{"response":"data"}`)

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	assert.JSONEq(t, `{"request":"data"}`, span.RequestBodyContent)
	assert.Empty(t, span.ResponseBodyContent)
}

func TestBodyExtraction_UnmatchedPathsIgnored(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionObfuscate,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeAll,
				Match: config.HTTPParsingMatch{
					ObfuscationJSONPaths: []config.JSONPathExpr{jp("$.nonexistent"), jp("$.also.missing")},
				},
			},
		},
	}
	span := &request.Span{Method: "POST", Path: "/api/data"}
	req, resp := makeReqRespWithBody(`{"name":"Alice","age":30}`, "")

	ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
	require.True(t, ok)
	// Body should be included with no changes since paths don't match
	assert.Contains(t, span.RequestBodyContent, `"Alice"`)
	assert.Contains(t, span.RequestBodyContent, "30")
}

func TestBodyExtraction_ExcludeRuleOnRoute(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionInclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionExclude,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeAll,
				Match: config.HTTPParsingMatch{
					URLPathPatterns: []services.GlobAttr{services.NewGlob("/health")},
				},
			},
		},
	}

	// Health route excluded
	span1 := &request.Span{Method: "GET", Path: "/health"}
	req1, resp1 := makeReqRespWithBody(`{"status":"ok"}`, "")
	ok := NewHTTPEnricher(cfg).Enrich(span1, req1, resp1)
	assert.False(t, ok)
	assert.Empty(t, span1.RequestBodyContent)

	// Other routes use default_action: include
	span2 := &request.Span{Method: "POST", Path: "/api/data"}
	req2, resp2 := makeReqRespWithBody(`{"key":"value"}`, "")
	ok = NewHTTPEnricher(cfg).Enrich(span2, req2, resp2)
	require.True(t, ok)
	assert.JSONEq(t, `{"key":"value"}`, span2.RequestBodyContent)
}

func TestBodyExtraction_ContentTypeVariants(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{},
			},
		},
	}

	tests := []struct {
		name        string
		contentType string
		shouldMatch bool
	}{
		{"application/json", "application/json", true},
		{"json with charset", "application/json; charset=utf-8", true},
		{"vnd+json", "application/vnd.api+json", true},
		{"text/plain", "text/plain", false},
		{"text/html", "text/html", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span := &request.Span{Method: "POST", Path: "/api/data"}
			req := &http.Request{Header: http.Header{}}
			req.Body = io.NopCloser(strings.NewReader(`{"key":"value"}`))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			resp := &http.Response{Header: http.Header{}}

			ok := NewHTTPEnricher(cfg).Enrich(span, req, resp)
			if tt.shouldMatch {
				require.True(t, ok)
				assert.JSONEq(t, `{"key":"value"}`, span.RequestBodyContent)
			} else {
				assert.Empty(t, span.RequestBodyContent)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		rules   []config.HTTPParsingRule
		wantErr string
	}{
		{
			name: "body obfuscate without json paths",
			rules: []config.HTTPParsingRule{{
				Action: config.HTTPParsingActionObfuscate,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeAll,
			}},
			wantErr: "obfuscation_json_paths",
		},
		{
			name: "body include with json paths",
			rules: []config.HTTPParsingRule{{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{ObfuscationJSONPaths: []config.JSONPathExpr{jp("$.x")}},
			}},
			wantErr: "obfuscation_json_paths can only be used with action",
		},
		{
			name: "header rule with json paths",
			rules: []config.HTTPParsingRule{{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{ObfuscationJSONPaths: []config.JSONPathExpr{jp("$.x")}},
			}},
			wantErr: "header rules cannot use obfuscation_json_paths",
		},
		{
			name: "body rule with patterns",
			rules: []config.HTTPParsingRule{{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{Patterns: []services.GlobAttr{gi("X-*")}},
			}},
			wantErr: "body rules cannot use patterns",
		},
		{
			name: "body rule with case_sensitive",
			rules: []config.HTTPParsingRule{{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{CaseSensitive: true},
			}},
			wantErr: "body rules cannot use case_sensitive",
		},
		{
			name: "header rule without patterns",
			rules: []config.HTTPParsingRule{{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
			}},
			wantErr: "header rules require at least one pattern",
		},
		{
			name: "valid body include",
			rules: []config.HTTPParsingRule{{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeAll,
			}},
		},
		{
			name: "valid body obfuscate",
			rules: []config.HTTPParsingRule{{
				Action: config.HTTPParsingActionObfuscate,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeRequest,
				Match:  config.HTTPParsingMatch{ObfuscationJSONPaths: []config.JSONPathExpr{jp("$.pw")}},
			}},
		},
		{
			name: "valid header include",
			rules: []config.HTTPParsingRule{{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{Patterns: []services.GlobAttr{gi("X-*")}},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.EnrichmentConfig{Enabled: true, Rules: tt.rules}
			err := cfg.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

// --- Benchmarks ---

func BenchmarkHTTPEnricher_HeadersOnly(b *testing.B) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionObfuscate,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{Patterns: []services.GlobAttr{gi("Authorization"), gi("Cookie")}},
			},
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{Patterns: []services.GlobAttr{gi("*")}},
			},
		},
	}

	enricher := NewHTTPEnricher(cfg)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		span := &request.Span{Method: "GET", Path: "/api/v1/users"}
		req := &http.Request{Header: http.Header{
			"Authorization": []string{"Bearer token"},
			"Content-Type":  []string{"application/json"},
			"X-Request-Id":  []string{"abc123"},
			"Accept":        []string{"application/json"},
			"Cookie":        []string{"session=xyz"},
		}}
		resp := &http.Response{Header: http.Header{
			"Content-Type":  []string{"application/json"},
			"X-Response-Id": []string{"resp456"},
			"Cache-Control": []string{"no-cache"},
		}}
		enricher.Enrich(span, req, resp)
	}
}

func BenchmarkHTTPEnricher_BodyInclude_SmallJSON(b *testing.B) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeRequest,
				Match:  config.HTTPParsingMatch{},
			},
		},
	}

	body := `{"username":"alice","email":"alice@example.com","age":30}`

	enricher := NewHTTPEnricher(cfg)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		span := &request.Span{Method: "POST", Path: "/api/users"}
		req := &http.Request{
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   io.NopCloser(strings.NewReader(body)),
		}
		resp := &http.Response{Header: http.Header{}}
		enricher.Enrich(span, req, resp)
	}
}

func BenchmarkHTTPEnricher_BodyObfuscate_SmallJSON(b *testing.B) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionObfuscate,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeRequest,
				Match: config.HTTPParsingMatch{
					ObfuscationJSONPaths: []config.JSONPathExpr{jp("$.password"), jp("$.ssn")},
				},
			},
		},
	}

	body := `{"username":"alice","password":"secret123","ssn":"123-45-6789","email":"alice@example.com"}`

	enricher := NewHTTPEnricher(cfg)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		span := &request.Span{Method: "POST", Path: "/api/users"}
		req := &http.Request{
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   io.NopCloser(strings.NewReader(body)),
		}
		resp := &http.Response{Header: http.Header{}}
		enricher.Enrich(span, req, resp)
	}
}

func BenchmarkHTTPEnricher_BodyObfuscate_LargeJSON(b *testing.B) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionObfuscate,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeRequest,
				Match: config.HTTPParsingMatch{
					ObfuscationJSONPaths: []config.JSONPathExpr{jp("$.users[*].email"), jp("$.users[*].ssn")},
				},
			},
		},
	}

	// Build a ~4KB JSON body with 50 users
	var users []string
	for i := 0; i < 50; i++ {
		users = append(users, `{"name":"User`+strings.Repeat("x", 10)+`","email":"user@test.com","ssn":"123-45-6789","role":"admin"}`)
	}
	body := `{"users":[` + strings.Join(users, ",") + `]}`

	enricher := NewHTTPEnricher(cfg)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		span := &request.Span{Method: "POST", Path: "/api/bulk"}
		req := &http.Request{
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   io.NopCloser(strings.NewReader(body)),
		}
		resp := &http.Response{Header: http.Header{}}
		enricher.Enrich(span, req, resp)
	}
}

func BenchmarkHTTPEnricher_BodyExcludedByDefault(b *testing.B) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
	}

	body := `{"username":"alice","password":"secret123"}`

	enricher := NewHTTPEnricher(cfg)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		span := &request.Span{Method: "POST", Path: "/api/users"}
		req := &http.Request{
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   io.NopCloser(strings.NewReader(body)),
		}
		resp := &http.Response{Header: http.Header{}}
		enricher.Enrich(span, req, resp)
	}
}

func BenchmarkHTTPEnricher_HeadersAndBody(b *testing.B) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction: config.HTTPParsingDefaultAction{
				Headers: config.HTTPParsingActionExclude,
				Body:    config.HTTPParsingActionExclude,
			},
			ObfuscationString: "***",
		},
		Rules: []config.HTTPParsingRule{
			{
				Action: config.HTTPParsingActionObfuscate,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{Patterns: []services.GlobAttr{gi("Authorization")}},
			},
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeAll,
				Match:  config.HTTPParsingMatch{Patterns: []services.GlobAttr{gi("Content-Type"), gi("X-*")}},
			},
			{
				Action: config.HTTPParsingActionObfuscate,
				Type:   config.HTTPParsingRuleTypeBody,
				Scope:  config.HTTPParsingScopeRequest,
				Match: config.HTTPParsingMatch{
					ObfuscationJSONPaths: []config.JSONPathExpr{jp("$.password")},
				},
			},
		},
	}

	body := `{"username":"alice","password":"secret123","email":"alice@example.com"}`

	enricher := NewHTTPEnricher(cfg)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		span := &request.Span{Method: "POST", Path: "/api/users"}
		req := &http.Request{
			Header: http.Header{
				"Authorization": []string{"Bearer token"},
				"Content-Type":  []string{"application/json"},
				"X-Request-Id":  []string{"abc123"},
			},
			Body: io.NopCloser(strings.NewReader(body)),
		}
		resp := &http.Response{Header: http.Header{
			"Content-Type": []string{"application/json"},
		}}
		enricher.Enrich(span, req, resp)
	}
}
