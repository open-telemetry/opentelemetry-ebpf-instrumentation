// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
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
			DefaultAction:     config.HTTPParsingActionInclude,
			MatchOrder:        config.HTTPParsingMatchOrderFirstMatchWins,
			ObfuscationString: "*",
		},
	}
	span := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"Content-Type": "application/json", "X-Request-Id": "abc123"},
		map[string]string{"X-Response-Id": "resp456"},
	)

	ok := EnrichHTTPSpan(span, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, []string{"application/json"}, span.RequestHeaders["Content-Type"])
	assert.Equal(t, []string{"abc123"}, span.RequestHeaders["X-Request-Id"])
	assert.Equal(t, []string{"resp456"}, span.ResponseHeaders["X-Response-Id"])
}

func TestGenericParsingSpan_ExcludeByDefault(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction:     config.HTTPParsingActionExclude,
			MatchOrder:        config.HTTPParsingMatchOrderFirstMatchWins,
			ObfuscationString: "*",
		},
	}
	span := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"Content-Type": "application/json"},
		map[string]string{"X-Response-Id": "resp456"},
	)

	ok := EnrichHTTPSpan(span, req, resp, cfg)
	assert.False(t, ok)
}

func TestGenericParsingSpan_IncludeRule(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction:     config.HTTPParsingActionExclude,
			MatchOrder:        config.HTTPParsingMatchOrderFirstMatchWins,
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

	ok := EnrichHTTPSpan(span, req, resp, cfg)
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
			DefaultAction:     config.HTTPParsingActionExclude,
			MatchOrder:        config.HTTPParsingMatchOrderFirstMatchWins,
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

	ok := EnrichHTTPSpan(span, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, []string{"***"}, span.RequestHeaders["Authorization"])
	_, hasContentType := span.RequestHeaders["Content-Type"]
	assert.False(t, hasContentType)
}

func TestGenericParsingSpan_ScopeRequest(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction:     config.HTTPParsingActionExclude,
			MatchOrder:        config.HTTPParsingMatchOrderFirstMatchWins,
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

	ok := EnrichHTTPSpan(span, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, []string{"req-value"}, span.RequestHeaders["X-Custom"])
}

func TestGenericParsingSpan_ScopeResponse(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction:     config.HTTPParsingActionExclude,
			MatchOrder:        config.HTTPParsingMatchOrderFirstMatchWins,
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

	ok := EnrichHTTPSpan(span, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, []string{"resp-value"}, span.ResponseHeaders["X-Custom"])
}

func TestGenericParsingSpan_CaseInsensitiveMatch(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction:     config.HTTPParsingActionExclude,
			MatchOrder:        config.HTTPParsingMatchOrderFirstMatchWins,
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

	ok := EnrichHTTPSpan(span, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, []string{"value"}, span.RequestHeaders["X-Custom"])
}

func TestGenericParsingSpan_FirstMatchWins(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction:     config.HTTPParsingActionExclude,
			MatchOrder:        config.HTTPParsingMatchOrderFirstMatchWins,
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

	ok := EnrichHTTPSpan(span, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, []string{"***"}, span.RequestHeaders["Authorization"])
	assert.Equal(t, []string{"application/json"}, span.RequestHeaders["Content-Type"])
}

func TestGenericParsingSpan_MultipleGlobsInRule(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction:     config.HTTPParsingActionExclude,
			MatchOrder:        config.HTTPParsingMatchOrderFirstMatchWins,
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

	ok := EnrichHTTPSpan(span, req, resp, cfg)
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
			DefaultAction:     config.HTTPParsingActionExclude,
			MatchOrder:        config.HTTPParsingMatchOrderFirstMatchWins,
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

	ok := EnrichHTTPSpan(span, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, []string{"abc123"}, span.RequestHeaders["X-Request-Id"])
	_, hasSecret := span.RequestHeaders["X-Secret"]
	assert.False(t, hasSecret, "X-Secret should be excluded by the first rule")
}

func TestGenericParsingSpan_RuleOrderIncludeBeforeExclude(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction:     config.HTTPParsingActionExclude,
			MatchOrder:        config.HTTPParsingMatchOrderFirstMatchWins,
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

	ok := EnrichHTTPSpan(span, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, []string{"abc123"}, span.RequestHeaders["X-Request-Id"])
	assert.Equal(t, []string{"visible-now"}, span.RequestHeaders["X-Secret"],
		"X-Secret should be included because the include rule comes first")
}

func TestGenericParsingSpan_RuleOrderObfuscateBeforeInclude(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction:     config.HTTPParsingActionExclude,
			MatchOrder:        config.HTTPParsingMatchOrderFirstMatchWins,
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

	ok := EnrichHTTPSpan(span, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, []string{"[REDACTED]"}, span.RequestHeaders["Authorization"])
	assert.Equal(t, []string{"[REDACTED]"}, span.RequestHeaders["Cookie"])
	assert.Equal(t, []string{"application/json"}, span.RequestHeaders["Content-Type"])
}

func TestGenericParsingSpan_ExplicitExcludeRule(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction:     config.HTTPParsingActionInclude,
			MatchOrder:        config.HTTPParsingMatchOrderFirstMatchWins,
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

	ok := EnrichHTTPSpan(span, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, []string{"text/plain"}, span.RequestHeaders["Content-Type"])
	_, hasAuth := span.RequestHeaders["Authorization"]
	assert.False(t, hasAuth)
}

func TestGenericParsingSpan_MixedScopeRuleOrder(t *testing.T) {
	cfg := config.EnrichmentConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction:     config.HTTPParsingActionExclude,
			MatchOrder:        config.HTTPParsingMatchOrderFirstMatchWins,
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

	ok := EnrichHTTPSpan(span, req, resp, cfg)
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
			DefaultAction:     config.HTTPParsingActionInclude,
			MatchOrder:        config.HTTPParsingMatchOrderFirstMatchWins,
			ObfuscationString: "***",
		},
	}
	span := &request.Span{Method: "GET", Path: "/test"}
	req := &http.Request{Header: http.Header{}}
	req.Header.Add("Set-Cookie", "session=abc")
	req.Header.Add("Set-Cookie", "theme=dark")
	resp := &http.Response{Header: http.Header{}}

	ok := EnrichHTTPSpan(span, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, []string{"session=abc", "theme=dark"}, span.RequestHeaders["Set-Cookie"])
}
