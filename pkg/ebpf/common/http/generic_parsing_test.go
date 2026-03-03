// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"net/http"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
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

// re is a helper to compile a regex in tests.
func re(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}

// rei is a helper to compile a case-insensitive regex in tests.
func rei(pattern string) *regexp.Regexp {
	return regexp.MustCompile("(?i)" + pattern)
}

func TestGenericParsingSpan_IncludeByDefault(t *testing.T) {
	cfg := config.HTTPGenericParsingConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction:     config.HTTPParsingActionInclude,
			MatchOrder:        config.HTTPParsingMatchOrderFirstMatchWins,
			ObfuscationString: "*",
		},
	}
	baseSpan := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"Content-Type": "application/json", "X-Request-Id": "abc123"},
		map[string]string{"X-Response-Id": "resp456"},
	)

	span, ok := GenericParsingSpan(baseSpan, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, "application/json", span.RequestHeaders["Content-Type"])
	assert.Equal(t, "abc123", span.RequestHeaders["X-Request-Id"])
	assert.Equal(t, "resp456", span.ResponseHeaders["X-Response-Id"])
}

func TestGenericParsingSpan_ExcludeByDefault(t *testing.T) {
	cfg := config.HTTPGenericParsingConfig{
		Enabled: true,
		Policy: config.HTTPParsingPolicy{
			DefaultAction:     config.HTTPParsingActionExclude,
			MatchOrder:        config.HTTPParsingMatchOrderFirstMatchWins,
			ObfuscationString: "*",
		},
	}
	baseSpan := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"Content-Type": "application/json"},
		map[string]string{"X-Response-Id": "resp456"},
	)

	_, ok := GenericParsingSpan(baseSpan, req, resp, cfg)
	assert.False(t, ok)
}

func TestGenericParsingSpan_IncludeRule(t *testing.T) {
	cfg := config.HTTPGenericParsingConfig{
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
				Scope:  config.HTTPParsingScopeBoth,
				Match: config.HTTPParsingMatch{
					Regex: []*regexp.Regexp{re("^X-Request-Id$")},
				},
			},
		},
	}
	baseSpan := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"Content-Type": "application/json", "X-Request-Id": "abc123"},
		map[string]string{"X-Response-Id": "resp456"},
	)

	span, ok := GenericParsingSpan(baseSpan, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, "abc123", span.RequestHeaders["X-Request-Id"])
	_, hasContentType := span.RequestHeaders["Content-Type"]
	assert.False(t, hasContentType)
	assert.Nil(t, span.ResponseHeaders)
}

func TestGenericParsingSpan_ObfuscateRule(t *testing.T) {
	cfg := config.HTTPGenericParsingConfig{
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
				Scope:  config.HTTPParsingScopeBoth,
				Match: config.HTTPParsingMatch{
					Regex: []*regexp.Regexp{rei("^Authorization$")},
				},
			},
		},
	}
	baseSpan := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"Authorization": "Bearer secret-token", "Content-Type": "text/plain"},
		nil,
	)

	span, ok := GenericParsingSpan(baseSpan, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, "***", span.RequestHeaders["Authorization"])
	_, hasContentType := span.RequestHeaders["Content-Type"]
	assert.False(t, hasContentType)
}

func TestGenericParsingSpan_ScopeRequest(t *testing.T) {
	cfg := config.HTTPGenericParsingConfig{
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
					Regex: []*regexp.Regexp{re("^X-Custom$")},
				},
			},
		},
	}
	baseSpan := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"X-Custom": "req-value"},
		map[string]string{"X-Custom": "resp-value"},
	)

	span, ok := GenericParsingSpan(baseSpan, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, "req-value", span.RequestHeaders["X-Custom"])
}

func TestGenericParsingSpan_ScopeResponse(t *testing.T) {
	cfg := config.HTTPGenericParsingConfig{
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
					Regex: []*regexp.Regexp{re("^X-Custom$")},
				},
			},
		},
	}
	baseSpan := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"X-Custom": "req-value"},
		map[string]string{"X-Custom": "resp-value"},
	)

	span, ok := GenericParsingSpan(baseSpan, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, "resp-value", span.ResponseHeaders["X-Custom"])
}

func TestGenericParsingSpan_CaseInsensitiveMatch(t *testing.T) {
	cfg := config.HTTPGenericParsingConfig{
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
				Scope:  config.HTTPParsingScopeBoth,
				Match: config.HTTPParsingMatch{
					Regex: []*regexp.Regexp{rei("^x-custom$")},
				},
			},
		},
	}
	baseSpan := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"X-Custom": "value"},
		nil,
	)

	span, ok := GenericParsingSpan(baseSpan, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, "value", span.RequestHeaders["X-Custom"])
}

func TestGenericParsingSpan_FirstMatchWins(t *testing.T) {
	cfg := config.HTTPGenericParsingConfig{
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
				Scope:  config.HTTPParsingScopeBoth,
				Match: config.HTTPParsingMatch{
					Regex: []*regexp.Regexp{re("^Authorization$")},
				},
			},
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeBoth,
				Match: config.HTTPParsingMatch{
					Regex: []*regexp.Regexp{re(".*")},
				},
			},
		},
	}
	baseSpan := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"Authorization": "Bearer token", "Content-Type": "application/json"},
		nil,
	)

	span, ok := GenericParsingSpan(baseSpan, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, "***", span.RequestHeaders["Authorization"])
	assert.Equal(t, "application/json", span.RequestHeaders["Content-Type"])
}

func TestGenericParsingSpan_MultipleRegexInRule(t *testing.T) {
	cfg := config.HTTPGenericParsingConfig{
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
				Scope:  config.HTTPParsingScopeBoth,
				Match: config.HTTPParsingMatch{
					Regex: []*regexp.Regexp{re("^Content-Type$"), re("^X-Request-Id$")},
				},
			},
		},
	}
	baseSpan := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"Content-Type": "text/html", "X-Request-Id": "123", "Authorization": "secret"},
		nil,
	)

	span, ok := GenericParsingSpan(baseSpan, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, "text/html", span.RequestHeaders["Content-Type"])
	assert.Equal(t, "123", span.RequestHeaders["X-Request-Id"])
	_, hasAuth := span.RequestHeaders["Authorization"]
	assert.False(t, hasAuth)
}

func TestGenericParsingSpan_RuleOrderExcludeBeforeInclude(t *testing.T) {
	// When an exclude rule appears before an include rule, the exclude wins for matching headers.
	cfg := config.HTTPGenericParsingConfig{
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
				Scope:  config.HTTPParsingScopeBoth,
				Match:  config.HTTPParsingMatch{Regex: []*regexp.Regexp{re("^X-Secret$")}},
			},
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeBoth,
				Match:  config.HTTPParsingMatch{Regex: []*regexp.Regexp{re("^X-.*$")}},
			},
		},
	}
	baseSpan := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"X-Secret": "hidden", "X-Request-Id": "abc123"},
		nil,
	)

	span, ok := GenericParsingSpan(baseSpan, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, "abc123", span.RequestHeaders["X-Request-Id"])
	_, hasSecret := span.RequestHeaders["X-Secret"]
	assert.False(t, hasSecret, "X-Secret should be excluded by the first rule")
}

func TestGenericParsingSpan_RuleOrderIncludeBeforeExclude(t *testing.T) {
	// Swapping the rule order: include-all-X before exclude-X-Secret means X-Secret is included.
	cfg := config.HTTPGenericParsingConfig{
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
				Scope:  config.HTTPParsingScopeBoth,
				Match:  config.HTTPParsingMatch{Regex: []*regexp.Regexp{re("^X-.*$")}},
			},
			{
				Action: config.HTTPParsingActionExclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeBoth,
				Match:  config.HTTPParsingMatch{Regex: []*regexp.Regexp{re("^X-Secret$")}},
			},
		},
	}
	baseSpan := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"X-Secret": "visible-now", "X-Request-Id": "abc123"},
		nil,
	)

	span, ok := GenericParsingSpan(baseSpan, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, "abc123", span.RequestHeaders["X-Request-Id"])
	assert.Equal(t, "visible-now", span.RequestHeaders["X-Secret"],
		"X-Secret should be included because the include rule comes first")
}

func TestGenericParsingSpan_RuleOrderObfuscateBeforeInclude(t *testing.T) {
	// Obfuscate rule for sensitive headers, then include-all, then verify order matters.
	cfg := config.HTTPGenericParsingConfig{
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
				Scope:  config.HTTPParsingScopeBoth,
				Match:  config.HTTPParsingMatch{Regex: []*regexp.Regexp{re("^Authorization$"), re("^Cookie$")}},
			},
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeBoth,
				Match:  config.HTTPParsingMatch{Regex: []*regexp.Regexp{re(".*")}},
			},
		},
	}
	baseSpan := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{
			"Authorization": "Bearer token",
			"Cookie":        "session=abc",
			"Content-Type":  "application/json",
		},
		nil,
	)

	span, ok := GenericParsingSpan(baseSpan, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, "[REDACTED]", span.RequestHeaders["Authorization"])
	assert.Equal(t, "[REDACTED]", span.RequestHeaders["Cookie"])
	assert.Equal(t, "application/json", span.RequestHeaders["Content-Type"])
}

func TestGenericParsingSpan_ExplicitExcludeRule(t *testing.T) {
	// Include by default, but explicitly exclude Authorization.
	cfg := config.HTTPGenericParsingConfig{
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
				Scope:  config.HTTPParsingScopeBoth,
				Match:  config.HTTPParsingMatch{Regex: []*regexp.Regexp{re("^Authorization$")}},
			},
		},
	}
	baseSpan := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"Authorization": "Bearer secret", "Content-Type": "text/plain"},
		nil,
	)

	span, ok := GenericParsingSpan(baseSpan, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, "text/plain", span.RequestHeaders["Content-Type"])
	_, hasAuth := span.RequestHeaders["Authorization"]
	assert.False(t, hasAuth)
}

func TestGenericParsingSpan_MixedScopeRuleOrder(t *testing.T) {
	// First rule: obfuscate Authorization on request only.
	// Second rule: include all on both scopes.
	// Authorization in response should be included (not obfuscated) because
	// the first rule doesn't apply to responses.
	cfg := config.HTTPGenericParsingConfig{
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
				Match:  config.HTTPParsingMatch{Regex: []*regexp.Regexp{re("^Authorization$")}},
			},
			{
				Action: config.HTTPParsingActionInclude,
				Type:   config.HTTPParsingRuleTypeHeaders,
				Scope:  config.HTTPParsingScopeBoth,
				Match:  config.HTTPParsingMatch{Regex: []*regexp.Regexp{re(".*")}},
			},
		},
	}
	baseSpan := &request.Span{Method: "GET", Path: "/test"}
	req, resp := makeReqResp(
		map[string]string{"Authorization": "Bearer token", "X-Foo": "bar"},
		map[string]string{"Authorization": "Bearer resp-token", "X-Bar": "baz"},
	)

	span, ok := GenericParsingSpan(baseSpan, req, resp, cfg)
	require.True(t, ok)
	assert.Equal(t, "***", span.RequestHeaders["Authorization"])
	assert.Equal(t, "bar", span.RequestHeaders["X-Foo"])
	assert.Equal(t, "Bearer resp-token", span.ResponseHeaders["Authorization"],
		"response Authorization should be included, not obfuscated")
	assert.Equal(t, "baz", span.ResponseHeaders["X-Bar"])
}
