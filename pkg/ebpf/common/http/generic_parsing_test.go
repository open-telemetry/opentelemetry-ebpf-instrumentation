// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"net/http"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

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

func TestHTTPParsingMatch_UnmarshalYAML(t *testing.T) {
	yamlData := `
rules:
  - action: include
    type: headers
    scope: both
    match:
      regex:
        - "^Content-Type$"
        - "^X-Request-Id$"
      case_sensitive: false
`
	var cfg config.HTTPGenericParsingConfig
	err := yaml.Unmarshal([]byte(yamlData), &cfg)
	require.NoError(t, err)
	require.Len(t, cfg.Rules, 1)
	require.Len(t, cfg.Rules[0].Match.Regex, 2)
	// case_sensitive=false means (?i) prefix
	assert.True(t, cfg.Rules[0].Match.Regex[0].MatchString("content-type"))
	assert.True(t, cfg.Rules[0].Match.Regex[0].MatchString("Content-Type"))
}
