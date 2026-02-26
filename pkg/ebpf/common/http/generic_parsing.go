// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"net/http"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
)

// GenericParsingSpan applies generic HTTP parsing rules to extract headers into the span.
// Regex patterns in rules are already compiled during YAML deserialization.
// Unlike other parsers, this enriches the span with headers rather than replacing it.
func GenericParsingSpan(
	baseSpan *request.Span,
	req *http.Request,
	resp *http.Response,
	cfg config.HTTPGenericParsingConfig,
) (request.Span, bool) {
	reqHeaders := make(map[string]string)
	respHeaders := make(map[string]string)

	// Process request headers
	for name, values := range req.Header {
		action := resolveHeaderAction(name, cfg.Rules, cfg.Policy, config.HTTPParsingScopeRequest)
		applyHeaderAction(action, name, values, reqHeaders, cfg.Policy.ObfuscationString)
	}

	// Process response headers
	for name, values := range resp.Header {
		action := resolveHeaderAction(name, cfg.Rules, cfg.Policy, config.HTTPParsingScopeResponse)
		applyHeaderAction(action, name, values, respHeaders, cfg.Policy.ObfuscationString)
	}

	if len(reqHeaders) == 0 && len(respHeaders) == 0 {
		return *baseSpan, false
	}

	if len(reqHeaders) > 0 {
		baseSpan.RequestHeaders = reqHeaders
	}
	if len(respHeaders) > 0 {
		baseSpan.ResponseHeaders = respHeaders
	}
	return *baseSpan, true
}

// resolveHeaderAction determines what action to take for a given header name
// by evaluating rules in order (first_match_wins).
func resolveHeaderAction(
	headerName string,
	rules []config.HTTPParsingRule,
	policy config.HTTPParsingPolicy,
	scope config.HTTPParsingScope,
) config.HTTPParsingAction {
	for _, rule := range rules {
		if rule.Type != config.HTTPParsingRuleTypeHeaders {
			continue
		}
		if !scopeApplies(rule.Scope, scope) {
			continue
		}
		for _, re := range rule.Match.Regex {
			if re.MatchString(headerName) {
				return rule.Action
			}
		}
	}
	return policy.DefaultAction
}

// scopeApplies returns true if the rule scope covers the given header source.
func scopeApplies(ruleScope config.HTTPParsingScope, headerSource config.HTTPParsingScope) bool {
	return ruleScope == config.HTTPParsingScopeBoth || ruleScope == headerSource
}

// applyHeaderAction adds the header to the map based on the resolved action.
func applyHeaderAction(
	action config.HTTPParsingAction,
	name string,
	values []string,
	headers map[string]string,
	obfuscationString string,
) {
	switch action {
	case config.HTTPParsingActionInclude:
		if len(values) > 0 {
			headers[name] = values[0]
		}
	case config.HTTPParsingActionObfuscate:
		headers[name] = obfuscationString
	case config.HTTPParsingActionExclude:
		// do nothing
	}
}
