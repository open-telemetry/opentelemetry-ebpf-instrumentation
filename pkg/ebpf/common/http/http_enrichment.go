// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"net/http"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
)

// EnrichHTTPSpan applies generic HTTP parsing rules to extract headers into the span.
// Glob patterns in rules are already compiled during YAML deserialization.
// Unlike other parsers, this enriches the span with headers rather than replacing it.
func EnrichHTTPSpan(
	baseSpan *request.Span,
	req *http.Request,
	resp *http.Response,
	cfg config.EnrichmentConfig,
) bool {
	reqHeaders := processHeaders(req.Header, cfg, config.HTTPParsingScopeRequest)
	respHeaders := processHeaders(resp.Header, cfg, config.HTTPParsingScopeResponse)

	if len(reqHeaders) == 0 && len(respHeaders) == 0 {
		return false
	}

	if len(reqHeaders) > 0 {
		baseSpan.RequestHeaders = reqHeaders
	}
	if len(respHeaders) > 0 {
		baseSpan.ResponseHeaders = respHeaders
	}
	return true
}

// processHeaders evaluates rules against each header and returns a map of
// headers to include or obfuscate.
func processHeaders(
	headers http.Header,
	cfg config.EnrichmentConfig,
	scope config.HTTPParsingScope,
) map[string]string {
	result := make(map[string]string)
	for name, values := range headers {
		action := resolveHeaderAction(name, cfg.Rules, cfg.Policy, scope)
		applyHeaderAction(action, name, values, result, cfg.Policy.ObfuscationString)
	}
	return result
}

// resolveHeaderAction determines what action to take for a given header name
// by evaluating rules in order (first_match_wins).
// For case-insensitive rules, the header name is lowercased once and reused.
func resolveHeaderAction(
	headerName string,
	rules []config.HTTPParsingRule,
	policy config.HTTPParsingPolicy,
	scope config.HTTPParsingScope,
) config.HTTPParsingAction {
	var lowerName string

	for _, rule := range rules {
		if rule.Type != config.HTTPParsingRuleTypeHeaders {
			continue
		}
		if !scopeApplies(rule.Scope, scope) {
			continue
		}
		matchName := headerName
		if !rule.Match.CaseSensitive {
			if lowerName == "" {
				lowerName = strings.ToLower(headerName)
			}
			matchName = lowerName
		}
		for i := range rule.Match.Patterns {
			if rule.Match.Patterns[i].MatchString(matchName) {
				return rule.Action
			}
		}
	}
	return policy.DefaultAction
}

// scopeApplies returns true if the rule scope covers the given header source.
func scopeApplies(ruleScope config.HTTPParsingScope, headerSource config.HTTPParsingScope) bool {
	return ruleScope == config.HTTPParsingScopeAll || ruleScope == headerSource
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
