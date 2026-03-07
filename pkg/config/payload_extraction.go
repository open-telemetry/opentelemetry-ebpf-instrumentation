// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "go.opentelemetry.io/obi/pkg/config"

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

type PayloadExtraction struct {
	HTTP HTTPConfig `yaml:"http"`
}

func (p PayloadExtraction) Enabled() bool {
	return p.HTTP.GraphQL.Enabled || p.HTTP.Elasticsearch.Enabled || p.HTTP.AWS.Enabled || p.HTTP.SQLPP.Enabled || p.HTTP.OpenAI.Enabled || p.HTTP.Enrichment.Enabled
}

type HTTPConfig struct {
	// GraphQL payload extraction and parsing
	GraphQL GraphQLConfig `yaml:"graphql"`
	// Elasticsearch payload extraction and parsing
	Elasticsearch ElasticsearchConfig `yaml:"elasticsearch"`
	// AWS payload extraction and parsing
	AWS AWSConfig `yaml:"aws"`
	// SQL++ payload extraction and parsing (Couchbase and other SQL++ databases)
	SQLPP SQLPPConfig `yaml:"sqlpp"`
	// OpenAI payload extraction
	OpenAI OpenAIConfig `yaml:"openai"`
	// Enrichment HTTP header and payload extraction with policy-based rules
	Enrichment EnrichmentConfig `yaml:"enrichment"`
}

type GraphQLConfig struct {
	// Enable GraphQL payload extraction and parsing
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_GRAPHQL_ENABLED" validate:"boolean"`
}

type AWSConfig struct {
	// Enable AWS services (S3, SQS, etc.) payload extraction and parsing
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_AWS_ENABLED" validate:"boolean"`
}

type ElasticsearchConfig struct {
	// Enable Elasticsearch payload extraction and parsing
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_ELASTICSEARCH_ENABLED" validate:"boolean"`
}

type SQLPPConfig struct {
	// Enable SQL++ payload extraction and parsing
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_SQLPP_ENABLED" validate:"boolean"`
	// EndpointPatterns specifies URL path patterns to detect SQL++ endpoints
	// Example: ["/query/service", "/query"]
	EndpointPatterns []string `yaml:"endpoint_patterns" env:"OTEL_EBPF_HTTP_SQLPP_ENDPOINT_PATTERNS"`
}

type OpenAIConfig struct {
	// Enable OpenAI payload extraction and parsing
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_OPENAI_ENABLED" validate:"boolean"`
}

// EnrichmentConfig configures generic HTTP header and payload extraction.
type EnrichmentConfig struct {
	// Enable generic HTTP header and payload extraction
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_HTTP_GENERIC_PARSING_ENABLED" validate:"boolean"`
	// Policy controls the default behavior and matching strategy
	Policy HTTPParsingPolicy `yaml:"policy"`
	// Rules is an ordered list of include/exclude/obfuscate rules.
	// Rules are evaluated according to Policy.MatchOrder.
	Rules []HTTPParsingRule `yaml:"rules"`
}

// HTTPParsingPolicy defines the default action and match strategy for generic parsing rules.
type HTTPParsingPolicy struct {
	// DefaultAction specifies what to do when no rule matches: "include" or "exclude"
	DefaultAction HTTPParsingAction `yaml:"default_action" env:"OTEL_EBPF_HTTP_PARSING_DEFAULT_ACTION"`
	// MatchOrder controls how rules are evaluated: "first_match_wins"
	MatchOrder HTTPParsingMatchOrder `yaml:"match_order" env:"OTEL_EBPF_HTTP_PARSING_MATCH_ORDER"`
	// ObfuscationString is the replacement string used when a rule's action is "obfuscate"
	ObfuscationString string `yaml:"obfuscation_string" env:"OTEL_EBPF_HTTP_PARSING_OBFUSCATION_STRING"`
}

// HTTPParsingRule defines a single include/exclude/obfuscate rule for HTTP header and payload extraction.
type HTTPParsingRule struct {
	// Action of the rule: "include", "exclude", or "obfuscate"
	Action HTTPParsingAction `yaml:"action"`
	// Type specifies what this rule matches against: "headers"
	Type HTTPParsingRuleType `yaml:"type"`
	// Scope of the rule: "request", "response", or "all"
	Scope HTTPParsingScope `yaml:"scope"`
	// Match defines the matching criteria for this rule
	Match HTTPParsingMatch `yaml:"match"`
}

// HTTPParsingRuleType specifies the target of a parsing rule.
type HTTPParsingRuleType string

const (
	HTTPParsingRuleTypeHeaders HTTPParsingRuleType = "headers"
)

func (t *HTTPParsingRuleType) UnmarshalText(text []byte) error {
	str := HTTPParsingRuleType(strings.TrimSpace(strings.ToLower(string(text))))
	switch str {
	case HTTPParsingRuleTypeHeaders:
		*t = str
		return nil
	default:
		return fmt.Errorf("invalid parsing rule type: %q (valid: headers)", string(text))
	}
}

// HTTPParsingMatch defines matching criteria for an HTTP parsing rule.
type HTTPParsingMatch struct {
	// Patterns is a list of compiled glob matchers.
	Patterns []services.GlobAttr `yaml:"patterns"`
	// CaseSensitive controls whether matching is case-sensitive.
	CaseSensitive bool `yaml:"case_sensitive"`
}

// UnmarshalYAML deserializes the match config and compiles glob patterns.
func (m *HTTPParsingMatch) UnmarshalYAML(value *yaml.Node) error {
	var raw struct {
		Patterns      []string `yaml:"patterns"`
		CaseSensitive bool     `yaml:"case_sensitive"`
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}

	m.CaseSensitive = raw.CaseSensitive
	m.Patterns = make([]services.GlobAttr, 0, len(raw.Patterns))
	for _, pattern := range raw.Patterns {
		compilePattern := pattern
		if !m.CaseSensitive {
			compilePattern = strings.ToLower(pattern)
		}
		m.Patterns = append(m.Patterns, services.NewGlob(compilePattern))
	}
	return nil
}

// HTTPParsingAction represents the action for a generic parsing rule or default policy.
type HTTPParsingAction string

const (
	HTTPParsingActionInclude   HTTPParsingAction = "include"
	HTTPParsingActionExclude   HTTPParsingAction = "exclude"
	HTTPParsingActionObfuscate HTTPParsingAction = "obfuscate"
)

func (a *HTTPParsingAction) UnmarshalText(text []byte) error {
	str := HTTPParsingAction(strings.TrimSpace(strings.ToLower(string(text))))
	switch str {
	case HTTPParsingActionInclude, HTTPParsingActionExclude, HTTPParsingActionObfuscate:
		*a = str
		return nil
	default:
		return fmt.Errorf("invalid parsing action: %q (valid: include, exclude, obfuscate)", string(text))
	}
}

// HTTPParsingAction represents the action for a http parsing rule or default policy.
type HTTPParsingScope string

const (
	HTTPParsingScopeRequest  HTTPParsingScope = "request"
	HTTPParsingScopeResponse HTTPParsingScope = "response"
	HTTPParsingScopeAll      HTTPParsingScope = "all"
)

func (a *HTTPParsingScope) UnmarshalText(text []byte) error {
	str := HTTPParsingScope(strings.TrimSpace(strings.ToLower(string(text))))
	switch str {
	case HTTPParsingScopeRequest, HTTPParsingScopeResponse, HTTPParsingScopeAll:
		*a = str
		return nil
	default:
		return fmt.Errorf("invalid parsing scope: %q (valid: include, exclude, obfuscate)", string(text))
	}
}

// HTTPParsingMatchOrder controls how rules are evaluated.
type HTTPParsingMatchOrder string

const (
	HTTPParsingMatchOrderFirstMatchWins HTTPParsingMatchOrder = "first_match_wins"
)

func (m *HTTPParsingMatchOrder) UnmarshalText(text []byte) error {
	str := HTTPParsingMatchOrder(strings.TrimSpace(strings.ToLower(string(text))))
	switch str {
	case HTTPParsingMatchOrderFirstMatchWins:
		*m = str
		return nil
	default:
		return fmt.Errorf("invalid parsing match order: %q (valid: first_match_wins)", string(text))
	}
}
