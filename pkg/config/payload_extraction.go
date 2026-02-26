// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "go.opentelemetry.io/obi/pkg/config"

import (
	"fmt"
	"regexp"
	"strings"
)

type PayloadExtraction struct {
	HTTP HTTPConfig `yaml:"http"`
}

func (p PayloadExtraction) Enabled() bool {
	return p.HTTP.GraphQL.Enabled || p.HTTP.Elasticsearch.Enabled || p.HTTP.AWS.Enabled || p.HTTP.SQLPP.Enabled || p.HTTP.OpenAI.Enabled || p.HTTP.GenericParsing.Enabled
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
	// Generic HTTP header and payload extraction with policy-based rules
	GenericParsing HTTPGenericParsingConfig `yaml:"generic"`
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

// HTTPGenericParsingConfig configures generic HTTP header and payload extraction.
type HTTPGenericParsingConfig struct {
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
	// Scope of the rule: "request", "response", or "both"
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
// Regex patterns are compiled during YAML unmarshaling. When CaseSensitive
// is false (the default), patterns are automatically wrapped with (?i).
type HTTPParsingMatch struct {
	// Regex is a list of compiled regular expressions to match against.
	Regex []*regexp.Regexp `yaml:"-"`
	// CaseSensitive controls whether matching is case-sensitive.
	CaseSensitive bool `yaml:"case_sensitive"`
}

// UnmarshalYAML deserializes the match config and compiles regex patterns.
func (m *HTTPParsingMatch) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Use a raw struct to capture the string patterns before compiling.
	var raw struct {
		Regex         []string `yaml:"regex"`
		CaseSensitive bool     `yaml:"case_sensitive"`
	}
	if err := unmarshal(&raw); err != nil {
		return err
	}

	m.CaseSensitive = raw.CaseSensitive
	m.Regex = make([]*regexp.Regexp, 0, len(raw.Regex))
	for _, pattern := range raw.Regex {
		if !m.CaseSensitive {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid regex %q in parsing match: %w", pattern, err)
		}
		m.Regex = append(m.Regex, re)
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
	HTTPParsingScopeBoth     HTTPParsingScope = "both"
)

func (a *HTTPParsingScope) UnmarshalText(text []byte) error {
	str := HTTPParsingScope(strings.TrimSpace(strings.ToLower(string(text))))
	switch str {
	case HTTPParsingScopeRequest, HTTPParsingScopeResponse, HTTPParsingScopeBoth:
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
