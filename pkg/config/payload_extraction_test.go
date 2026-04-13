// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

func TestEnrichmentConfig_Validate_HeaderRules(t *testing.T) {
	tests := []struct {
		name    string
		rules   []HTTPParsingRule
		wantErr string
	}{
		{
			name: "valid header rule",
			rules: []HTTPParsingRule{
				{
					Action: HTTPParsingActionInclude,
					Type:   HTTPParsingRuleTypeHeaders,
					Scope:  HTTPParsingScopeAll,
					Match: HTTPParsingMatch{
						Patterns: []services.GlobAttr{services.NewGlob("Content-Type")},
					},
				},
			},
		},
		{
			name: "header rule without patterns",
			rules: []HTTPParsingRule{
				{
					Action: HTTPParsingActionInclude,
					Type:   HTTPParsingRuleTypeHeaders,
					Scope:  HTTPParsingScopeAll,
					Match:  HTTPParsingMatch{},
				},
			},
			wantErr: "rule 0: header rules require at least one pattern",
		},
		{
			name: "header rule with obfuscation_json_paths",
			rules: []HTTPParsingRule{
				{
					Action: HTTPParsingActionObfuscate,
					Type:   HTTPParsingRuleTypeHeaders,
					Scope:  HTTPParsingScopeAll,
					Match: HTTPParsingMatch{
						Patterns:             []services.GlobAttr{services.NewGlob("Authorization")},
						ObfuscationJSONPaths: []JSONPathExpr{{str: "$.password"}},
					},
				},
			},
			wantErr: "rule 0: header rules cannot use obfuscation_json_paths",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := EnrichmentConfig{Rules: tt.rules}
			err := cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestEnrichmentConfig_Validate_BodyRules(t *testing.T) {
	jsonPath, _ := NewJSONPathExpr("$.password")

	tests := []struct {
		name    string
		rules   []HTTPParsingRule
		wantErr string
	}{
		{
			name: "valid body include rule",
			rules: []HTTPParsingRule{
				{
					Action: HTTPParsingActionInclude,
					Type:   HTTPParsingRuleTypeBody,
					Scope:  HTTPParsingScopeRequest,
					Match:  HTTPParsingMatch{},
				},
			},
		},
		{
			name: "valid body obfuscate rule",
			rules: []HTTPParsingRule{
				{
					Action: HTTPParsingActionObfuscate,
					Type:   HTTPParsingRuleTypeBody,
					Scope:  HTTPParsingScopeAll,
					Match: HTTPParsingMatch{
						ObfuscationJSONPaths: []JSONPathExpr{jsonPath},
					},
				},
			},
		},
		{
			name: "body rule with patterns",
			rules: []HTTPParsingRule{
				{
					Action: HTTPParsingActionInclude,
					Type:   HTTPParsingRuleTypeBody,
					Scope:  HTTPParsingScopeAll,
					Match: HTTPParsingMatch{
						Patterns: []services.GlobAttr{services.NewGlob("Content-Type")},
					},
				},
			},
			wantErr: "rule 0: body rules cannot use patterns",
		},
		{
			name: "body rule with case_sensitive",
			rules: []HTTPParsingRule{
				{
					Action: HTTPParsingActionInclude,
					Type:   HTTPParsingRuleTypeBody,
					Scope:  HTTPParsingScopeAll,
					Match: HTTPParsingMatch{
						CaseSensitive: true,
					},
				},
			},
			wantErr: "rule 0: body rules cannot use case_sensitive",
		},
		{
			name: "body obfuscate without json paths",
			rules: []HTTPParsingRule{
				{
					Action: HTTPParsingActionObfuscate,
					Type:   HTTPParsingRuleTypeBody,
					Scope:  HTTPParsingScopeAll,
					Match:  HTTPParsingMatch{},
				},
			},
			wantErr: "rule 0: action \"obfuscate\" on body rule requires obfuscation_json_paths",
		},
		{
			name: "body include with json paths",
			rules: []HTTPParsingRule{
				{
					Action: HTTPParsingActionInclude,
					Type:   HTTPParsingRuleTypeBody,
					Scope:  HTTPParsingScopeAll,
					Match: HTTPParsingMatch{
						ObfuscationJSONPaths: []JSONPathExpr{jsonPath},
					},
				},
			},
			wantErr: "rule 0: obfuscation_json_paths can only be used with action \"obfuscate\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := EnrichmentConfig{Rules: tt.rules}
			err := cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

func TestEnrichmentConfig_Validate_MultipleRules(t *testing.T) {
	jsonPath, _ := NewJSONPathExpr("$.secret")

	cfg := EnrichmentConfig{
		Rules: []HTTPParsingRule{
			{
				Action: HTTPParsingActionInclude,
				Type:   HTTPParsingRuleTypeHeaders,
				Scope:  HTTPParsingScopeAll,
				Match: HTTPParsingMatch{
					Patterns: []services.GlobAttr{services.NewGlob("Content-Type")},
				},
			},
			{
				Action: HTTPParsingActionObfuscate,
				Type:   HTTPParsingRuleTypeBody,
				Scope:  HTTPParsingScopeRequest,
				Match: HTTPParsingMatch{
					ObfuscationJSONPaths: []JSONPathExpr{jsonPath},
				},
			},
		},
	}
	assert.NoError(t, cfg.Validate())
}

func TestEnrichmentConfig_Validate_SecondRuleInvalid(t *testing.T) {
	cfg := EnrichmentConfig{
		Rules: []HTTPParsingRule{
			{
				Action: HTTPParsingActionInclude,
				Type:   HTTPParsingRuleTypeHeaders,
				Scope:  HTTPParsingScopeAll,
				Match: HTTPParsingMatch{
					Patterns: []services.GlobAttr{services.NewGlob("Content-Type")},
				},
			},
			{
				Action: HTTPParsingActionInclude,
				Type:   HTTPParsingRuleTypeHeaders,
				Scope:  HTTPParsingScopeAll,
				Match:  HTTPParsingMatch{},
			},
		},
	}
	assert.EqualError(t, cfg.Validate(), "rule 1: header rules require at least one pattern")
}

func TestEnrichmentConfig_Validate_EmptyRules(t *testing.T) {
	cfg := EnrichmentConfig{}
	assert.NoError(t, cfg.Validate())
}
