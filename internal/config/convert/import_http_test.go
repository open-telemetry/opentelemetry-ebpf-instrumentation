// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/transform"
)

func TestV2ToRuntimeHTTPRoutesRoundTrip(t *testing.T) {
	t.Parallel()

	cfg := defaultRuntimeConfig()
	cfg.Routes.Unmatch = transform.UnmatchPath
	cfg.Routes.Patterns = []string{"/products/{id}", "/orders/{id}"}
	cfg.Routes.IgnorePatterns = []string{"/health", "/ready"}
	cfg.Routes.IgnoredEvents = transform.IgnoreTraces
	cfg.Routes.WildcardChar = "#"
	cfg.Routes.MaxPathSegmentCardinality = 22
	cfg.Discovery.RouteHarvesterTimeout = 23 * time.Second
	cfg.Discovery.DisabledRouteHarvesters = []services.RouteHarvesterLanguage{
		services.RouteHarvesterLanguageJava,
		services.RouteHarvesterLanguageNodejs,
	}
	cfg.Discovery.RouteHarvestConfig.JavaHarvestDelay = 24 * time.Second

	_, ext := RuntimeToV2(&cfg)

	got, err := V2ToRuntime(ext)
	require.NoError(t, err)

	require.NotNil(t, got.Routes)
	// A symmetric global routes config round-trips back to the global
	// representation the user authored, not a directional one.
	require.Nil(t, got.Routes.Directional)
	require.Equal(t, cfg.Routes.Unmatch, got.Routes.Unmatch)
	require.Equal(t, cfg.Routes.Patterns, got.Routes.Patterns)
	require.Equal(t, cfg.Routes.IgnorePatterns, got.Routes.IgnorePatterns)
	require.Equal(t, cfg.Routes.IgnoredEvents, got.Routes.IgnoredEvents)
	require.Equal(t, cfg.Routes.WildcardChar, got.Routes.WildcardChar)
	require.Equal(t, cfg.Routes.MaxPathSegmentCardinality, got.Routes.MaxPathSegmentCardinality)
	require.Equal(t, cfg.Routes.DirectionalPolicies(), got.Routes.DirectionalPolicies())
	require.Equal(t, cfg.Discovery.RouteHarvesterTimeout, got.Discovery.RouteHarvesterTimeout)
	require.Equal(t, cfg.Discovery.DisabledRouteHarvesters, got.Discovery.DisabledRouteHarvesters)
	require.Equal(t, cfg.Discovery.RouteHarvestConfig.JavaHarvestDelay, got.Discovery.RouteHarvestConfig.JavaHarvestDelay)
}

func TestV2ToRuntimeHTTPNilRoutesRoundTrip(t *testing.T) {
	t.Parallel()

	cfg := defaultRuntimeConfig()
	cfg.Routes = nil
	cfg.Discovery.RouteHarvesterTimeout = 25 * time.Second
	cfg.Discovery.DisabledRouteHarvesters = []services.RouteHarvesterLanguage{
		services.RouteHarvesterLanguageGo,
	}
	cfg.Discovery.RouteHarvestConfig.JavaHarvestDelay = 26 * time.Second

	_, ext := RuntimeToV2(&cfg)

	got, err := V2ToRuntime(ext)
	require.NoError(t, err)

	require.Nil(t, got.Routes)
	require.Equal(t, cfg.Discovery.RouteHarvesterTimeout, got.Discovery.RouteHarvesterTimeout)
	require.Equal(t, cfg.Discovery.DisabledRouteHarvesters, got.Discovery.DisabledRouteHarvesters)
	require.Equal(t, cfg.Discovery.RouteHarvestConfig.JavaHarvestDelay, got.Discovery.RouteHarvestConfig.JavaHarvestDelay)
}

func TestV2ToRuntimeHTTPRuleRoutesWithoutGlobalRoutes(t *testing.T) {
	t.Parallel()

	cfg := defaultRuntimeConfig()
	cfg.Routes = nil
	_, ext := RuntimeToV2(&cfg)

	incomingPatterns := []string{"/orders/{id}"}
	incomingIgnored := []string{"/health"}
	ext.Capture.Rules = append(ext.Capture.Rules, schema.Rule{
		Action: schema.CaptureActionInclude,
		Match: schema.RuleMatch{
			Process: schema.RuleProcessMatch{ExePathGlob: []string{"/srv/*"}},
		},
		Refine: schema.RuleRefinement{
			HTTP: &schema.HTTPRefinement{
				Routes: schema.HTTPRefinementRoutes{
					Incoming: &schema.HTTPRoutePolicy{
						Patterns:        &incomingPatterns,
						IgnoredPatterns: &incomingIgnored,
					},
				},
			},
		},
	})

	got, err := V2ToRuntime(ext)
	require.NoError(t, err)
	require.NotNil(t, got.Routes)
	require.NotNil(t, got.Routes.Directional)
	require.True(t, got.Routes.DirectionalRuleOnly)
	require.Equal(t, services.UnmatchUnset, got.Routes.Directional.Incoming.Unmatch)
	require.Equal(t, services.UnmatchUnset, got.Routes.Directional.Outgoing.Unmatch)

	var ruleRoutes *services.CustomRoutesConfig
	for i := range got.Discovery.Instrument {
		if got.Discovery.Instrument[i].Routes != nil {
			ruleRoutes = got.Discovery.Instrument[i].Routes
			break
		}
	}
	require.NotNil(t, ruleRoutes)
	require.NotNil(t, ruleRoutes.PolicyOverrides)
	require.Equal(t, incomingPatterns, *ruleRoutes.PolicyOverrides.Incoming.Patterns)
	require.Equal(t, incomingIgnored, *ruleRoutes.PolicyOverrides.Incoming.IgnorePatterns)

	_, roundTrip := RuntimeToV2(got)
	require.Nil(t, roundTrip.Capture.Instrumentation.HTTP.Routes.Incoming)
	require.Nil(t, roundTrip.Capture.Instrumentation.HTTP.Routes.Outgoing)
}

func TestV2ToRuntimeImportsDirectionalHTTPRoutes(t *testing.T) {
	t.Parallel()

	incomingUnmatched := services.UnmatchPath
	incomingPatterns := []string{"/orders/{id}"}
	incomingIgnored := []string{"/health"}
	incomingIgnoreMode := services.IgnoreTraces
	incomingWildcard := "#"
	incomingCardinality := 7
	outgoingUnmatched := services.UnmatchWildcard
	outgoingPatterns := []string{"/inventory/{id}"}

	got, err := V2ToRuntime(&schema.Extension{
		Version: schema.SupportedVersion,
		Capture: schema.Capture{
			Instrumentation: schema.Instrumentation{
				HTTP: schema.HTTPInstrumentation{
					Routes: schema.HTTPRoutes{
						Incoming: &schema.HTTPRoutePolicy{
							Unmatched:                 &incomingUnmatched,
							Patterns:                  &incomingPatterns,
							IgnoredPatterns:           &incomingIgnored,
							IgnoreMode:                &incomingIgnoreMode,
							WildcardChar:              &incomingWildcard,
							MaxPathSegmentCardinality: &incomingCardinality,
						},
						Outgoing: &schema.HTTPRoutePolicy{
							Unmatched: &outgoingUnmatched,
							Patterns:  &outgoingPatterns,
						},
					},
				},
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, got.Routes)
	require.NotNil(t, got.Routes.Directional)
	require.False(t, got.Routes.DirectionalRuleOnly)

	policies := got.Routes.DirectionalPolicies()
	require.Equal(t, incomingUnmatched, policies.Incoming.Unmatch)
	require.Equal(t, incomingPatterns, policies.Incoming.Patterns)
	require.Equal(t, incomingIgnored, policies.Incoming.IgnorePatterns)
	require.Equal(t, incomingIgnoreMode, policies.Incoming.IgnoredEvents)
	require.Equal(t, incomingWildcard, policies.Incoming.WildcardChar)
	require.Equal(t, incomingCardinality, policies.Incoming.MaxPathSegmentCardinality)
	require.Equal(t, outgoingUnmatched, policies.Outgoing.Unmatch)
	require.Equal(t, outgoingPatterns, policies.Outgoing.Patterns)
}

func TestV2ToRuntimePreservesAbsentGlobalHTTPDirection(t *testing.T) {
	t.Parallel()

	cfg := defaultRuntimeConfig()
	_, ext := RuntimeToV2(&cfg)
	incomingPatterns := []string{"/orders/{id}"}
	ext.Capture.Instrumentation.HTTP.Routes.Incoming = &schema.HTTPRoutePolicy{
		Patterns: &incomingPatterns,
	}
	ext.Capture.Instrumentation.HTTP.Routes.Outgoing = nil

	got, err := V2ToRuntime(ext)
	require.NoError(t, err)
	require.NotNil(t, got.Routes)
	require.True(t, got.Routes.HasIncomingPolicy())
	require.False(t, got.Routes.HasOutgoingPolicy())

	policies := got.Routes.DirectionalPolicies()
	require.Equal(t, incomingPatterns, policies.Incoming.Patterns)
	require.Empty(t, policies.Incoming.Unmatch)
	require.Empty(t, policies.Incoming.WildcardChar)
	require.Zero(t, policies.Incoming.MaxPathSegmentCardinality)

	_, roundTrip := RuntimeToV2(got)
	require.NotNil(t, roundTrip.Capture.Instrumentation.HTTP.Routes.Incoming)
	require.Nil(t, roundTrip.Capture.Instrumentation.HTTP.Routes.Outgoing)
}

func TestV2ToRuntimePreservesAbsentGlobalHTTPDirectionWithRule(t *testing.T) {
	t.Parallel()

	cfg := defaultRuntimeConfig()
	_, ext := RuntimeToV2(&cfg)
	incomingPatterns := []string{"/orders/{id}"}
	ext.Capture.Instrumentation.HTTP.Routes.Incoming = &schema.HTTPRoutePolicy{
		Patterns: &incomingPatterns,
	}
	ext.Capture.Instrumentation.HTTP.Routes.Outgoing = nil

	rulePatterns := []string{"/inventory/{id}"}
	ext.Capture.Rules = append(ext.Capture.Rules, schema.Rule{
		Action: schema.CaptureActionInclude,
		Match: schema.RuleMatch{
			Process: schema.RuleProcessMatch{ExePathGlob: []string{"/srv/*"}},
		},
		Refine: schema.RuleRefinement{
			HTTP: &schema.HTTPRefinement{
				Routes: schema.HTTPRefinementRoutes{
					Outgoing: &schema.HTTPRoutePolicy{Patterns: &rulePatterns},
				},
			},
		},
	})

	got, err := V2ToRuntime(ext)
	require.NoError(t, err)
	require.NotNil(t, got.Routes)
	require.False(t, got.Routes.DirectionalRuleOnly)
	require.True(t, got.Routes.HasIncomingPolicy())
	require.False(t, got.Routes.HasOutgoingPolicy())

	policies := got.Routes.DirectionalPolicies()
	require.Empty(t, policies.Incoming.Unmatch)
	require.Equal(t, services.UnmatchUnset, policies.Outgoing.Unmatch)

	_, roundTrip := RuntimeToV2(got)
	require.NotNil(t, roundTrip.Capture.Instrumentation.HTTP.Routes.Incoming)
	require.Nil(t, roundTrip.Capture.Instrumentation.HTTP.Routes.Outgoing)
}

func TestV2ToRuntimeRejectsInvalidDirectionalHTTPRoutes(t *testing.T) {
	t.Parallel()

	invalidUnmatched := services.RouteUnmatch("invalid")
	_, err := V2ToRuntime(&schema.Extension{
		Version: schema.SupportedVersion,
		Capture: schema.Capture{
			Instrumentation: schema.Instrumentation{
				HTTP: schema.HTTPInstrumentation{
					Routes: schema.HTTPRoutes{
						Incoming: &schema.HTTPRoutePolicy{Unmatched: &invalidUnmatched},
					},
				},
			},
		},
	})
	require.EqualError(t, err, `capture.instrumentation.http.routes.incoming.unmatched has invalid value "invalid"`)
}

func TestV2ToRuntimeValidatesDirectionalHTTPWildcard(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		wildcard string
		wantErr  string
	}{
		{name: "empty"},
		{name: "ASCII", wildcard: "#"},
		{
			name:     "NUL",
			wildcard: "\x00",
			wantErr: "capture.instrumentation.http.routes.incoming.wildcard_char " +
				"must be empty or contain one nonzero ASCII byte",
		},
		{
			name:     "Unicode",
			wildcard: "•",
			wantErr: "capture.instrumentation.http.routes.incoming.wildcard_char " +
				"must be empty or contain one nonzero ASCII byte",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := V2ToRuntime(&schema.Extension{
				Version: schema.SupportedVersion,
				Capture: schema.Capture{
					Instrumentation: schema.Instrumentation{
						HTTP: schema.HTTPInstrumentation{
							Routes: schema.HTTPRoutes{
								Incoming: &schema.HTTPRoutePolicy{WildcardChar: &tc.wildcard},
							},
						},
					},
				},
			})
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tc.wantErr)
		})
	}
}

func TestV2ToRuntimeHTTPPayloadExtractionRoundTrip(t *testing.T) {
	t.Parallel()

	cfg := defaultRuntimeConfig()
	http := &cfg.EBPF.PayloadExtraction.HTTP
	http.GraphQL.Enabled = true
	http.Elasticsearch.Enabled = true
	http.AWS.Enabled = true
	http.SQLPP.Enabled = true
	http.SQLPP.EndpointPatterns = []string{"/query", "/analytics"}
	http.GenAI.OpenAI.Enabled = true
	http.GenAI.Anthropic.Enabled = true
	http.GenAI.Gemini.Enabled = true
	http.GenAI.Qwen.Enabled = true
	http.GenAI.Bedrock.Enabled = true
	http.GenAI.MCP.Enabled = true
	http.GenAI.Embedding.Enabled = true
	http.GenAI.Rerank.Enabled = true
	http.GenAI.Retrieval.Enabled = true
	http.GenAI.Ollama.Enabled = true
	http.JSONRPC.Enabled = true
	http.Enrichment.Enabled = true
	http.Enrichment.Policy.DefaultAction.Headers = config.HTTPParsingActionInclude
	http.Enrichment.Policy.DefaultAction.Body = config.HTTPParsingActionObfuscate
	http.Enrichment.Policy.DefaultObfuscationString = "[redacted]"
	jsonPath, err := config.NewJSONPathExpr("$.secret")
	require.NoError(t, err)
	http.Enrichment.Rules = []config.HTTPParsingRule{
		{
			Action: config.HTTPParsingActionObfuscate,
			Type:   config.HTTPParsingRuleTypeBody,
			Scope:  config.HTTPParsingScopeRequest,
			Match: config.HTTPParsingMatch{
				ObfuscationJSONPaths: []config.JSONPathExpr{jsonPath},
				Methods:              []config.HTTPMethod{config.HTTPMethodPOST},
			},
		},
	}

	_, ext := RuntimeToV2(&cfg)

	got, err := V2ToRuntime(ext)
	require.NoError(t, err)

	gotHTTP := got.EBPF.PayloadExtraction.HTTP
	require.True(t, gotHTTP.GraphQL.Enabled)
	require.True(t, gotHTTP.Elasticsearch.Enabled)
	require.True(t, gotHTTP.AWS.Enabled)
	require.True(t, gotHTTP.SQLPP.Enabled)
	require.Equal(t, []string{"/query", "/analytics"}, gotHTTP.SQLPP.EndpointPatterns)
	require.True(t, gotHTTP.GenAI.OpenAI.Enabled)
	require.True(t, gotHTTP.GenAI.Anthropic.Enabled)
	require.True(t, gotHTTP.GenAI.Gemini.Enabled)
	require.True(t, gotHTTP.GenAI.Qwen.Enabled)
	require.True(t, gotHTTP.GenAI.Bedrock.Enabled)
	require.True(t, gotHTTP.GenAI.MCP.Enabled)
	require.True(t, gotHTTP.GenAI.Embedding.Enabled)
	require.True(t, gotHTTP.GenAI.Rerank.Enabled)
	require.True(t, gotHTTP.GenAI.Retrieval.Enabled)
	require.True(t, gotHTTP.GenAI.Ollama.Enabled)
	require.True(t, gotHTTP.JSONRPC.Enabled)
	require.True(t, gotHTTP.Enrichment.Enabled)
	require.Equal(t, http.Enrichment.Policy, gotHTTP.Enrichment.Policy)
	require.Equal(t, http.Enrichment.Rules, gotHTTP.Enrichment.Rules)
}

func TestV2ToRuntimeHTTPApplicationFiltersRoundTrip(t *testing.T) {
	t.Parallel()

	statusCode := 500
	cfg := defaultRuntimeConfig()
	cfg.Filters.Application = filter.AttributeFamilyConfig{
		"http.status_code": {Equals: &statusCode},
		"service.name":     {Match: "checkout-*"},
	}

	_, ext := RuntimeToV2(&cfg)
	require.NotNil(t, ext.Capture.Instrumentation.Aerospike)
	require.Equal(
		t,
		ext.Capture.Instrumentation.HTTP.Filters,
		ext.Capture.Instrumentation.Aerospike.Filters,
	)

	got, err := V2ToRuntime(ext)
	require.NoError(t, err)

	require.Equal(t, cfg.Filters.Application, got.Filters.Application)
}

func TestV2ToRuntimeHTTPApplicationFiltersRejectsOneSignal(t *testing.T) {
	t.Parallel()

	filters := schema.AttributeFilters{
		"service.name": {Match: "checkout-*"},
	}

	_, err := V2ToRuntime(&schema.Extension{
		Version: schema.SupportedVersion,
		Capture: schema.Capture{
			Instrumentation: schema.Instrumentation{
				HTTP: schema.HTTPInstrumentation{
					Filters: schema.SignalFilters{
						Traces: filters,
					},
				},
			},
		},
	})
	require.ErrorContains(
		t,
		err,
		"capture.instrumentation.http.filters.metrics cannot differ from "+
			"capture.instrumentation.http.filters.traces",
	)
}

func TestV2ToRuntimeHTTPApplicationFiltersRejectsConflictingSignals(t *testing.T) {
	t.Parallel()

	statusCode := 500
	_, err := V2ToRuntime(&schema.Extension{
		Version: schema.SupportedVersion,
		Capture: schema.Capture{
			Instrumentation: schema.Instrumentation{
				HTTP: schema.HTTPInstrumentation{
					Filters: schema.SignalFilters{
						Traces: schema.AttributeFilters{
							"service.name": {Match: "checkout-*"},
						},
						Metrics: schema.AttributeFilters{
							"http.status_code": {Equals: &statusCode},
						},
					},
				},
			},
		},
	})

	require.ErrorContains(t, err, "capture.instrumentation.http.filters")
}

func TestV2ToRuntimeApplicationFiltersRejectsProtocolScope(t *testing.T) {
	t.Parallel()

	_, err := V2ToRuntime(&schema.Extension{
		Version: schema.SupportedVersion,
		Capture: schema.Capture{
			Instrumentation: schema.Instrumentation{
				GRPC: schema.ProtocolInstrumentation{
					Filters: schema.SignalFilters{
						Traces: schema.AttributeFilters{
							"service.name": {Match: "checkout-*"},
						},
					},
				},
			},
		},
	})
	require.ErrorContains(t, err, "capture.instrumentation.grpc.filters.traces")
}

func TestV2ToRuntimeRejectsDivergentProtocolFilters(t *testing.T) {
	t.Parallel()

	statusCode := 500
	cfg := defaultRuntimeConfig()
	cfg.Filters.Application = filter.AttributeFamilyConfig{
		"http.status_code": {Equals: &statusCode},
	}
	_, ext := RuntimeToV2(&cfg)
	ext.Capture.Instrumentation.GRPC.Filters.Traces = schema.AttributeFilters{
		"service.name": {Match: "checkout-*"},
	}

	_, err := V2ToRuntime(ext)
	require.ErrorContains(
		t,
		err,
		"capture.instrumentation.grpc.filters.traces cannot differ from "+
			"capture.instrumentation.http.filters.traces",
	)
}

func TestV2ToRuntimeRejectsDivergentAerospikeFilters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		signal string
		mutate func(*schema.AerospikeInstrumentation)
	}{
		{
			name:   "traces",
			signal: "traces",
			mutate: func(aerospike *schema.AerospikeInstrumentation) {
				aerospike.Filters.Traces = schema.AttributeFilters{
					"service.name": {Match: "checkout-*"},
				}
			},
		},
		{
			name:   "metrics",
			signal: "metrics",
			mutate: func(aerospike *schema.AerospikeInstrumentation) {
				aerospike.Filters.Metrics = schema.AttributeFilters{
					"service.name": {Match: "checkout-*"},
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statusCode := 500
			cfg := defaultRuntimeConfig()
			cfg.Filters.Application = filter.AttributeFamilyConfig{
				"http.status_code": {Equals: &statusCode},
			}
			_, ext := RuntimeToV2(&cfg)
			require.NotNil(t, ext.Capture.Instrumentation.Aerospike)
			test.mutate(ext.Capture.Instrumentation.Aerospike)

			_, err := V2ToRuntime(ext)
			require.ErrorContains(
				t,
				err,
				"capture.instrumentation.aerospike.filters."+test.signal+" cannot differ from "+
					"capture.instrumentation.http.filters.traces because the runtime uses one application filter",
			)
		})
	}
}

func TestV2ToRuntimeHTTPPayloadExtractionRejectsUnknownEnabled(t *testing.T) {
	t.Parallel()

	_, err := V2ToRuntime(&schema.Extension{
		Version: schema.SupportedVersion,
		Capture: schema.Capture{
			Instrumentation: schema.Instrumentation{
				HTTP: schema.HTTPInstrumentation{
					PayloadExtraction: schema.PayloadExtraction{
						Enabled: []string{
							payloadExtractorGraphQL,
							"unknown",
						},
					},
				},
			},
		},
	})

	require.ErrorContains(t, err, `capture.instrumentation.http.payload_extraction.enabled[1]: unknown payload extractor "unknown"`)
}
