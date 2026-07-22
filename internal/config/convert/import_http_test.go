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
	require.Equal(t, cfg.Routes, got.Routes)
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

	got, err := V2ToRuntime(ext)
	require.NoError(t, err)

	require.Equal(t, cfg.Filters.Application, got.Filters.Application)
}

func TestV2ToRuntimeHTTPApplicationFiltersImportsOneSignal(t *testing.T) {
	t.Parallel()

	statusCode := 500
	filters := schema.AttributeFilters{
		"http.status_code": {Equals: &statusCode},
		"service.name":     {Match: "checkout-*"},
	}

	got, err := V2ToRuntime(&schema.Extension{
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
	require.NoError(t, err)

	require.Equal(t, filter.AttributeFamilyConfig{
		"http.status_code": {Equals: &statusCode},
		"service.name":     {Match: "checkout-*"},
	}, got.Filters.Application)
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
