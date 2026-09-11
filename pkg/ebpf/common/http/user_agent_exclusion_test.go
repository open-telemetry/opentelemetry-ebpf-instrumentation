// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
)

// user_agent.original is derived from the same header the enricher governs, so
// excluding the header has to suppress the attribute too. Without this the raw
// User-Agent resurfaces under a different key after being explicitly excluded.
func TestUserAgentExclusionClearsSpanValue(t *testing.T) {
	const ua = "curl/8.4.0"

	enricherFor := func(action config.HTTPParsingAction) *HTTPEnricher {
		return NewHTTPEnricher(config.EnrichmentConfig{
			Enabled: true,
			Policy: config.HTTPParsingPolicy{
				DefaultAction: config.HTTPParsingDefaultAction{
					Headers: action,
					Body:    config.HTTPParsingActionExclude,
				},
				DefaultObfuscationString: "***",
			},
		})
	}

	t.Run("excluded header clears the span value", func(t *testing.T) {
		span := &request.Span{Method: "GET", Path: "/test", UserAgent: ua}
		req, resp := makeReqResp(map[string]string{"User-Agent": ua}, nil)

		NewHTTPEnricher(config.EnrichmentConfig{
			Enabled: true,
			Policy: config.HTTPParsingPolicy{
				DefaultAction: config.HTTPParsingDefaultAction{
					Headers: config.HTTPParsingActionExclude,
					Body:    config.HTTPParsingActionExclude,
				},
				DefaultObfuscationString: "***",
			},
		}).Enrich(span, req, resp)

		assert.NotContains(t, span.RequestHeaders, "User-Agent")
		assert.Empty(t, span.UserAgent, "an excluded header must not survive on the span")
	})

	t.Run("included header leaves the span value intact", func(t *testing.T) {
		span := &request.Span{Method: "GET", Path: "/test", UserAgent: ua}
		req, resp := makeReqResp(map[string]string{"User-Agent": ua}, nil)

		ok := enricherFor(config.HTTPParsingActionInclude).Enrich(span, req, resp)
		require.True(t, ok)
		assert.Equal(t, []string{ua}, span.RequestHeaders["User-Agent"])
		assert.Equal(t, ua, span.UserAgent)
	})

	t.Run("obfuscated header rewrites the captured value", func(t *testing.T) {
		span := &request.Span{Method: "GET", Path: "/test", UserAgent: ua}
		req, resp := makeReqResp(map[string]string{"User-Agent": ua}, nil)

		ok := enricherFor(config.HTTPParsingActionObfuscate).Enrich(span, req, resp)
		require.True(t, ok)
		assert.Equal(t, []string{"***"}, span.RequestHeaders["User-Agent"])
	})
}
