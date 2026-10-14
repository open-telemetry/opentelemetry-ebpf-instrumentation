// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// Registering the attributes in Traces.Section is only meaningful if the
// exclusion actually reaches the emission sites.
func TestTraceAttributesSelector_HTTPAttributesAreExcludable(t *testing.T) {
	span := &request.Span{
		Type: request.EventTypeHTTP, Method: "PURGE", Path: "/x", Status: 200,
		UserAgent: "curl/8.4.0",
	}

	for _, name := range []attr.Name{
		attr.HTTPRequestMethodOrig,
		attr.UserAgentOriginal,
	} {
		t.Run("exclude "+string(name), func(t *testing.T) {
			selected, err := UserSelectedAttributes(&attributes.SelectorConfig{
				SelectionCfg: attributes.Selection{
					attributes.Traces.Section: attributes.InclusionLists{
						Exclude: []string{string(name)},
					},
				},
			})
			require.NoError(t, err)

			_, ok := attrValue(TraceAttributesSelector(span, selected), string(name))
			assert.False(t, ok, "%s must be excludable", name)
		})
	}

	t.Run("both present by default", func(t *testing.T) {
		attrs := TraceAttributesSelector(span, defaultTraceAttrs(t))
		for _, key := range []string{"http.request.method_original", "user_agent.original"} {
			_, ok := attrValue(attrs, key)
			assert.True(t, ok, "%s should be on by default", key)
		}
	})
}

// An HTTP subtype carries a different protocol, and the SQL++ branch in
// particular builds a deliberately DB-only attribute set.
// Only SQL++ replaces the HTTP attribute set with a DB-only one; the other
// subtypes keep their HTTP attributes and are still HTTP spans.
func TestTraceAttributesSelector_UserAgentPerSubtype(t *testing.T) {
	const ua = "curl/8.4.0"

	serverSpan := func(sub int) *request.Span {
		return &request.Span{
			Type: request.EventTypeHTTP, SubType: sub,
			Method: "POST", Path: "/q", Status: 200,
			UserAgent: ua,
		}
	}

	t.Run("withheld from SQL++", func(t *testing.T) {
		_, ok := attrValue(
			TraceAttributesSelector(serverSpan(request.HTTPSubtypeSQLPP), defaultTraceAttrs(t)),
			"user_agent.original")
		assert.False(t, ok)
	})

	for _, sub := range []int{
		request.HTTPSubtypeNone,
		request.HTTPSubtypeGraphQL,
		request.HTTPSubtypeMCP,
		request.HTTPSubtypeElasticsearch,
		request.HTTPSubtypeAWSS3,
	} {
		t.Run("reported for subtype", func(t *testing.T) {
			v, ok := attrValue(
				TraceAttributesSelector(serverSpan(sub), defaultTraceAttrs(t)),
				"user_agent.original")
			require.True(t, ok, "subtype %d is still an HTTP span", sub)
			assert.Equal(t, ua, v.AsString())
		})
	}
}
