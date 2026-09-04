// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// semconv makes user_agent.original recommended on server spans and opt-in on
// client spans, and an operator's header policy has to govern it either way.
func TestTraceAttributesSelector_UserAgentServerClientSplit(t *testing.T) {
	const ua = "curl/8.4.0"

	t.Run("server span reports it without header capture", func(t *testing.T) {
		span := &request.Span{
			Type: request.EventTypeHTTP, Method: "GET", Path: "/x", Status: 200,
			UserAgent: ua,
		}
		v, ok := attrValue(TraceAttributesSelector(span, defaultTraceAttrs(t)), "user_agent.original")
		require.True(t, ok)
		assert.Equal(t, ua, v.AsString())
	})

	t.Run("client span stays silent without header capture", func(t *testing.T) {
		span := &request.Span{
			Type: request.EventTypeHTTPClient, Method: "GET", Path: "/x", Status: 200,
			UserAgent: ua,
		}
		_, ok := attrValue(TraceAttributesSelector(span, defaultTraceAttrs(t)), "user_agent.original")
		assert.False(t, ok, "opt-in on client spans per semconv")
	})

	t.Run("client span reports it once the header is captured", func(t *testing.T) {
		span := &request.Span{
			Type: request.EventTypeHTTPClient, Method: "GET", Path: "/x", Status: 200,
			UserAgent:      ua,
			RequestHeaders: map[string][]string{"User-Agent": {ua}},
		}
		attrs := TraceAttributesSelector(span, defaultTraceAttrs(t))
		v, ok := attrValue(attrs, "user_agent.original")
		require.True(t, ok)
		assert.Equal(t, ua, v.AsString())
		assert.Equal(t, 1, countAttr(attrs, "user_agent.original"))
	})

	// The enricher writes its exclude/obfuscate decision into RequestHeaders, so
	// preferring that value keeps one policy in charge of the header content.
	t.Run("an obfuscated header wins over the parsed request", func(t *testing.T) {
		span := &request.Span{
			Type: request.EventTypeHTTP, Method: "GET", Path: "/x", Status: 200,
			UserAgent:      ua,
			RequestHeaders: map[string][]string{"User-Agent": {"***"}},
		}
		v, ok := attrValue(TraceAttributesSelector(span, defaultTraceAttrs(t)), "user_agent.original")
		require.True(t, ok)
		assert.Equal(t, "***", v.AsString(), "the header policy must govern this attribute too")
	})

	t.Run("withheld from SQL++", func(t *testing.T) {
		span := &request.Span{
			Type: request.EventTypeHTTPClient, SubType: request.HTTPSubtypeSQLPP,
			Method: "POST", Path: "/q", Status: 200,
			UserAgent:      ua,
			RequestHeaders: map[string][]string{"User-Agent": {ua}},
		}
		_, ok := attrValue(TraceAttributesSelector(span, defaultTraceAttrs(t)), "user_agent.original")
		assert.False(t, ok, "SQL++ spans carry DB attributes only")
	})

	t.Run("excluded by selection", func(t *testing.T) {
		span := &request.Span{
			Type: request.EventTypeHTTP, Method: "GET", Path: "/x", Status: 200,
			UserAgent: ua,
		}
		_, ok := attrValue(TraceAttributesSelector(span, map[attr.Name]struct{}{}), "user_agent.original")
		assert.False(t, ok)
	})
}
