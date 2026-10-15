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

// Only a plain HTTP span, or a GraphQL client span, describes the HTTP
// exchange; every other subtype reports its own convention without it.
func TestTraceAttributesSelector_UserAgentPerSubtype(t *testing.T) {
	const ua = "curl/8.4.0"

	serverSpan := func(sub int) *request.Span {
		return &request.Span{
			Type: request.EventTypeHTTP, SubType: sub,
			Method: "POST", Path: "/q", Status: 200,
			UserAgent: ua,
		}
	}

	clientSpan := func(sub int) *request.Span {
		return &request.Span{
			Type: request.EventTypeHTTPClient, SubType: sub,
			Method: "POST", Path: "/q", Status: 200,
			RequestHeaders: map[string][]string{"User-Agent": {ua}},
		}
	}

	tests := []struct {
		name     string
		span     *request.Span
		reported bool
	}{
		{name: "http server", span: serverSpan(request.HTTPSubtypeNone), reported: true},
		{name: "graphql server", span: serverSpan(request.HTTPSubtypeGraphQL)},
		{name: "mcp server", span: serverSpan(request.HTTPSubtypeMCP)},
		{name: "jsonrpc server", span: serverSpan(request.HTTPSubtypeJSONRPC)},
		{name: "http client", span: clientSpan(request.HTTPSubtypeNone), reported: true},
		{name: "graphql client", span: clientSpan(request.HTTPSubtypeGraphQL), reported: true},
		{name: "sql++ client", span: clientSpan(request.HTTPSubtypeSQLPP)},
		{name: "elasticsearch client", span: clientSpan(request.HTTPSubtypeElasticsearch)},
		{name: "mcp client", span: clientSpan(request.HTTPSubtypeMCP)},
		{name: "jsonrpc client", span: clientSpan(request.HTTPSubtypeJSONRPC)},
		{name: "openai client", span: clientSpan(request.HTTPSubtypeOpenAI)},
		{name: "s3 client", span: clientSpan(request.HTTPSubtypeAWSS3)},
		{name: "sqs client", span: clientSpan(request.HTTPSubtypeAWSSQS)},
		{name: "sns client", span: clientSpan(request.HTTPSubtypeAWSSNS)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs := TraceAttributesSelector(tc.span, defaultTraceAttrs(t))

			v, ok := attrValue(attrs, "user_agent.original")
			require.Equal(t, tc.reported, ok)
			if tc.reported {
				assert.Equal(t, ua, v.AsString())
			}

			_, ok = attrValue(attrs, "http.request.header.user-agent")
			assert.Equal(t, tc.reported && tc.span.Type == request.EventTypeHTTPClient, ok)
		})
	}
}
