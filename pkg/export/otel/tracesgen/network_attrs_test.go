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

// SQL++ is the one subtype whose branch replaces the HTTP attribute set with a
// DB-only one; every other subtype is still an HTTP span and keeps the version.
func TestTraceAttributesSelector_ProtocolVersionPerSubtype(t *testing.T) {
	span := func(sub int) *request.Span {
		return &request.Span{
			Type: request.EventTypeHTTPClient, SubType: sub,
			Method: "POST", Path: "/q", Host: "10.0.0.9", HostPort: 8093, Status: 200,
			DBSystem:     "couchbase",
			ProtoVersion: request.ProtoVersionHTTP11,
		}
	}

	t.Run("withheld from SQL++", func(t *testing.T) {
		attrs := TraceAttributesSelector(span(request.HTTPSubtypeSQLPP), defaultTraceAttrs(t))
		_, ok := attrValue(attrs, "network.protocol.version")
		assert.False(t, ok, "SQL++ spans carry DB attributes only")
	})

	for _, sub := range []int{
		request.HTTPSubtypeNone,
		request.HTTPSubtypeGraphQL,
		request.HTTPSubtypeMCP,
		request.HTTPSubtypeElasticsearch,
		request.HTTPSubtypeAWSS3,
		request.HTTPSubtypeOpenAI,
	} {
		t.Run("reported for subtype", func(t *testing.T) {
			attrs := TraceAttributesSelector(span(sub), defaultTraceAttrs(t))
			v, ok := attrValue(attrs, "network.protocol.version")
			require.True(t, ok, "subtype %d is still an HTTP span", sub)
			assert.Equal(t, "1.1", v.AsString())
		})
	}
}

// Registering the attributes in Traces.Section is only meaningful if the
// exclusion actually reaches the emission sites.
func TestTraceAttributesSelector_NetworkAttributesAreExcludable(t *testing.T) {
	span := &request.Span{
		Type: request.EventTypeHTTP, Method: "GET", Path: "/x", Status: 200,
		Peer: "10.0.0.5", PeerPort: 54321,
		ProtoVersion: request.ProtoVersionHTTP11,
	}

	for _, name := range []attr.Name{
		attr.NetworkPeerAddress,
		attr.NetworkPeerPort,
		attr.NetworkProtocolVersion,
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

	t.Run("all present by default", func(t *testing.T) {
		attrs := TraceAttributesSelector(span, defaultTraceAttrs(t))
		for _, key := range []string{
			"network.peer.address", "network.peer.port", "network.protocol.version",
		} {
			_, ok := attrValue(attrs, key)
			assert.True(t, ok, "%s should be on by default", key)
		}
	})
}
