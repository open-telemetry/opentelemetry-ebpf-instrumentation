// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
	trace2 "go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestTraceAttributesSelector_SunRPCClient(t *testing.T) {
	span := &request.Span{
		Type:      request.EventTypeSunRPCClient,
		Method:    "3",
		Path:      "nfs",
		Route:     "3",
		Statement: "rpcsec_gss",
		SubType:   4,
		Host:      "10.0.0.2",
		HostPort:  2049,
		Peer:      "10.0.0.1",
	}

	attrs := TraceAttributesSelector(span, map[attr.Name]struct{}{})

	require.NotEmpty(t, attrs)
	assert.Equal(t, trace2.SpanKindClient, spanKind(span))
	assert.Contains(t, attrs, semconv.RPCSystemOncRPC)
	assert.Contains(t, attrs, semconv.OncRPCProgramName("nfs"))
	assert.Contains(t, attrs, semconv.OncRPCProcedureNumber(3))
	assert.Contains(t, attrs, semconv.OncRPCVersion(4))
	assert.Contains(t, attrs, attribute.String(string(attr.OncRPCAuthFlavor), "rpcsec_gss"))
}

func TestSpanKind_SunRPCServer(t *testing.T) {
	span := &request.Span{Type: request.EventTypeSunRPCServer}
	assert.Equal(t, trace2.SpanKindServer, spanKind(span))
}
