// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

func TestConnectionInfoEdgeFromClientSpan(t *testing.T) {
	span := &Span{
		Type:           EventTypeHTTPClient,
		Service:        svc.Attrs{UID: svc.UID{Name: "frontend", Namespace: "shop"}},
		Host:           "10.0.0.8",
		HostName:       "catalog",
		OtherNamespace: "data",
	}

	edge, ok := connectionInfoEdgeFromSpan(span)

	require.True(t, ok)
	assert.Equal(t, connectionInfoEdge{
		client:          "frontend",
		clientNamespace: "shop",
		server:          "catalog",
		serverNamespace: "data",
	}, edge)
}

func TestConnectionInfoEdgeFromSpanRequiresClientAndResolvedDestination(t *testing.T) {
	tests := []struct {
		name string
		span *Span
	}{
		{
			name: "server span",
			span: &Span{Type: EventTypeHTTP, Service: svc.Attrs{UID: svc.UID{Name: "catalog"}}, HostName: "frontend"},
		},
		{
			name: "unresolved destination",
			span: &Span{Type: EventTypeHTTPClient, Service: svc.Attrs{UID: svc.UID{Name: "frontend"}}, Host: "10.0.0.8"},
		},
		{
			name: "missing client identity",
			span: &Span{Type: EventTypeHTTPClient, HostName: "catalog"},
		},
		{name: "nil span"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, ok := connectionInfoEdgeFromSpan(test.span)
			assert.False(t, ok)
		})
	}
}
