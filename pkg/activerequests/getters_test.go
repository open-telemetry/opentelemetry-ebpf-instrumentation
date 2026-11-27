// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package activerequests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestActiveRequestGetters(t *testing.T) {
	entry := &Request{
		Service: svc.Attrs{
			UID:      svc.UID{Name: "shop", Instance: "instance-1"},
			Metadata: map[attr.Name]string{attr.K8sNamespaceName: "orders"},
		},
		Method:        "CUSTOM",
		Scheme:        "https",
		ServerAddress: "::1",
		ServerPort:    8443,
	}

	otelMethod, ok := OTELGetters()(attr.HTTPRequestMethod)
	require.True(t, ok)
	assert.Equal(t, "_OTHER", otelMethod(entry).Value.AsString())

	otelPort, ok := OTELGetters()(attr.ServerPort)
	require.True(t, ok)
	assert.Equal(t, int64(8443), otelPort(entry).Value.AsInt64())
	entry.ServerPort = 0
	assert.False(t, otelPort(entry).Valid())

	promPort, ok := PromGetters()(attr.ServerPort)
	require.True(t, ok)
	assert.Empty(t, promPort(entry))

	metadata, ok := PromGetters()(attr.K8sNamespaceName)
	require.True(t, ok)
	assert.Equal(t, "orders", metadata(entry))

	otelMetadata, ok := OTELGetters()(attr.K8sNamespaceName)
	require.True(t, ok)
	assert.Equal(t, "orders", otelMetadata(entry).Value.AsString())
}
