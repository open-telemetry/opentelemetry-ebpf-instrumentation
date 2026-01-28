// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestSpanOTELGetters_K8SClientNamespace(t *testing.T) {
	tests := []struct {
		name              string
		span              *Span
		expectedNamespace string
	}{
		{
			name: "client span - uses service namespace from metadata",
			span: &Span{
				Type: EventTypeHTTPClient,
				Service: svc.Attrs{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "test-namespace",
					},
					Metadata: map[attr.Name]string{
						attr.K8sNamespaceName: "k8s-namespace",
					},
				},
				OtherK8SNamespace: "other-k8s-namespace",
			},
			expectedNamespace: "k8s-namespace",
		},
		{
			name: "server span - uses OtherK8SNamespace",
			span: &Span{
				Type: EventTypeHTTP,
				Service: svc.Attrs{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "test-namespace",
					},
					Metadata: map[attr.Name]string{
						attr.K8sNamespaceName: "k8s-namespace",
					},
				},
				OtherK8SNamespace: "other-k8s-namespace",
			},
			expectedNamespace: "other-k8s-namespace",
		},
		{
			name: "client span - empty k8s namespace",
			span: &Span{
				Type: EventTypeGRPCClient,
				Service: svc.Attrs{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "test-namespace",
					},
					Metadata: map[attr.Name]string{},
				},
				OtherK8SNamespace: "other-k8s-namespace",
			},
			expectedNamespace: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getter, ok := spanOTELGetters(attr.K8SClientNamespace)
			require.True(t, ok, "getter should be found for K8SClientNamespace")

			kv := getter(tt.span)
			assert.Equal(t, string(attr.K8SClientNamespace), string(kv.Key))
			assert.Equal(t, tt.expectedNamespace, kv.Value.AsString())
		})
	}
}

func TestSpanOTELGetters_K8SServerNamespace(t *testing.T) {
	tests := []struct {
		name              string
		span              *Span
		expectedNamespace string
	}{
		{
			name: "client span - uses OtherK8SNamespace",
			span: &Span{
				Type: EventTypeHTTPClient,
				Service: svc.Attrs{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "test-namespace",
					},
					Metadata: map[attr.Name]string{
						attr.K8sNamespaceName: "k8s-namespace",
					},
				},
				OtherK8SNamespace: "other-k8s-namespace",
			},
			expectedNamespace: "other-k8s-namespace",
		},
		{
			name: "server span - uses service namespace from metadata",
			span: &Span{
				Type: EventTypeHTTP,
				Service: svc.Attrs{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "test-namespace",
					},
					Metadata: map[attr.Name]string{
						attr.K8sNamespaceName: "k8s-namespace",
					},
				},
				OtherK8SNamespace: "other-k8s-namespace",
			},
			expectedNamespace: "k8s-namespace",
		},
		{
			name: "server span - empty k8s namespace in metadata",
			span: &Span{
				Type: EventTypeGRPC,
				Service: svc.Attrs{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "test-namespace",
					},
					Metadata: map[attr.Name]string{},
				},
				OtherK8SNamespace: "other-k8s-namespace",
			},
			expectedNamespace: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getter, ok := spanOTELGetters(attr.K8SServerNamespace)
			require.True(t, ok, "getter should be found for K8SServerNamespace")

			kv := getter(tt.span)
			assert.Equal(t, string(attr.K8SServerNamespace), string(kv.Key))
			assert.Equal(t, tt.expectedNamespace, kv.Value.AsString())
		})
	}
}

func TestSpanOTELGetters_K8SClientCluster(t *testing.T) {
	tests := []struct {
		name            string
		span            *Span
		expectedCluster string
	}{
		{
			name: "client span - uses service cluster from metadata",
			span: &Span{
				Type: EventTypeHTTPClient,
				Service: svc.Attrs{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "test-namespace",
					},
					Metadata: map[attr.Name]string{
						attr.K8sClusterName: "k8s-cluster",
					},
				},
				OtherK8SNamespace: "other-k8s-namespace",
			},
			expectedCluster: "k8s-cluster",
		},
		{
			name: "server span with peer k8s namespace - uses service cluster",
			span: &Span{
				Type: EventTypeHTTP,
				Service: svc.Attrs{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "test-namespace",
					},
					Metadata: map[attr.Name]string{
						attr.K8sClusterName: "k8s-cluster",
					},
				},
				OtherK8SNamespace: "other-k8s-namespace",
			},
			expectedCluster: "k8s-cluster",
		},
		{
			name: "server span without peer k8s namespace - empty cluster",
			span: &Span{
				Type: EventTypeGRPC,
				Service: svc.Attrs{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "test-namespace",
					},
					Metadata: map[attr.Name]string{
						attr.K8sClusterName: "k8s-cluster",
					},
				},
				OtherK8SNamespace: "",
			},
			expectedCluster: "",
		},
		{
			name: "client span - no cluster in metadata",
			span: &Span{
				Type: EventTypeGRPCClient,
				Service: svc.Attrs{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "test-namespace",
					},
					Metadata: map[attr.Name]string{},
				},
				OtherK8SNamespace: "other-k8s-namespace",
			},
			expectedCluster: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getter, ok := spanOTELGetters(attr.K8SClientCluster)
			require.True(t, ok, "getter should be found for K8SClientCluster")

			kv := getter(tt.span)
			assert.Equal(t, string(attr.K8SClientCluster), string(kv.Key))
			assert.Equal(t, tt.expectedCluster, kv.Value.AsString())
		})
	}
}

func TestSpanOTELGetters_K8SServerCluster(t *testing.T) {
	tests := []struct {
		name            string
		span            *Span
		expectedCluster string
	}{
		{
			name: "client span with peer k8s namespace - uses service cluster",
			span: &Span{
				Type: EventTypeHTTPClient,
				Service: svc.Attrs{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "test-namespace",
					},
					Metadata: map[attr.Name]string{
						attr.K8sClusterName: "k8s-cluster",
					},
				},
				OtherK8SNamespace: "other-k8s-namespace",
			},
			expectedCluster: "k8s-cluster",
		},
		{
			name: "client span without peer k8s namespace - empty cluster",
			span: &Span{
				Type: EventTypeGRPCClient,
				Service: svc.Attrs{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "test-namespace",
					},
					Metadata: map[attr.Name]string{
						attr.K8sClusterName: "k8s-cluster",
					},
				},
				OtherK8SNamespace: "",
			},
			expectedCluster: "",
		},
		{
			name: "server span - uses service cluster from metadata",
			span: &Span{
				Type: EventTypeHTTP,
				Service: svc.Attrs{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "test-namespace",
					},
					Metadata: map[attr.Name]string{
						attr.K8sClusterName: "k8s-cluster",
					},
				},
				OtherK8SNamespace: "other-k8s-namespace",
			},
			expectedCluster: "k8s-cluster",
		},
		{
			name: "server span - no cluster in metadata",
			span: &Span{
				Type: EventTypeGRPC,
				Service: svc.Attrs{
					UID: svc.UID{
						Name:      "test-service",
						Namespace: "test-namespace",
					},
					Metadata: map[attr.Name]string{},
				},
				OtherK8SNamespace: "other-k8s-namespace",
			},
			expectedCluster: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getter, ok := spanOTELGetters(attr.K8SServerCluster)
			require.True(t, ok, "getter should be found for K8SServerCluster")

			kv := getter(tt.span)
			assert.Equal(t, string(attr.K8SServerCluster), string(kv.Key))
			assert.Equal(t, tt.expectedCluster, kv.Value.AsString())
		})
	}
}
