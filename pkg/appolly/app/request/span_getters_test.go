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

func TestSpanOTELGetters_MessagingOpName(t *testing.T) {
	tests := []struct {
		name     string
		span     *Span
		expected string
	}{
		{
			name:     "kafka client publish",
			span:     &Span{Type: EventTypeKafkaClient, Method: MessagingPublish},
			expected: "publish",
		},
		{
			name:     "kafka server process",
			span:     &Span{Type: EventTypeKafkaServer, Method: MessagingProcess},
			expected: "process",
		},
		{
			name:     "mqtt client publish",
			span:     &Span{Type: EventTypeMQTTClient, Method: MessagingPublish},
			expected: "publish",
		},
		{
			name:     "mqtt server process",
			span:     &Span{Type: EventTypeMQTTServer, Method: MessagingProcess},
			expected: "process",
		},
		{
			name:     "nats client publish",
			span:     &Span{Type: EventTypeNATSClient, Method: MessagingPublish},
			expected: "publish",
		},
		{
			name:     "nats server process",
			span:     &Span{Type: EventTypeNATSServer, Method: MessagingProcess},
			expected: "process",
		},
		{
			name:     "http span returns empty",
			span:     &Span{Type: EventTypeHTTP, Method: "GET"},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getter, ok := spanOTELGetters(attr.MessagingOpName)
			require.True(t, ok, "getter should be found for MessagingOpName")

			kv := getter(tt.span)
			assert.Equal(t, string(attr.MessagingOpName), string(kv.Key))
			assert.Equal(t, tt.expected, kv.Value.AsString())
		})
	}
}

func TestSpanOTELGetters_HTTPURLScheme(t *testing.T) {
	tests := []struct {
		name           string
		span           *Span
		expectedScheme string
	}{
		{
			name:           "http scheme from statement",
			span:           &Span{Statement: "http" + SchemeHostSeparator + "example.com"},
			expectedScheme: "http",
		},
		{
			name:           "https scheme from statement",
			span:           &Span{Statement: "https" + SchemeHostSeparator + "api.example.com"},
			expectedScheme: "https",
		},
		{
			name:           "empty statement",
			span:           &Span{Statement: ""},
			expectedScheme: "",
		},
		{
			name:           "statement without separator",
			span:           &Span{Statement: "no-scheme-here"},
			expectedScheme: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getter, ok := spanOTELGetters(attr.HTTPURLScheme)
			require.True(t, ok, "getter should be found for HTTPURLScheme")

			kv := getter(tt.span)
			assert.Equal(t, string(attr.HTTPURLScheme), string(kv.Key))
			assert.Equal(t, tt.expectedScheme, kv.Value.AsString())
		})
	}
}

func TestSpanOTELGetters_JSONRPCAttributes(t *testing.T) {
	jsonrpcSpan := &Span{
		SubType: HTTPSubtypeJSONRPC,
		JSONRPC: &JSONRPC{
			Version:   "2.0",
			RequestID: "42",
			ErrorCode: -32601,
		},
	}

	nonJSONRPCSpan := &Span{
		Type: EventTypeHTTP,
	}

	tests := []struct {
		name     string
		attrName attr.Name
		span     *Span
		expected string
	}{
		{
			name:     "protocol version - JSON-RPC span",
			attrName: attr.JSONRPCProtocolVersion,
			span:     jsonrpcSpan,
			expected: "2.0",
		},
		{
			name:     "protocol version - non-JSON-RPC span",
			attrName: attr.JSONRPCProtocolVersion,
			span:     nonJSONRPCSpan,
			expected: "",
		},
		{
			name:     "request ID - JSON-RPC span",
			attrName: attr.JSONRPCRequestID,
			span:     jsonrpcSpan,
			expected: "42",
		},
		{
			name:     "request ID - non-JSON-RPC span",
			attrName: attr.JSONRPCRequestID,
			span:     nonJSONRPCSpan,
			expected: "",
		},
		{
			name:     "response status code - JSON-RPC span with error",
			attrName: attr.RPCResponseStatusCode,
			span:     jsonrpcSpan,
			expected: "-32601",
		},
		{
			name:     "response status code - non-JSON-RPC span",
			attrName: attr.RPCResponseStatusCode,
			span:     nonJSONRPCSpan,
			expected: "",
		},
		{
			name:     "response status code - JSON-RPC span without error",
			attrName: attr.RPCResponseStatusCode,
			span: &Span{
				SubType: HTTPSubtypeJSONRPC,
				JSONRPC: &JSONRPC{Version: "2.0"},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getter, ok := spanOTELGetters(tt.attrName)
			require.True(t, ok, "getter should be found for %s", tt.attrName)

			kv := getter(tt.span)
			assert.Equal(t, string(tt.attrName), string(kv.Key))
			assert.Equal(t, tt.expected, kv.Value.AsString())
		})
	}
}

func TestSpanOTELGetters_MessagingAttributes_NATS(t *testing.T) {
	span := &Span{
		Type:   EventTypeNATSClient,
		Path:   "updates.orders",
		Method: MessagingPublish,
	}

	systemGetter, ok := spanOTELGetters(attr.MessagingSystem)
	require.True(t, ok, "getter should be found for MessagingSystem")
	systemKV := systemGetter(span)
	assert.Equal(t, string(attr.MessagingSystem), string(systemKV.Key))
	assert.Equal(t, "nats", systemKV.Value.AsString())

	destinationGetter, ok := spanOTELGetters(attr.MessagingDestination)
	require.True(t, ok, "getter should be found for MessagingDestination")
	destinationKV := destinationGetter(span)
	assert.Equal(t, string(attr.MessagingDestination), string(destinationKV.Key))
	assert.Equal(t, "updates.orders", destinationKV.Value.AsString())

	opTypeGetter, ok := spanOTELGetters(attr.MessagingOpType)
	require.True(t, ok, "getter should be found for MessagingOpType")
	assert.Equal(t, MessagingPublish, opTypeGetter(span).Value.AsString())

	span.Method = MessagingProcess
	assert.Equal(t, MessagingProcess, opTypeGetter(span).Value.AsString())
}
