// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

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

func TestSpanOTELGetters_DBCollectionName(t *testing.T) {
	tests := []struct {
		name     string
		span     *Span
		expected string
	}{
		{
			name: "Elasticsearch collection",
			span: &Span{
				Type:          EventTypeHTTPClient,
				SubType:       HTTPSubtypeElasticsearch,
				Elasticsearch: &Elasticsearch{DBCollectionName: "products"},
			},
			expected: "products",
		},
		{
			name:     "SQLPP collection",
			span:     &Span{Type: EventTypeHTTPClient, SubType: HTTPSubtypeSQLPP, Route: "inventory"},
			expected: "inventory",
		},
		{
			name:     "SQL client collection",
			span:     &Span{Type: EventTypeSQLClient, Path: "customers"},
			expected: "customers",
		},
		{
			name:     "SQL server collection",
			span:     &Span{Type: EventTypeSQLServer, Path: "orders"},
			expected: "orders",
		},
		{
			name:     "Aerospike collection",
			span:     &Span{Type: EventTypeAerospikeClient, Path: "sessions"},
			expected: "sessions",
		},
		{
			name:     "MongoDB collection",
			span:     &Span{Type: EventTypeMongoClient, Path: "a_collection"},
			expected: "a_collection",
		},
		{
			name:     "Couchbase collection",
			span:     &Span{Type: EventTypeCouchbaseClient, Path: "sofa"},
			expected: "sofa",
		},
		{
			name: "nil Elasticsearch metadata",
			span: &Span{Type: EventTypeHTTPClient, SubType: HTTPSubtypeElasticsearch},
		},
		{
			name: "unsupported span type",
			span: &Span{Type: EventTypeHTTP, Path: "ignored"},
		},
	}

	getter, ok := spanOTELGetters(attr.DBCollectionName)
	require.True(t, ok)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kv := getter(tt.span)
			assert.Equal(t, attribute.Key(attr.DBCollectionName), kv.Key)
			assert.Equal(t, tt.expected, kv.Value.AsString())
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
			name:     "amqp client publish",
			span:     &Span{Type: EventTypeAMQPClient, Method: MessagingPublish},
			expected: "publish",
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

func TestSpanOTELGetters_SunRPC(t *testing.T) {
	span := &Span{
		Type:    EventTypeSunRPCClient,
		Path:    "portmapper",
		Route:   "0",
		Method:  "0",
		SubType: 2,
		Status:  0,
	}

	stringTests := []struct {
		name     string
		attrName attr.Name
		expected string
	}{
		{name: "rpc system", attrName: attr.RPCSystem, expected: "onc_rpc"},
		{name: "rpc method", attrName: attr.RPCMethod, expected: "0"},
		{name: "program name", attrName: attr.OncRPCProgramName, expected: "portmapper"},
		{name: "response status code", attrName: attr.RPCResponseStatusCode, expected: "0"},
	}

	for _, tt := range stringTests {
		t.Run(tt.name, func(t *testing.T) {
			getter, ok := spanOTELGetters(tt.attrName)
			require.True(t, ok, "getter should be found for %s", tt.attrName)

			kv := getter(span)
			assert.Equal(t, string(tt.attrName), string(kv.Key))
			assert.Equal(t, tt.expected, kv.Value.AsString())
		})
	}

	t.Run("procedure number", func(t *testing.T) {
		getter, ok := spanOTELGetters(attr.OncRPCProcedureNumber)
		require.True(t, ok)
		assert.Equal(t, semconv.OncRPCProcedureNumber(0), getter(span))
	})

	t.Run("version", func(t *testing.T) {
		getter, ok := spanOTELGetters(attr.OncRPCVersion)
		require.True(t, ok)
		assert.Equal(t, semconv.OncRPCVersion(2), getter(span))
	})
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
		// omitted asserts the getter returns an invalid (zero) KeyValue so
		// the attribute is dropped instead of being emitted empty.
		omitted bool
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
			omitted:  true,
		},
		{
			name:     "response status code - JSON-RPC span without error",
			attrName: attr.RPCResponseStatusCode,
			span: &Span{
				SubType: HTTPSubtypeJSONRPC,
				JSONRPC: &JSONRPC{Version: "2.0"},
			},
			omitted: true,
		},
		{
			name:     "response status code - gRPC server span",
			attrName: attr.RPCResponseStatusCode,
			span: &Span{
				Type:   EventTypeGRPC,
				Status: 3,
			},
			expected: "INVALID_ARGUMENT",
		},
		{
			name:     "response status code - gRPC span with leaked HTTP status is omitted",
			attrName: attr.RPCResponseStatusCode,
			span: &Span{
				Type:   EventTypeGRPC,
				Status: 200,
			},
			omitted: true,
		},
		{
			name:     "response status code - gRPC client span with failed status read is omitted",
			attrName: attr.RPCResponseStatusCode,
			span: &Span{
				Type:   EventTypeGRPCClient,
				Status: 0xFFFF, // u16(-1) fallback from the eBPF side
			},
			omitted: true,
		},
		{
			name:     "response status code - SunRPC success",
			attrName: attr.RPCResponseStatusCode,
			span: &Span{
				Type:   EventTypeSunRPCClient,
				Status: 0,
			},
			expected: "0",
		},
		{
			name:     "response status code - SunRPC denied",
			attrName: attr.RPCResponseStatusCode,
			span: &Span{
				Type:   EventTypeSunRPCServer,
				Status: 1,
			},
			expected: "denied",
		},
		{
			name:     "response status code - SunRPC proc unavail",
			attrName: attr.RPCResponseStatusCode,
			span: &Span{
				Type:   EventTypeSunRPCClient,
				Status: 4,
			},
			expected: "3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getter, ok := spanOTELGetters(tt.attrName)
			require.True(t, ok, "getter should be found for %s", tt.attrName)

			kv := getter(tt.span)
			if tt.omitted {
				assert.False(t, kv.Valid(), "attribute should be omitted, got %v", kv)
				return
			}
			assert.Equal(t, string(tt.attrName), string(kv.Key))
			assert.Equal(t, tt.expected, kv.Value.AsString())
		})
	}
}

func TestSpanOTELGetters_DBQueryText(t *testing.T) {
	getter, ok := spanOTELGetters(attr.DBQueryText)
	require.True(t, ok, "getter should be found for DBQueryText")

	tests := []struct {
		name     string
		span     *Span
		expected string
	}{
		{
			name: "SQL++ HTTP client span uses statement",
			span: &Span{
				Type:      EventTypeHTTPClient,
				SubType:   HTTPSubtypeSQLPP,
				Statement: "SELECT * FROM bucket.scope.collection",
			},
			expected: "SELECT * FROM bucket.scope.collection",
		},
		{
			name: "SQL++ HTTP client span without statement returns empty",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeSQLPP,
			},
			expected: "",
		},
		{
			name: "Elasticsearch HTTP client span uses Elasticsearch query",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeElasticsearch,
				Elasticsearch: &Elasticsearch{
					DBQueryText: `{"query":{"match_all":{}}}`,
				},
			},
			expected: `{"query":{"match_all":{}}}`,
		},
		{
			name: "Elasticsearch HTTP client span without Elasticsearch state returns empty",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeElasticsearch,
			},
			expected: "",
		},
		{
			name: "SQL++ subtype on non HTTP client span returns empty",
			span: &Span{
				Type:      EventTypeHTTP,
				SubType:   HTTPSubtypeSQLPP,
				Statement: "SELECT * FROM bucket",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var kv attribute.KeyValue
			assert.NotPanics(t, func() { kv = getter(tt.span) })
			assert.Equal(t, string(attr.DBQueryText), string(kv.Key))
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

// TestSpanOTELGetters_MessagingOpTypeOmitted ensures messaging.operation.type
// (a semconv enum) is omitted — not emitted as an empty string — when the
// operation is unknown or the span is not a messaging span.
func TestSpanOTELGetters_MessagingOpTypeOmitted(t *testing.T) {
	opTypeGetter, ok := spanOTELGetters(attr.MessagingOpType)
	require.True(t, ok, "getter should be found for MessagingOpType")

	// messaging span with an unknown operation
	kv := opTypeGetter(&Span{Type: EventTypeKafkaClient})
	assert.False(t, kv.Valid(), "attribute should be omitted, got %v", kv)

	// SQS span whose operation type was not recognized
	kv = opTypeGetter(&Span{
		Type:    EventTypeHTTPClient,
		SubType: HTTPSubtypeAWSSQS,
		AWS:     &AWS{},
	})
	assert.False(t, kv.Valid(), "attribute should be omitted, got %v", kv)

	// non-messaging span
	kv = opTypeGetter(&Span{Type: EventTypeHTTP})
	assert.False(t, kv.Valid(), "attribute should be omitted, got %v", kv)
}

// TestSpanOTELGetters_ErrorTypeOmitted ensures error.type is omitted — not
// emitted as an empty string — on successful requests, while failed requests
// keep their error.type value.
func TestSpanOTELGetters_ErrorTypeOmitted(t *testing.T) {
	getter, ok := spanOTELGetters(attr.ErrorType)
	require.True(t, ok, "getter should be found for ErrorType")

	// successful HTTP request: no error.type
	kv := getter(&Span{Type: EventTypeHTTP, Status: 200})
	assert.False(t, kv.Valid(), "attribute should be omitted, got %v", kv)

	// failed HTTP request: generic error.type
	kv = getter(&Span{Type: EventTypeHTTP, Status: 500})
	require.True(t, kv.Valid())
	assert.Equal(t, string(attr.ErrorType), string(kv.Key))
	assert.Equal(t, "error", kv.Value.AsString())

	// failed Memcached request keeps its specific error code
	kv = getter(&Span{
		Type:    EventTypeMemcachedClient,
		Status:  1,
		DBError: DBError{ErrorCode: "SERVER_ERROR"},
	})
	require.True(t, kv.Valid())
	assert.Equal(t, "SERVER_ERROR", kv.Value.AsString())
}

// TestSpanOTELGetters_GenAIOperationNameOmitted ensures gen_ai.operation.name
// is omitted — not emitted as an empty string — when the operation could not
// be derived, while classified operations keep it.
func TestSpanOTELGetters_GenAIOperationNameOmitted(t *testing.T) {
	getter, ok := spanOTELGetters(attr.GenAIOperationName)
	require.True(t, ok, "getter should be found for GenAIOperationName")

	// non-GenAI span
	kv := getter(&Span{Type: EventTypeHTTPClient})
	assert.False(t, kv.Valid(), "attribute should be omitted, got %v", kv)

	// GenAI span whose operation was not classified
	kv = getter(&Span{
		Type:    EventTypeHTTPClient,
		SubType: HTTPSubtypeOpenAI,
		GenAI:   &GenAI{OpenAI: &VendorOpenAI{}},
	})
	assert.False(t, kv.Valid(), "attribute should be omitted, got %v", kv)

	// classified GenAI span keeps its operation name
	kv = getter(&Span{
		Type:    EventTypeHTTPClient,
		SubType: HTTPSubtypeOpenAI,
		GenAI:   &GenAI{OpenAI: &VendorOpenAI{OperationName: ChatOperationName}},
	})
	require.True(t, kv.Valid())
	assert.Equal(t, ChatOperationName, kv.Value.AsString())
}

// TestSpanOTELGetters_GenAIProviderNameOmitted ensures gen_ai.provider.name
// (a semconv enum) is omitted — not emitted as an empty string — on spans
// with no detected GenAI provider.
func TestSpanOTELGetters_GenAIProviderNameOmitted(t *testing.T) {
	getter, ok := spanOTELGetters(attr.GenAIProviderName)
	require.True(t, ok, "getter should be found for GenAIProviderName")

	// non-GenAI span
	kv := getter(&Span{Type: EventTypeHTTPClient})
	assert.False(t, kv.Valid(), "attribute should be omitted, got %v", kv)

	// GenAI span keeps its provider
	kv = getter(&Span{
		Type:    EventTypeHTTPClient,
		SubType: HTTPSubtypeOpenAI,
		GenAI:   &GenAI{OpenAI: &VendorOpenAI{}},
	})
	require.True(t, kv.Valid())
	assert.Equal(t, "openai", kv.Value.AsString())
}

func TestSpanOTELGetters_GenAIInput(t *testing.T) {
	tests := []struct {
		name     string
		span     *Span
		expected string
	}{
		{
			name: "openai",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeOpenAI,
				GenAI: &GenAI{OpenAI: &VendorOpenAI{Request: OpenAIInput{
					Messages: json.RawMessage(`[{"role":"user","content":"hi"}]`),
				}}},
			},
			expected: `[{"role":"user","parts":[{"type":"text","content":"hi"}]}]`,
		},
		{
			name: "anthropic",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeAnthropic,
				GenAI: &GenAI{Anthropic: &VendorAnthropic{Input: AnthropicRequest{
					Messages: json.RawMessage(`[{"role":"user","content":"hello"}]`),
				}}},
			},
			expected: `[{"role":"user","parts":[{"type":"text","content":"hello"}]}]`,
		},
		{
			name: "qwen",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeQwen,
				GenAI: &GenAI{Qwen: &VendorOpenAI{Request: OpenAIInput{
					Messages: json.RawMessage(`[{"role":"user","content":"hey"}]`),
				}}},
			},
			expected: `[{"role":"user","parts":[{"type":"text","content":"hey"}]}]`,
		},
		{
			name: "bedrock",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeAWSBedrock,
				GenAI: &GenAI{Bedrock: &VendorBedrock{Input: BedrockRequest{
					Messages: json.RawMessage(`[{"role":"user","content":"howdy"}]`),
				}}},
			},
			expected: `[{"role":"user","parts":[{"type":"text","content":"howdy"}]}]`,
		},
		{
			name:     "no genai",
			span:     &Span{Type: EventTypeHTTPClient, SubType: HTTPSubtypeOpenAI},
			expected: "",
		},
	}

	getter, ok := spanOTELGetters(attr.GenAIInput)
	require.True(t, ok)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, getter(tt.span).Value.AsString())
		})
	}
}

func TestSpanOTELGetters_GenAIOutput(t *testing.T) {
	tests := []struct {
		name     string
		span     *Span
		expected string
	}{
		{
			name: "anthropic",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeAnthropic,
				GenAI: &GenAI{Anthropic: &VendorAnthropic{Output: AnthropicResponse{
					Role:       "assistant",
					Content:    json.RawMessage(`[{"type":"text","text":"hello"}]`),
					StopReason: "end_turn",
				}}},
			},
			expected: `[{"role":"assistant","parts":[{"type":"text","content":"hello"}],"finish_reason":"end_turn"}]`,
		},
		{
			name: "bedrock anthropic format",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeAWSBedrock,
				GenAI: &GenAI{Bedrock: &VendorBedrock{Output: BedrockResponse{
					Content:    json.RawMessage(`[{"type":"text","text":"hi from bedrock"}]`),
					StopReason: "end_turn",
				}}},
			},
			expected: `[{"role":"assistant","parts":[{"type":"text","content":"hi from bedrock"}],"finish_reason":"end_turn"}]`,
		},
		{
			name: "bedrock llama format",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeAWSBedrock,
				GenAI: &GenAI{Bedrock: &VendorBedrock{Output: BedrockResponse{
					Generation: "llama says hi",
					StopReason: "stop",
				}}},
			},
			expected: `[{"role":"assistant","parts":[{"type":"text","content":"llama says hi"}],"finish_reason":"stop"}]`,
		},
		{
			name:     "no genai",
			span:     &Span{Type: EventTypeHTTPClient, SubType: HTTPSubtypeAnthropic},
			expected: "",
		},
		{
			// gen_ai.output.messages must be suppressed for embeddings to
			// stay aligned with the tracesgen path.
			name: "openai embeddings suppressed",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeOpenAI,
				GenAI: &GenAI{OpenAI: &VendorOpenAI{
					OperationName: EmbeddingOperationName,
					Data:          json.RawMessage(`[{"object":"embedding","embedding":[0.1,0.2]}]`),
				}},
			},
			expected: "",
		},
		{
			name: "qwen embeddings suppressed",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeQwen,
				GenAI: &GenAI{Qwen: &VendorOpenAI{
					OperationName: EmbeddingOperationName,
					Data:          json.RawMessage(`[{"object":"embedding","embedding":[0.1]}]`),
				}},
			},
			expected: "",
		},
	}

	getter, ok := spanOTELGetters(attr.GenAIOutput)
	require.True(t, ok)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, getter(tt.span).Value.AsString())
		})
	}
}

func TestSpanOTELGetters_GenAIInstructions(t *testing.T) {
	tests := []struct {
		name     string
		span     *Span
		expected string
	}{
		{
			name: "openai",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeOpenAI,
				GenAI: &GenAI{OpenAI: &VendorOpenAI{Request: OpenAIInput{
					Instructions: "be concise",
				}}},
			},
			expected: `[{"type":"text","content":"be concise"}]`,
		},
		{
			name: "anthropic",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeAnthropic,
				GenAI: &GenAI{Anthropic: &VendorAnthropic{Input: AnthropicRequest{
					System: "you are helpful",
				}}},
			},
			expected: `[{"type":"text","content":"you are helpful"}]`,
		},
		{
			name: "qwen",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeQwen,
				GenAI: &GenAI{Qwen: &VendorOpenAI{Request: OpenAIInput{
					Instructions: "respond in english",
				}}},
			},
			expected: `[{"type":"text","content":"respond in english"}]`,
		},
		{
			name: "openai empty instructions",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeOpenAI,
				GenAI:   &GenAI{OpenAI: &VendorOpenAI{}},
			},
			expected: "",
		},
	}

	getter, ok := spanOTELGetters(attr.GenAIInstructions)
	require.True(t, ok)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, getter(tt.span).Value.AsString())
		})
	}
}

func TestSpanOTELGetters_GenAITools(t *testing.T) {
	openAITools := json.RawMessage(`[{"type":"function","function":{"name":"get_weather","description":"get weather","parameters":{"type":"object"}}}]`)
	anthropicTools := json.RawMessage(`[{"name":"get_weather","description":"get weather","input_schema":{"type":"object"}}]`)
	geminiTools := json.RawMessage(`[{"functionDeclarations":[{"name":"get_weather","description":"get weather","parameters":{"type":"object"}}]}]`)
	expectedNormalized := `[{"type":"function","name":"get_weather","description":"get weather","parameters":{"type":"object"}}]`

	tests := []struct {
		name     string
		span     *Span
		expected string
	}{
		{
			name: "openai",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeOpenAI,
				GenAI: &GenAI{OpenAI: &VendorOpenAI{Request: OpenAIInput{
					Tools: openAITools,
				}}},
			},
			expected: expectedNormalized,
		},
		{
			name: "anthropic",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeAnthropic,
				GenAI: &GenAI{Anthropic: &VendorAnthropic{Input: AnthropicRequest{
					Tools: anthropicTools,
				}}},
			},
			expected: expectedNormalized,
		},
		{
			name: "gemini",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeGemini,
				GenAI: &GenAI{Gemini: &VendorGemini{Input: GeminiRequest{
					Tools: geminiTools,
				}}},
			},
			expected: expectedNormalized,
		},
		{
			name: "qwen",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeQwen,
				GenAI: &GenAI{Qwen: &VendorOpenAI{Request: OpenAIInput{
					Tools: openAITools,
				}}},
			},
			expected: expectedNormalized,
		},
		{
			name: "bedrock",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeAWSBedrock,
				GenAI: &GenAI{Bedrock: &VendorBedrock{Input: BedrockRequest{
					Tools: anthropicTools,
				}}},
			},
			expected: expectedNormalized,
		},
		{
			name:     "no genai",
			span:     &Span{Type: EventTypeHTTPClient, SubType: HTTPSubtypeAnthropic},
			expected: "",
		},
	}

	getter, ok := spanOTELGetters(attr.GenAITools)
	require.True(t, ok)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, getter(tt.span).Value.AsString())
		})
	}
}

func TestSpanOTELGetters_Instance(t *testing.T) {
	getter, ok := spanOTELGetters(attr.Instance)
	require.True(t, ok, "getter should be found for Instance")

	span := &Span{
		Service: svc.Attrs{
			UID: svc.UID{
				Instance: "instance-42",
			},
		},
	}

	kv := getter(span)
	assert.Equal(t, string(attr.Instance), string(kv.Key))
	assert.Equal(t, "instance-42", kv.Value.AsString())
}
