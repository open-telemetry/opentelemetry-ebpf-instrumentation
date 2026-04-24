// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

func TestSpanClientServer(t *testing.T) {
	for _, st := range []EventType{EventTypeHTTP, EventTypeGRPC, EventTypeKafkaServer, EventTypeMQTTServer, EventTypeNATSServer, EventTypeRedisServer, EventTypeMemcachedServer, EventTypeSQLServer} {
		span := &Span{
			Type: st,
		}
		assert.False(t, span.IsClientSpan())
	}

	for _, st := range []EventType{
		EventTypeHTTPClient, EventTypeGRPCClient, EventTypeSQLClient,
		EventTypeRedisClient, EventTypeKafkaClient, EventTypeMQTTClient, EventTypeNATSClient,
		EventTypeMongoClient, EventTypeMemcachedClient, EventTypeFailedConnect,
	} {
		span := &Span{
			Type: st,
		}
		assert.True(t, span.IsClientSpan())
	}
}

func TestEventTypeString(t *testing.T) {
	typeStringMap := map[EventType]string{
		EventTypeHTTP:            "HTTP",
		EventTypeGRPC:            "GRPC",
		EventTypeHTTPClient:      "HTTPClient",
		EventTypeGRPCClient:      "GRPCClient",
		EventTypeSQLClient:       "SQLClient",
		EventTypeSQLServer:       "SQLServer",
		EventTypeRedisClient:     "RedisClient",
		EventTypeMemcachedClient: "MemcachedClient",
		EventTypeKafkaClient:     "KafkaClient",
		EventTypeMQTTClient:      "MQTTClient",
		EventTypeNATSClient:      "NATSClient",
		EventTypeRedisServer:     "RedisServer",
		EventTypeMemcachedServer: "MemcachedServer",
		EventTypeKafkaServer:     "KafkaServer",
		EventTypeMQTTServer:      "MQTTServer",
		EventTypeNATSServer:      "NATSServer",
		EventTypeMongoClient:     "MongoClient",
		EventType(99):            "UNKNOWN (99)",
	}

	for ev, str := range typeStringMap {
		assert.Equal(t, ev.String(), str)
	}
}

func TestKindString(t *testing.T) {
	m := map[*Span]string{
		{Type: EventTypeHTTP}:                                  "SPAN_KIND_SERVER",
		{Type: EventTypeGRPC}:                                  "SPAN_KIND_SERVER",
		{Type: EventTypeKafkaServer}:                           "SPAN_KIND_SERVER",
		{Type: EventTypeMQTTServer}:                            "SPAN_KIND_SERVER",
		{Type: EventTypeNATSServer}:                            "SPAN_KIND_SERVER",
		{Type: EventTypeRedisServer}:                           "SPAN_KIND_SERVER",
		{Type: EventTypeMemcachedServer}:                       "SPAN_KIND_SERVER",
		{Type: EventTypeSQLServer}:                             "SPAN_KIND_SERVER",
		{Type: EventTypeHTTPClient}:                            "SPAN_KIND_CLIENT",
		{Type: EventTypeGRPCClient}:                            "SPAN_KIND_CLIENT",
		{Type: EventTypeSQLClient}:                             "SPAN_KIND_CLIENT",
		{Type: EventTypeRedisClient}:                           "SPAN_KIND_CLIENT",
		{Type: EventTypeMemcachedClient}:                       "SPAN_KIND_CLIENT",
		{Type: EventTypeMongoClient}:                           "SPAN_KIND_CLIENT",
		{Type: EventTypeKafkaClient, Method: MessagingPublish}: "SPAN_KIND_PRODUCER",
		{Type: EventTypeKafkaClient, Method: MessagingProcess}: "SPAN_KIND_CONSUMER",
		{Type: EventTypeMQTTClient, Method: MessagingPublish}:  "SPAN_KIND_PRODUCER",
		{Type: EventTypeMQTTClient, Method: MessagingProcess}:  "SPAN_KIND_CONSUMER",
		{Type: EventTypeNATSClient, Method: MessagingPublish}:  "SPAN_KIND_PRODUCER",
		{Type: EventTypeNATSClient, Method: MessagingProcess}:  "SPAN_KIND_CONSUMER",
		{}: "SPAN_KIND_INTERNAL",
	}

	for span, str := range m {
		assert.Equal(t, span.ServiceGraphKind(), str)
	}
}

func TestServiceGraphConnectionType(t *testing.T) {
	tests := []struct {
		name     string
		span     *Span
		expected string
	}{
		// Database client spans should return "database"
		{name: "SQL client", span: &Span{Type: EventTypeSQLClient}, expected: "database"},
		{name: "Redis client", span: &Span{Type: EventTypeRedisClient}, expected: "database"},
		{name: "Memcached client", span: &Span{Type: EventTypeMemcachedClient}, expected: "database"},
		{name: "Mongo client", span: &Span{Type: EventTypeMongoClient}, expected: "database"},
		{name: "Elasticsearch client", span: &Span{Type: EventTypeHTTPClient, SubType: HTTPSubtypeElasticsearch}, expected: "database"},

		// Messaging client spans should return "messaging_system"
		{name: "Kafka client producer", span: &Span{Type: EventTypeKafkaClient, Method: MessagingPublish}, expected: "messaging_system"},
		{name: "Kafka client consumer", span: &Span{Type: EventTypeKafkaClient, Method: MessagingProcess}, expected: "messaging_system"},
		{name: "MQTT client publisher", span: &Span{Type: EventTypeMQTTClient, Method: MessagingPublish}, expected: "messaging_system"},
		{name: "MQTT client subscriber", span: &Span{Type: EventTypeMQTTClient, Method: MessagingProcess}, expected: "messaging_system"},
		{name: "NATS client publisher", span: &Span{Type: EventTypeNATSClient, Method: MessagingPublish}, expected: "messaging_system"},
		{name: "NATS client subscriber", span: &Span{Type: EventTypeNATSClient, Method: MessagingProcess}, expected: "messaging_system"},
		{name: "AWS SQS client", span: &Span{Type: EventTypeHTTPClient, SubType: HTTPSubtypeAWSSQS}, expected: "messaging_system"},

		// Server spans should return empty
		{name: "Redis server", span: &Span{Type: EventTypeRedisServer}, expected: ""},
		{name: "Memcached server", span: &Span{Type: EventTypeMemcachedServer}, expected: ""},
		{name: "SQL server", span: &Span{Type: EventTypeSQLServer}, expected: ""},
		{name: "Kafka server", span: &Span{Type: EventTypeKafkaServer}, expected: ""},
		{name: "MQTT server", span: &Span{Type: EventTypeMQTTServer}, expected: ""},
		{name: "NATS server", span: &Span{Type: EventTypeNATSServer}, expected: ""},

		// Regular HTTP/gRPC spans should return empty (unset)
		{name: "HTTP server", span: &Span{Type: EventTypeHTTP}, expected: ""},
		{name: "HTTP client", span: &Span{Type: EventTypeHTTPClient}, expected: ""},
		{name: "GRPC server", span: &Span{Type: EventTypeGRPC}, expected: ""},
		{name: "GRPC client", span: &Span{Type: EventTypeGRPCClient}, expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.span.ServiceGraphConnectionType())
		})
	}
}

func TestTraceName(t *testing.T) {
	tests := []struct {
		name     string
		span     *Span
		expected string
	}{
		// HTTP spans
		{name: "HTTP server", span: &Span{Type: EventTypeHTTP, Method: "GET", Route: "/users"}, expected: "GET /users"},
		{name: "HTTP client", span: &Span{Type: EventTypeHTTPClient, Method: "POST", Route: "/api"}, expected: "POST /api"},
		{name: "HTTP no route", span: &Span{Type: EventTypeHTTP, Method: "GET"}, expected: "GET"},

		// gRPC spans
		{name: "gRPC server", span: &Span{Type: EventTypeGRPC, Path: "/service/Method"}, expected: "/service/Method"},
		{name: "gRPC client", span: &Span{Type: EventTypeGRPCClient, Path: "/service/Call"}, expected: "/service/Call"},

		// SQL spans
		{name: "SQL client", span: &Span{Type: EventTypeSQLClient, Method: "SELECT", Path: "users"}, expected: "SELECT users"},
		{name: "SQL server", span: &Span{Type: EventTypeSQLServer, Method: "SELECT", Path: "users"}, expected: "SELECT users"},
		{name: "SQL no table", span: &Span{Type: EventTypeSQLClient, Method: "BEGIN"}, expected: "BEGIN"},
		{name: "SQL empty", span: &Span{Type: EventTypeSQLClient}, expected: "SQL"},

		// Redis spans
		{name: "Redis client", span: &Span{Type: EventTypeRedisClient, Method: "GET"}, expected: "GET"},
		{name: "Redis empty", span: &Span{Type: EventTypeRedisClient}, expected: "REDIS"},
		{name: "Memcached client", span: &Span{Type: EventTypeMemcachedClient, Method: "GET", Path: "cache-key"}, expected: "GET"},
		{name: "Memcached empty", span: &Span{Type: EventTypeMemcachedClient}, expected: "MEMCACHED"},

		// Kafka spans
		{name: "Kafka client publish", span: &Span{Type: EventTypeKafkaClient, Method: MessagingPublish, Path: "orders"}, expected: "publish orders"},
		{name: "Kafka client process", span: &Span{Type: EventTypeKafkaClient, Method: MessagingProcess, Path: "events"}, expected: "process events"},
		{name: "Kafka server", span: &Span{Type: EventTypeKafkaServer, Method: MessagingProcess, Path: "topic"}, expected: "process topic"},
		{name: "Kafka no topic", span: &Span{Type: EventTypeKafkaClient, Method: MessagingPublish}, expected: "publish"},

		// MQTT spans
		{name: "MQTT client publish", span: &Span{Type: EventTypeMQTTClient, Method: MessagingPublish, Path: "sensors/temperature"}, expected: "publish sensors/temperature"},
		{name: "MQTT client subscribe", span: &Span{Type: EventTypeMQTTClient, Method: MessagingProcess, Path: "sensors/#"}, expected: "process sensors/#"},
		{name: "MQTT server", span: &Span{Type: EventTypeMQTTServer, Method: MessagingProcess, Path: "home/lights"}, expected: "process home/lights"},
		{name: "MQTT no topic", span: &Span{Type: EventTypeMQTTClient, Method: MessagingPublish}, expected: "publish"},
		{name: "NATS client publish", span: &Span{Type: EventTypeNATSClient, Method: MessagingPublish, Path: "updates.orders"}, expected: "publish updates.orders"},
		{name: "NATS client process", span: &Span{Type: EventTypeNATSClient, Method: MessagingProcess, Path: "updates.orders"}, expected: "process updates.orders"},
		{name: "NATS server", span: &Span{Type: EventTypeNATSServer, Method: MessagingProcess, Path: "updates.orders"}, expected: "process updates.orders"},
		{name: "NATS no subject", span: &Span{Type: EventTypeNATSClient, Method: MessagingPublish}, expected: "publish"},

		// JSON-RPC spans
		{name: "JSON-RPC with method", span: &Span{Type: EventTypeHTTP, SubType: HTTPSubtypeJSONRPC, JSONRPC: &JSONRPC{Method: "subtract", Version: "2.0"}}, expected: "subtract"},
		{name: "JSON-RPC no method", span: &Span{Type: EventTypeHTTP, SubType: HTTPSubtypeJSONRPC, JSONRPC: &JSONRPC{Version: "2.0"}}, expected: "jsonrpc"},
		{name: "JSON-RPC client", span: &Span{Type: EventTypeHTTPClient, SubType: HTTPSubtypeJSONRPC, JSONRPC: &JSONRPC{Method: "getUser", Version: "2.0"}}, expected: "getUser"},

		// Other spans
		{name: "Mongo client", span: &Span{Type: EventTypeMongoClient, Method: "find", Path: "users"}, expected: "find users"},
		{name: "Failed connect", span: &Span{Type: EventTypeFailedConnect}, expected: "CONNECT"},
		{name: "DNS", span: &Span{Type: EventTypeDNS, Method: "A", Path: "example.com"}, expected: "A example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.span.TraceName())
		})
	}
}

func TestSpanStatusCode_JSONRPC(t *testing.T) {
	tests := []struct {
		name         string
		span         *Span
		expectedCode string
	}{
		{
			name: "server span with JSON-RPC error",
			span: &Span{
				Type:    EventTypeHTTP,
				Status:  200,
				SubType: HTTPSubtypeJSONRPC,
				JSONRPC: &JSONRPC{Method: "subtract", Version: "2.0", ErrorCode: -32601, ErrorMessage: "Method not found"},
			},
			expectedCode: StatusCodeError,
		},
		{
			name: "server span without JSON-RPC error",
			span: &Span{
				Type:    EventTypeHTTP,
				Status:  200,
				SubType: HTTPSubtypeJSONRPC,
				JSONRPC: &JSONRPC{Method: "subtract", Version: "2.0"},
			},
			expectedCode: StatusCodeUnset,
		},
		{
			name: "client span with JSON-RPC error",
			span: &Span{
				Type:    EventTypeHTTPClient,
				Status:  200,
				SubType: HTTPSubtypeJSONRPC,
				JSONRPC: &JSONRPC{Method: "subtract", Version: "2.0", ErrorCode: -32600, ErrorMessage: "Invalid Request"},
			},
			expectedCode: StatusCodeError,
		},
		{
			name: "client span without JSON-RPC error",
			span: &Span{
				Type:    EventTypeHTTPClient,
				Status:  200,
				SubType: HTTPSubtypeJSONRPC,
				JSONRPC: &JSONRPC{Method: "subtract", Version: "2.0"},
			},
			expectedCode: StatusCodeUnset,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedCode, SpanStatusCode(tt.span))
		})
	}
}

func TestSpanStatusMessage_JSONRPC(t *testing.T) {
	tests := []struct {
		name            string
		span            *Span
		expectedMessage string
	}{
		{
			name: "server span with error message",
			span: &Span{
				Type:    EventTypeHTTP,
				Status:  200,
				SubType: HTTPSubtypeJSONRPC,
				JSONRPC: &JSONRPC{Method: "subtract", ErrorCode: -32601, ErrorMessage: "Method not found"},
			},
			expectedMessage: "Method not found",
		},
		{
			name: "client span with error message",
			span: &Span{
				Type:    EventTypeHTTPClient,
				Status:  200,
				SubType: HTTPSubtypeJSONRPC,
				JSONRPC: &JSONRPC{Method: "subtract", ErrorCode: -32600, ErrorMessage: "Invalid Request"},
			},
			expectedMessage: "Invalid Request",
		},
		{
			name: "server span without error",
			span: &Span{
				Type:    EventTypeHTTP,
				Status:  200,
				SubType: HTTPSubtypeJSONRPC,
				JSONRPC: &JSONRPC{Method: "subtract", Version: "2.0"},
			},
			expectedMessage: "",
		},
		{
			name: "client span without error",
			span: &Span{
				Type:    EventTypeHTTPClient,
				Status:  200,
				SubType: HTTPSubtypeJSONRPC,
				JSONRPC: &JSONRPC{Method: "subtract", Version: "2.0"},
			},
			expectedMessage: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedMessage, SpanStatusMessage(tt.span))
		})
	}
}

type jsonObject = map[string]any

func deserializeJSONObject(data []byte) (jsonObject, error) {
	var object jsonObject
	err := json.Unmarshal(data, &object)

	return object, err
}

func TestSerializeJSONSpans(t *testing.T) {
	type testData struct {
		eventType EventType
		attribs   map[string]any
	}

	tData := []testData{
		{
			eventType: EventTypeHTTP,
			attribs: map[string]any{
				"method":      "method",
				"status":      "200",
				"url":         "path",
				"contentLen":  "1024",
				"responseLen": "2048",
				"route":       "route",
				"clientAddr":  "peername",
				"serverAddr":  "hostname",
				"serverPort":  "5678",
			},
		},
		{
			eventType: EventTypeHTTPClient,
			attribs: map[string]any{
				"method":     "method",
				"status":     "200",
				"url":        "path",
				"clientAddr": "peername",
				"serverAddr": "hostname",
				"serverPort": "5678",
			},
		},
		{
			eventType: EventTypeGRPC,
			attribs: map[string]any{
				"method":     "path",
				"status":     "200",
				"clientAddr": "peername",
				"serverAddr": "hostname",
				"serverPort": "5678",
			},
		},
		{
			eventType: EventTypeGRPCClient,
			attribs: map[string]any{
				"method":     "path",
				"status":     "200",
				"serverAddr": "hostname",
				"serverPort": "5678",
			},
		},
		{
			eventType: EventTypeSQLClient,
			attribs: map[string]any{
				"serverAddr":       "hostname",
				"serverPort":       "5678",
				"operation":        "method",
				"table":            "path",
				"statement":        "statement",
				"errorCode":        "123",
				"errorDescription": "SQL Server errored for command 'COM_QUERY': error_code=123 sql_state=s123 message=err123",
				"errorMessage":     "err123",
				"sqlCommand":       "QUERY",
				"sqlState":         "s123",
			},
		},
		{
			eventType: EventTypeRedisClient,
			attribs:   map[string]any{},
		},
		{
			eventType: EventTypeKafkaClient,
			attribs: map[string]any{
				"serverAddr": "hostname",
				"serverPort": "5678",
				"operation":  "method",
				"clientId":   "statement",
				"topic":      "path",
				"partition":  "5",
			},
		},
		{
			eventType: EventTypeNATSClient,
			attribs: map[string]any{
				"serverAddr": "hostname",
				"serverPort": "5678",
				"operation":  "method",
				"clientId":   "statement",
				"subject":    "path",
			},
		},
		{
			eventType: EventTypeRedisServer,
			attribs: map[string]any{
				"serverAddr": "hostname",
				"serverPort": "5678",
				"operation":  "method",
				"statement":  "statement",
				"query":      "path",
			},
		},
		{
			eventType: EventTypeKafkaServer,
			attribs: map[string]any{
				"serverAddr": "hostname",
				"serverPort": "5678",
				"operation":  "method",
				"clientId":   "statement",
				"topic":      "path",
				"partition":  "5",
			},
		},
		{
			eventType: EventTypeMongoClient,
			attribs: map[string]any{
				"serverAddr": "hostname",
				"serverPort": "5678",
				"operation":  "method",
				"table":      "path",
			},
		},
	}

	test := func(t *testing.T, tData *testData) {
		span := Span{
			Type:           tData.eventType,
			Method:         "method",
			Path:           "path",
			Route:          "route",
			Peer:           "peer",
			PeerPort:       1234,
			Host:           "host",
			HostPort:       5678,
			Status:         200,
			ContentLength:  1024,
			ResponseLength: 2048,
			RequestStart:   10000,
			Start:          15000,
			End:            35000,
			TraceID:        trace.TraceID{0x1, 0x2, 0x3},
			SpanID:         trace.SpanID{0x1, 0x2, 0x3},
			ParentSpanID:   trace.SpanID{0x1, 0x2, 0x3},
			TraceFlags:     1,
			PeerName:       "peername",
			HostName:       "hostname",
			OtherNamespace: "otherns",
			Statement:      "statement",
			SQLCommand:     "QUERY",
			SQLError: &SQLError{
				SQLState: "s123",
				Message:  "err123",
				Code:     123,
			},
			MessagingInfo: &MessagingInfo{
				Partition: 5,
			},
		}

		data, err := json.MarshalIndent(span, "", " ")

		require.NoError(t, err)

		s, err := deserializeJSONObject(data)

		require.NoError(t, err)

		assert.Equal(t, map[string]any{
			"type":                tData.eventType.String(),
			"kind":                span.ServiceGraphKind(),
			"peer":                "peer",
			"peerPort":            "1234",
			"host":                "host",
			"hostPort":            "5678",
			"peerName":            "peername",
			"hostName":            "hostname",
			"start":               s["start"],
			"handlerStart":        s["handlerStart"],
			"end":                 s["end"],
			"duration":            "25µs",
			"durationUSec":        "25",
			"handlerDuration":     "20µs",
			"handlerDurationUSec": "20",
			"traceID":             "01020300000000000000000000000000",
			"spanID":              "0102030000000000",
			"parentSpanID":        "0102030000000000",
			"traceFlags":          "1",
			"attributes":          tData.attribs,
		}, s)
	}

	for i := range tData {
		test(t, &tData[i])
	}
}

func TestDetectsOTelExport(t *testing.T) {
	const defaultOtlpGRPCPort = 4317
	// Metrics
	tests := []struct {
		name    string
		span    Span
		exports bool
	}{
		{
			name:    "HTTP server spans don't export",
			span:    Span{Type: EventTypeHTTP, Method: "GET", Path: "/v1/metrics", RequestStart: 100, End: 200, Status: 200},
			exports: false,
		},
		{
			name:    "HTTP /foo doesn't export",
			span:    Span{Type: EventTypeHTTPClient, Method: "GET", Path: "/foo", RequestStart: 100, End: 200, Status: 200},
			exports: false,
		},
		{
			name:    "HTTP failed spans don't export",
			span:    Span{Type: EventTypeHTTPClient, Method: "GET", Path: "/v1/metrics", RequestStart: 100, End: 200, Status: 401},
			exports: false,
		},
		{
			name:    "Successful HTTP /v1/metrics spans export",
			span:    Span{Type: EventTypeHTTPClient, Method: "GET", Path: "/v1/metrics", RequestStart: 100, End: 200, Status: 200},
			exports: true,
		},
		{
			name:    "Successful HTTP /prefix/v1/metrics spans export",
			span:    Span{Type: EventTypeHTTPClient, Method: "GET", Path: "/prefix/v1/metrics", RequestStart: 100, End: 200, Status: 200},
			exports: true,
		},
		{
			name:    "GRPC server spans don't export",
			span:    Span{Type: EventTypeGRPC, Method: "GET", Path: "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export", RequestStart: 100, End: 200, Status: 0},
			exports: false,
		},
		{
			name:    "GRPC /v1/metrics doesn't export",
			span:    Span{Type: EventTypeGRPCClient, Method: "GET", Path: "/v1/metrics", RequestStart: 100, End: 200, Status: 0},
			exports: false,
		},
		{
			name:    "GRPC failed spans don't export",
			span:    Span{Type: EventTypeGRPCClient, Method: "GET", Path: "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export", RequestStart: 100, End: 200, Status: 1},
			exports: false,
		},
		{
			name:    "Successful GRPC /v1/metrics spans export",
			span:    Span{Type: EventTypeGRPCClient, Method: "GET", Path: "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export", RequestStart: 100, End: 200, Status: 0},
			exports: true,
		},
		{
			name: "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL != grpc doesn't export",
			span: Span{
				Type: EventTypeGRPCClient, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0,
				Service: svc.Attrs{EnvVars: map[string]string{"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL": "http/protobuf"}},
			},
			exports: false,
		},
		{
			name: "OTEL_EXPORTER_OTLP_PROTOCOL != grpc doesn't export",
			span: Span{
				Type: EventTypeGRPCClient, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0,
				Service: svc.Attrs{EnvVars: map[string]string{"OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf"}},
			},
			exports: false,
		},
		{
			name: "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT is not a valid endpoint doesn't export",
			span: Span{
				Type: EventTypeGRPCClient, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0,
				Service: svc.Attrs{EnvVars: map[string]string{"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "notanendpoint"}},
			},
			exports: false,
		},
		{
			name: "OTEL_EXPORTER_OTLP_ENDPOINT is not a valid endpoint doesn't export",
			span: Span{
				Type: EventTypeGRPCClient, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0,
				Service: svc.Attrs{EnvVars: map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "notanendpoint"}},
			},
			exports: false,
		},
		{
			name: "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT != span.PeerPort doesn't export",
			span: Span{
				Type: EventTypeGRPCClient, PeerPort: 8080, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0,
				Service: svc.Attrs{EnvVars: map[string]string{"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://localhost:4317"}},
			},
			exports: false,
		},
		{
			name: "OTEL_EXPORTER_OTLP_ENDPOINT != span.PeerPort doesn't export",
			span: Span{
				Type: EventTypeGRPCClient, PeerPort: 8080, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0,
				Service: svc.Attrs{EnvVars: map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4317"}},
			},
			exports: false,
		},
		{
			name: "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT == span.PeerPort export",
			span: Span{
				Type: EventTypeGRPCClient, PeerPort: 9090, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0,
				Service: svc.Attrs{EnvVars: map[string]string{"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://localhost:9090"}},
			},
			exports: true,
		},
		{
			name: "OTEL_EXPORTER_OTLP_ENDPOINT == span.PeerPort export",
			span: Span{
				Type: EventTypeGRPCClient, PeerPort: 9090, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0,
				Service: svc.Attrs{EnvVars: map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:9090", "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "http/protobuf"}},
			},
			exports: true,
		},
		{
			name: fmt.Sprintf("no otel metrics environment sends to %x export", defaultOtlpGRPCPort),
			span: Span{
				Type: EventTypeGRPCClient, PeerPort: 4317, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0,
				Service: svc.Attrs{EnvVars: map[string]string{"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "http/protobuf"}},
			},
			exports: true,
		},
		{
			name:    fmt.Sprintf("no otel environment sends to anything other the %d doesn't export", defaultOtlpGRPCPort),
			span:    Span{Type: EventTypeGRPCClient, PeerPort: 8080, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0},
			exports: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.exports, tt.span.IsExportMetricsSpan(defaultOtlpGRPCPort))
			assert.False(t, tt.span.IsExportTracesSpan(defaultOtlpGRPCPort))
		})
	}

	// Traces
	tests = []struct {
		name    string
		span    Span
		exports bool
	}{
		{
			name:    "HTTP server spans don't export",
			span:    Span{Type: EventTypeHTTP, Method: "GET", Path: "/v1/traces", RequestStart: 100, End: 200, Status: 200},
			exports: false,
		},
		{
			name:    "/foo doesn't export",
			span:    Span{Type: EventTypeHTTPClient, Method: "GET", Path: "/foo", RequestStart: 100, End: 200, Status: 200},
			exports: false,
		},
		{
			name:    "HTTP failed spans don't export",
			span:    Span{Type: EventTypeHTTPClient, Method: "GET", Path: "/v1/traces", RequestStart: 100, End: 200, Status: 401},
			exports: false,
		},
		{
			name:    "Successful HTTP /v1/traces spans export",
			span:    Span{Type: EventTypeHTTPClient, Method: "GET", Path: "/v1/traces", RequestStart: 100, End: 200, Status: 200},
			exports: true,
		},
		{
			name:    "GRPC server spans don't export",
			span:    Span{Type: EventTypeGRPC, Method: "GET", Path: "/opentelemetry.proto.collector.trace.v1.TraceService/Export", RequestStart: 100, End: 200, Status: 0},
			exports: false,
		},
		{
			name:    "GRPC /v1/traces doesn't export",
			span:    Span{Type: EventTypeGRPCClient, Method: "GET", Path: "/v1/traces", RequestStart: 100, End: 200, Status: 0},
			exports: false,
		},
		{
			name:    "GRPC failed spans don't export",
			span:    Span{Type: EventTypeGRPCClient, Method: "GET", Path: "/opentelemetry.proto.collector.trace.v1.TraceService/Export", RequestStart: 100, End: 200, Status: 1},
			exports: false,
		},
		{
			name:    "Successful GRPC /v1/traces spans export",
			span:    Span{Type: EventTypeGRPCClient, Method: "GET", Path: "/opentelemetry.proto.collector.trace.v1.TraceService/Export", RequestStart: 100, End: 200, Status: 0},
			exports: true,
		},
		{
			name: "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL != grpc doesn't export",
			span: Span{
				Type: EventTypeGRPCClient, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0,
				Service: svc.Attrs{EnvVars: map[string]string{"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "http/protobuf"}},
			},
			exports: false,
		},
		{
			name: "OTEL_EXPORTER_OTLP_PROTOCOL != grpc doesn't export",
			span: Span{
				Type: EventTypeGRPCClient, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0,
				Service: svc.Attrs{EnvVars: map[string]string{"OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf"}},
			},
			exports: false,
		},
		{
			name: "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT is not a valid endpoint doesn't export",
			span: Span{
				Type: EventTypeGRPCClient, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0,
				Service: svc.Attrs{EnvVars: map[string]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "notanendpoint"}},
			},
			exports: false,
		},
		{
			name: "OTEL_EXPORTER_OTLP_ENDPOINT is not a valid endpoint doesn't export",
			span: Span{
				Type: EventTypeGRPCClient, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0,
				Service: svc.Attrs{EnvVars: map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "notanendpoint"}},
			},
			exports: false,
		},
		{
			name: "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT != span.PeerPort doesn't export",
			span: Span{
				Type: EventTypeGRPCClient, PeerPort: 8080, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0,
				Service: svc.Attrs{EnvVars: map[string]string{"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://localhost:4317"}},
			},
			exports: false,
		},
		{
			name: "OTEL_EXPORTER_OTLP_ENDPOINT != span.PeerPort doesn't export",
			span: Span{
				Type: EventTypeGRPCClient, PeerPort: 8080, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0,
				Service: svc.Attrs{EnvVars: map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4317"}},
			},
			exports: false,
		},
		{
			name: "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT == span.PeerPort export",
			span: Span{
				Type: EventTypeGRPCClient, PeerPort: 9090, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0,
				Service: svc.Attrs{EnvVars: map[string]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://localhost:9090"}},
			},
			exports: true,
		},
		{
			name: "OTEL_EXPORTER_OTLP_ENDPOINT == span.PeerPort export",
			span: Span{
				Type: EventTypeGRPCClient, PeerPort: 9090, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0,
				Service: svc.Attrs{EnvVars: map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:9090", "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL": "http/protobuf"}},
			},
			exports: true,
		},
		{
			name: fmt.Sprintf("no otel traces environment sends to %d export", defaultOtlpGRPCPort),
			span: Span{
				Type: EventTypeGRPCClient, PeerPort: 4317, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0,
				Service: svc.Attrs{EnvVars: map[string]string{"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL": "http/protobuf"}},
			},
			exports: true,
		},
		{
			name:    fmt.Sprintf("no otel environment sends to anything other the %d doesn't export", defaultOtlpGRPCPort),
			span:    Span{Type: EventTypeGRPCClient, PeerPort: 8080, Method: "GET", Path: "*", RequestStart: 100, End: 200, Status: 0},
			exports: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.exports, tt.span.IsExportTracesSpan(defaultOtlpGRPCPort))
			assert.False(t, tt.span.IsExportMetricsSpan(defaultOtlpGRPCPort))
		})
	}
}

func TestSelfReferencingSpan(t *testing.T) {
	// Metrics
	tests := []struct {
		name    string
		span    Span
		selfref bool
	}{
		{
			name:    "Not a self-reference",
			span:    Span{Type: EventTypeHTTP, Method: "GET", Path: "/v1/metrics", RequestStart: 100, End: 200, Status: 200, Host: "10.10.10.10", Peer: "10.11.10.11", OtherNamespace: "", Service: svc.Attrs{UID: svc.UID{Namespace: ""}}},
			selfref: false,
		},
		{
			name:    "Not a self-reference, same IP, different namespace",
			span:    Span{Type: EventTypeHTTP, Method: "GET", Path: "/v1/metrics", RequestStart: 100, End: 200, Status: 200, Host: "10.10.10.10", Peer: "10.10.10.10", OtherNamespace: "B", Service: svc.Attrs{UID: svc.UID{Namespace: "A"}}},
			selfref: false,
		},
		{
			name:    "Same IP different namespace, but the other namespace is empty",
			span:    Span{Type: EventTypeHTTP, Method: "GET", Path: "/v1/metrics", RequestStart: 100, End: 200, Status: 200, Host: "10.10.10.10", Peer: "10.10.10.10", OtherNamespace: "", Service: svc.Attrs{UID: svc.UID{Namespace: "A"}}},
			selfref: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.selfref, tt.span.IsSelfReferenceSpan())
		})
	}
}

func TestHostPeerClientServer(t *testing.T) {
	// Metrics
	tests := []struct {
		name   string
		span   Span
		client string
		server string
	}{
		{
			name:   "Same namespaces HTTP",
			span:   Span{Type: EventTypeHTTP, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Client in different namespace",
			span:   Span{Type: EventTypeHTTP, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client.far",
			server: "server",
		},
		{
			name:   "Client in different namespace",
			span:   Span{Type: EventTypeHTTP, Peer: "1.1.1.1", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "1.1.1.1",
			server: "server",
		},
		{
			name:   "Same namespaces for HTTP client",
			span:   Span{Type: EventTypeHTTPClient, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Server in different namespace ",
			span:   Span{Type: EventTypeHTTPClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server.far",
		},
		{
			name:   "Server in different namespace ",
			span:   Span{Type: EventTypeHTTPClient, PeerName: "client", Host: "2.2.2.2", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "2.2.2.2",
		},
		{
			name:   "Same namespaces GRPC",
			span:   Span{Type: EventTypeGRPC, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Client in different namespace GRPC",
			span:   Span{Type: EventTypeGRPC, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client.far",
			server: "server",
		},
		{
			name:   "Same namespaces for GRPC client",
			span:   Span{Type: EventTypeGRPCClient, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Server in different namespace GRPC",
			span:   Span{Type: EventTypeGRPCClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server.far",
		},
		{
			name:   "Same namespaces for SQL client",
			span:   Span{Type: EventTypeSQLClient, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Server in different namespace SQL",
			span:   Span{Type: EventTypeSQLClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server.far",
		},
		{
			name:   "Same namespaces for Redis client",
			span:   Span{Type: EventTypeRedisClient, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Server in different namespace Redis",
			span:   Span{Type: EventTypeRedisClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server.far",
		},
		{
			name:   "Client in different namespace Redis",
			span:   Span{Type: EventTypeRedisServer, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client.far",
			server: "server",
		},
		{
			name:   "Same namespaces for Mongo client",
			span:   Span{Type: EventTypeMongoClient, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Same namespaces for NATS client",
			span:   Span{Type: EventTypeNATSClient, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Server in different namespace NATS",
			span:   Span{Type: EventTypeNATSClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server.far",
		},
		{
			name:   "Server in different namespace Mongo",
			span:   Span{Type: EventTypeMongoClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server.far",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.client, PeerAsClient(&tt.span))
			assert.Equal(t, tt.server, HostAsServer(&tt.span))
		})
	}
}

func TestRequestBodyLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		s        Span
		expected int64
	}{
		{
			name: "With ContentLength less than zero",
			s: Span{
				ContentLength: -1,
			},
			expected: 0,
		},
		{
			name: "With ContentLength equal to zero",
			s: Span{
				ContentLength: 0,
			},
			expected: 0,
		},
		{
			name: "With ContentLength greater than zero",
			s: Span{
				ContentLength: 128,
			},
			expected: 128,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.expected, tt.s.RequestBodyLength())
		})
	}
}

func TestResponseBodyLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		s        Span
		expected int64
	}{
		{
			name: "With ResponseLength less than zero",
			s: Span{
				ResponseLength: -1,
			},
			expected: 0,
		},
		{
			name: "With ResponseLength equal to zero",
			s: Span{
				ResponseLength: 0,
			},
			expected: 0,
		},
		{
			name: "With ResponseLength greater than zero",
			s: Span{
				ResponseLength: 128,
			},
			expected: 128,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.expected, tt.s.ResponseBodyLength())
		})
	}
}

func TestIsHTTPSpan(t *testing.T) {
	spanHTTP := &Span{Type: EventTypeHTTP}
	spanHTTPClient := &Span{Type: EventTypeHTTPClient}
	spanGRPC := &Span{Type: EventTypeGRPC}
	spanOther := &Span{Type: EventTypeSQLClient}

	assert.True(t, spanHTTP.IsHTTPSpan(), "EventTypeHTTP should be HTTP span")
	assert.True(t, spanHTTPClient.IsHTTPSpan(), "EventTypeHTTPClient should be HTTP span")
	assert.False(t, spanGRPC.IsHTTPSpan(), "EventTypeGRPC should not be HTTP span")
	assert.False(t, spanOther.IsHTTPSpan(), "Other types should not be HTTP span")
}

func TestHTTPSpanStatusCode_OpenAI(t *testing.T) {
	tests := []struct {
		name     string
		span     *Span
		expected string
	}{
		{
			name: "non-OpenAI 2xx → unset",
			span: &Span{
				Type:   EventTypeHTTPClient,
				Status: 200,
			},
			expected: StatusCodeUnset,
		},
		{
			name: "OpenAI 2xx, no error field → unset",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeOpenAI,
				Status:  200,
				GenAI: &GenAI{
					OpenAI: &VendorOpenAI{
						OperationName: "response",
						ResponseModel: "gpt-5-mini-2025-08-07",
					},
				},
			},
			expected: StatusCodeUnset,
		},
		{
			name: "OpenAI 2xx, error.type set → error",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeOpenAI,
				Status:  200,
				GenAI: &GenAI{
					OpenAI: &VendorOpenAI{
						Error: OpenAIError{
							Type:    "insufficient_quota",
							Message: "You exceeded your current quota.",
						},
					},
				},
			},
			expected: StatusCodeError,
		},
		{
			name: "OpenAI 2xx, OpenAI is nil → unset (nil guard)",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeOpenAI,
				Status:  200,
				GenAI:   nil,
			},
			expected: StatusCodeUnset,
		},
		{
			name: "OpenAI 4xx → error (HTTP status wins regardless)",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeOpenAI,
				Status:  429,
				GenAI: &GenAI{
					OpenAI: &VendorOpenAI{
						Error: OpenAIError{
							Type:    "insufficient_quota",
							Message: "You exceeded your current quota.",
						},
					},
				},
			},
			expected: StatusCodeError,
		},
		{
			name: "OpenAI status 0 → error (missing status)",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeOpenAI,
				Status:  0,
				GenAI:   &GenAI{OpenAI: &VendorOpenAI{}},
			},
			expected: StatusCodeError,
		},
		{
			name: "Qwen 2xx, error.type set → error",
			span: &Span{
				Type:    EventTypeHTTPClient,
				SubType: HTTPSubtypeQwen,
				Status:  200,
				GenAI: &GenAI{
					Qwen: &VendorOpenAI{
						Error: OpenAIError{
							Type:    "insufficient_quota",
							Message: "Quota exceeded",
						},
					},
				},
			},
			expected: StatusCodeError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, HTTPSpanStatusCode(tt.span))
		})
	}
}

// Test GenAIInputTokens
func TestSpan_GenAIInputTokens(t *testing.T) {
	t.Run("GenAI is nil", func(t *testing.T) {
		span := &Span{GenAI: nil}
		result := span.GenAIInputTokens()
		assert.Equal(t, 0, result)
	})

	t.Run("OpenAI present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				OpenAI: &VendorOpenAI{
					Usage: OpenAIUsage{
						InputTokens: 100,
					},
				},
			},
		}
		result := span.GenAIInputTokens()
		assert.Equal(t, 100, result)
	})

	t.Run("Anthropic present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Anthropic: &VendorAnthropic{
					Output: AnthropicResponse{
						Usage: AnthropicUsage{
							InputTokens: 200,
						},
					},
				},
			},
		}
		result := span.GenAIInputTokens()
		assert.Equal(t, 200, result)
	})

	t.Run("Gemini present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Gemini: &VendorGemini{
					Output: GeminiResponse{
						UsageMetadata: GeminiUsage{
							PromptTokenCount: 300,
						},
					},
				},
			},
		}
		result := span.GenAIInputTokens()
		assert.Equal(t, 300, result)
	})

	t.Run("Qwen present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Qwen: &VendorOpenAI{
					Usage: OpenAIUsage{
						InputTokens: 333,
					},
				},
			},
		}
		result := span.GenAIInputTokens()
		assert.Equal(t, 333, result)
	})

	t.Run("Bedrock present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Bedrock: &VendorBedrock{
					Output: BedrockResponse{
						InputTokens: 25,
					},
				},
			},
		}
		result := span.GenAIInputTokens()
		assert.Equal(t, 25, result)
	})
}

// Test GenAIOutputTokens
func TestSpan_GenAIOutputTokens(t *testing.T) {
	t.Run("GenAI is nil", func(t *testing.T) {
		span := &Span{GenAI: nil}
		result := span.GenAIOutputTokens()
		assert.Equal(t, 0, result)
	})

	t.Run("OpenAI present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				OpenAI: &VendorOpenAI{
					Usage: OpenAIUsage{
						OutputTokens: 150,
					},
				},
			},
		}
		result := span.GenAIOutputTokens()
		assert.Equal(t, 150, result)
	})

	t.Run("OpenAI present, no usage", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				OpenAI: &VendorOpenAI{},
			},
		}
		result := span.GenAIOutputTokens()
		assert.Equal(t, 0, result)
	})

	t.Run("Anthropic present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Anthropic: &VendorAnthropic{
					Output: AnthropicResponse{
						Usage: AnthropicUsage{
							OutputTokens: 250,
						},
					},
				},
			},
		}
		result := span.GenAIOutputTokens()
		assert.Equal(t, 250, result)
	})

	t.Run("Anthropic present no usage", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Anthropic: &VendorAnthropic{},
			},
		}
		result := span.GenAIOutputTokens()
		assert.Equal(t, 0, result)
	})

	t.Run("Gemini present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Gemini: &VendorGemini{
					Output: GeminiResponse{
						UsageMetadata: GeminiUsage{
							CandidatesTokenCount: 400,
						},
					},
				},
			},
		}
		result := span.GenAIOutputTokens()
		assert.Equal(t, 400, result)
	})

	t.Run("Gemini present no usage", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Gemini: &VendorGemini{},
			},
		}
		result := span.GenAIOutputTokens()
		assert.Equal(t, 0, result)
	})

	t.Run("Qwen present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Qwen: &VendorOpenAI{
					Usage: OpenAIUsage{
						OutputTokens: 444,
					},
				},
			},
		}
		result := span.GenAIOutputTokens()
		assert.Equal(t, 444, result)
	})

	t.Run("Bedrock present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Bedrock: &VendorBedrock{
					Output: BedrockResponse{
						OutputTokens: 18,
					},
				},
			},
		}
		result := span.GenAIOutputTokens()
		assert.Equal(t, 18, result)
	})

	t.Run("Bedrock present no usage", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Bedrock: &VendorBedrock{},
			},
		}
		result := span.GenAIOutputTokens()
		assert.Equal(t, 0, result)
	})
}

// Test GenAIOperationName
func TestSpan_GenAIOperationName(t *testing.T) {
	t.Run("nil GenAI", func(t *testing.T) {
		span := &Span{GenAI: nil}
		result := span.GenAIOperationName()
		assert.Empty(t, result)
	})

	t.Run("OpenAI present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				OpenAI: &VendorOpenAI{
					OperationName: "chat.completion",
				},
			},
		}
		result := span.GenAIOperationName()
		assert.Equal(t, "chat.completion", result)
	})

	t.Run("Anthropic present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Anthropic: &VendorAnthropic{
					Output: AnthropicResponse{
						Type: "message",
					},
				},
			},
		}
		result := span.GenAIOperationName()
		assert.Equal(t, "message", result)
	})

	t.Run("Gemini present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Gemini: &VendorGemini{},
			},
		}
		result := span.GenAIOperationName()
		assert.Equal(t, "generate_content", result)
	})

	t.Run("Qwen present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Qwen: &VendorOpenAI{
					OperationName: "chat.completion",
				},
			},
		}
		result := span.GenAIOperationName()
		assert.Equal(t, "chat.completion", result)
	})

	t.Run("Bedrock present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Bedrock: &VendorBedrock{},
			},
		}
		result := span.GenAIOperationName()
		assert.Equal(t, "invoke_model", result)
	})
}

// Test GenAIProviderName
func TestSpan_GenAIProviderName(t *testing.T) {
	t.Run("nil GenAI", func(t *testing.T) {
		span := &Span{GenAI: nil}
		result := span.GenAIProviderName()
		assert.Empty(t, result)
	})

	t.Run("OpenAI present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				OpenAI: &VendorOpenAI{},
			},
		}
		result := span.GenAIProviderName()
		assert.Equal(t, "openai", result) // Assuming semconv.GenAIProviderNameOpenAI.Value.AsString() returns "openai"
	})

	t.Run("Anthropic present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Anthropic: &VendorAnthropic{},
			},
		}
		result := span.GenAIProviderName()
		assert.Equal(t, "anthropic", result) // Assuming semconv.GenAIProviderNameAnthropic.Value.AsString() returns "anthropic"
	})

	t.Run("Gemini present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Gemini: &VendorGemini{},
			},
		}
		result := span.GenAIProviderName()
		assert.Equal(t, "gcp.gemini", result)
	})

	t.Run("Qwen present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Qwen: &VendorOpenAI{},
			},
		}
		result := span.GenAIProviderName()
		assert.Equal(t, "qwen", result)
	})

	t.Run("Bedrock present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Bedrock: &VendorBedrock{},
			},
		}
		result := span.GenAIProviderName()
		assert.Equal(t, "aws.bedrock", result)
	})
}

// Test GenAIRequestModel
func TestSpan_GenAIRequestModel(t *testing.T) {
	t.Run("nil GenAI", func(t *testing.T) {
		span := &Span{GenAI: nil}
		result := span.GenAIRequestModel()
		assert.Empty(t, result)
	})

	t.Run("OpenAI present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				OpenAI: &VendorOpenAI{
					Request: OpenAIInput{
						Model: "gpt-3.5-turbo",
					},
				},
			},
		}
		result := span.GenAIRequestModel()
		assert.Equal(t, "gpt-3.5-turbo", result)
	})

	t.Run("Anthropic present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Anthropic: &VendorAnthropic{
					Input: AnthropicRequest{
						Model: "claude-2",
					},
				},
			},
		}
		result := span.GenAIRequestModel()
		assert.Equal(t, "claude-2", result)
	})

	t.Run("Gemini present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Gemini: &VendorGemini{
					Model: "gemini-2.0-flash",
				},
			},
		}
		result := span.GenAIRequestModel()
		assert.Equal(t, "gemini-2.0-flash", result)
	})

	t.Run("Qwen present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Qwen: &VendorOpenAI{
					Request: OpenAIInput{
						Model: "qwen-plus",
					},
				},
			},
		}
		result := span.GenAIRequestModel()
		assert.Equal(t, "qwen-plus", result)
	})

	t.Run("Bedrock present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Bedrock: &VendorBedrock{
					Model: "anthropic.claude-3-5-sonnet-20241022-v1:0",
				},
			},
		}
		result := span.GenAIRequestModel()
		assert.Equal(t, "anthropic.claude-3-5-sonnet-20241022-v1:0", result)
	})
}

// Test GenAIResponseModel
func TestSpan_GenAIResponseModel(t *testing.T) {
	t.Run("nil GenAI", func(t *testing.T) {
		span := &Span{GenAI: nil}
		result := span.GenAIResponseModel()
		assert.Empty(t, result)
	})

	t.Run("OpenAI present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				OpenAI: &VendorOpenAI{
					ResponseModel: "gpt-3.5-turbo-0125",
				},
			},
		}
		result := span.GenAIResponseModel()
		assert.Equal(t, "gpt-3.5-turbo-0125", result)
	})

	t.Run("Anthropic present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Anthropic: &VendorAnthropic{
					Output: AnthropicResponse{
						Model: "claude-2.1",
					},
				},
			},
		}
		result := span.GenAIResponseModel()
		assert.Equal(t, "claude-2.1", result)
	})

	t.Run("Gemini present with model version", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Gemini: &VendorGemini{
					Model: "gemini-2.0-flash",
					Output: GeminiResponse{
						ModelVersion: "gemini-2.0-flash-001",
					},
				},
			},
		}
		result := span.GenAIResponseModel()
		assert.Equal(t, "gemini-2.0-flash-001", result)
	})

	t.Run("Gemini present without model version", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Gemini: &VendorGemini{
					Model: "gemini-2.0-flash",
				},
			},
		}
		result := span.GenAIResponseModel()
		assert.Equal(t, "gemini-2.0-flash", result)
	})

	t.Run("Qwen present with response model", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Qwen: &VendorOpenAI{
					ResponseModel: "qwen-plus-2026-01-01",
					Request: OpenAIInput{
						Model: "qwen-plus",
					},
				},
			},
		}
		result := span.GenAIResponseModel()
		assert.Equal(t, "qwen-plus-2026-01-01", result)
	})

	t.Run("Qwen present without response model", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Qwen: &VendorOpenAI{
					Request: OpenAIInput{
						Model: "qwen-plus",
					},
				},
			},
		}
		result := span.GenAIResponseModel()
		assert.Equal(t, "qwen-plus", result)
	})

	t.Run("Bedrock present", func(t *testing.T) {
		span := &Span{
			GenAI: &GenAI{
				Bedrock: &VendorBedrock{
					Model: "anthropic.claude-3-5-sonnet-20241022-v1:0",
				},
			},
		}
		result := span.GenAIResponseModel()
		assert.Equal(t, "anthropic.claude-3-5-sonnet-20241022-v1:0", result)
	})
}
