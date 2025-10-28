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
	for _, st := range []EventType{EventTypeHTTP, EventTypeGRPC} {
		span := &Span{
			Type: st,
		}
		assert.False(t, span.IsClientSpan())
	}

	for _, st := range []EventType{EventTypeHTTPClient, EventTypeGRPCClient, EventTypeSQLClient} {
		span := &Span{
			Type: st,
		}
		assert.True(t, span.IsClientSpan())
	}
}

func TestEventTypeString(t *testing.T) {
	typeStringMap := map[EventType]string{
		EventTypeHTTP:        "HTTP",
		EventTypeGRPC:        "GRPC",
		EventTypeHTTPClient:  "HTTPClient",
		EventTypeGRPCClient:  "GRPCClient",
		EventTypeSQLClient:   "SQLClient",
		EventTypeRedisClient: "RedisClient",
		EventTypeKafkaClient: "KafkaClient",
		EventTypeRedisServer: "RedisServer",
		EventTypeKafkaServer: "KafkaServer",
		EventTypeMongoClient: "MongoClient",
		EventType(99):        "UNKNOWN (99)",
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
		{Type: EventTypeRedisServer}:                           "SPAN_KIND_SERVER",
		{Type: EventTypeHTTPClient}:                            "SPAN_KIND_CLIENT",
		{Type: EventTypeGRPCClient}:                            "SPAN_KIND_CLIENT",
		{Type: EventTypeSQLClient}:                             "SPAN_KIND_CLIENT",
		{Type: EventTypeRedisClient}:                           "SPAN_KIND_CLIENT",
		{Type: EventTypeMongoClient}:                           "SPAN_KIND_CLIENT",
		{Type: EventTypeKafkaClient, Method: MessagingPublish}: "SPAN_KIND_PRODUCER",
		{Type: EventTypeKafkaClient, Method: MessagingProcess}: "SPAN_KIND_CONSUMER",
		{}: "SPAN_KIND_INTERNAL",
	}

	for span, str := range m {
		assert.Equal(t, span.ServiceGraphKind(), str)
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
