// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"

	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/components/pipe/global"
	"go.opentelemetry.io/obi/pkg/components/sqlprune"
	"go.opentelemetry.io/obi/pkg/components/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/idgen"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

var cache = expirable2.NewLRU[svc.UID, []attribute.KeyValue](1024, nil, 5*time.Minute)

func TestTraceSampling(t *testing.T) {
	spans := []request.Span{}
	start := time.Now()
	for i := 0; i < 10; i++ {
		span := request.Span{
			Type:         request.EventTypeHTTP,
			RequestStart: start.UnixNano(),
			Start:        start.Add(time.Second).UnixNano(),
			End:          start.Add(3 * time.Second).UnixNano(),
			Method:       "GET",
			Route:        "/test" + strconv.Itoa(i),
			Status:       200,
			TraceID:      idgen.RandomTraceID(),
			Service:      svc.Attrs{UID: svc.UID{Name: strconv.Itoa(i)}},
		}
		spans = append(spans, span)
	}

	receiver := makeTracesTestReceiver([]string{"http"})

	t.Run("test sample all", func(t *testing.T) {
		sampler := sdktrace.AlwaysSample()
		attrs := make(map[attr.Name]struct{})

		tr := []ptrace.Traces{}

		exporter := TestExporter{
			collector: func(td ptrace.Traces) {
				tr = append(tr, td)
			},
		}

		receiver.processSpans(t.Context(), exporter, spans, attrs, sampler)
		assert.Len(t, tr, 10)
	})

	t.Run("test sample nothing", func(t *testing.T) {
		sampler := sdktrace.NeverSample()
		attrs := make(map[attr.Name]struct{})

		tr := []ptrace.Traces{}

		exporter := TestExporter{
			collector: func(td ptrace.Traces) {
				tr = append(tr, td)
			},
		}

		receiver.processSpans(t.Context(), exporter, spans, attrs, sampler)
		assert.Empty(t, tr)
	})

	t.Run("test sample 1/10th", func(t *testing.T) {
		sampler := sdktrace.TraceIDRatioBased(0.1)
		attrs := make(map[attr.Name]struct{})

		tr := []ptrace.Traces{}

		exporter := TestExporter{
			collector: func(td ptrace.Traces) {
				tr = append(tr, td)
			},
		}

		receiver.processSpans(t.Context(), exporter, spans, attrs, sampler)
		// The result is likely 0,1,2 with 1/10th, but since sampling
		// it's a probabilistic matter, we don't want this test to become
		// flaky as some of them could report even 4-5 samples
		assert.GreaterOrEqual(t, 6, len(tr))
	})
}

func TestTraceSkipSpanMetrics(t *testing.T) {
	spans := []request.Span{}
	start := time.Now()
	for i := 0; i < 10; i++ {
		span := request.Span{
			Type:         request.EventTypeHTTP,
			RequestStart: start.UnixNano(),
			Start:        start.Add(time.Second).UnixNano(),
			End:          start.Add(3 * time.Second).UnixNano(),
			Method:       "GET",
			Route:        "/test" + strconv.Itoa(i),
			Status:       200,
			Service:      svc.Attrs{UID: svc.UID{Name: strconv.Itoa(i)}},
			TraceID:      idgen.RandomTraceID(),
		}
		spans = append(spans, span)
	}

	t.Run("test with span metrics on", func(t *testing.T) {
		receiver := makeTracesTestReceiverWithSpanMetrics([]string{"http"})

		sampler := sdktrace.AlwaysSample()
		attrs, err := receiver.getConstantAttributes()
		require.NoError(t, err)

		tr := []ptrace.Traces{}

		exporter := TestExporter{
			collector: func(td ptrace.Traces) {
				tr = append(tr, td)
			},
		}

		receiver.processSpans(t.Context(), exporter, spans, attrs, sampler)
		assert.Len(t, tr, 10)

		for _, ts := range tr {
			for i := 0; i < ts.ResourceSpans().Len(); i++ {
				rs := ts.ResourceSpans().At(i)
				for j := 0; j < rs.ScopeSpans().Len(); j++ {
					ss := rs.ScopeSpans().At(j)
					for k := 0; k < ss.Spans().Len(); k++ {
						span := ss.Spans().At(k)
						if strings.HasPrefix(span.Name(), "GET /test") {
							v, ok := span.Attributes().Get(string(attr.SkipSpanMetrics.OTEL()))
							assert.True(t, ok)
							assert.True(t, v.Bool())
						}
					}
				}
			}
		}
	})

	t.Run("test with span metrics off", func(t *testing.T) {
		receiver := makeTracesTestReceiver([]string{"http"})

		sampler := sdktrace.AlwaysSample()
		attrs, err := receiver.getConstantAttributes()
		require.NoError(t, err)

		tr := []ptrace.Traces{}

		exporter := TestExporter{
			collector: func(td ptrace.Traces) {
				tr = append(tr, td)
			},
		}

		receiver.processSpans(t.Context(), exporter, spans, attrs, sampler)
		assert.Len(t, tr, 10)

		for _, ts := range tr {
			for i := 0; i < ts.ResourceSpans().Len(); i++ {
				rs := ts.ResourceSpans().At(i)
				for j := 0; j < rs.ScopeSpans().Len(); j++ {
					ss := rs.ScopeSpans().At(j)
					for k := 0; k < ss.Spans().Len(); k++ {
						span := ss.Spans().At(k)
						if strings.HasPrefix(span.Name(), "GET /test") {
							_, ok := span.Attributes().Get(string(attr.SkipSpanMetrics.OTEL()))
							assert.False(t, ok)
						}
					}
				}
			}
		}
	})
}

func TestSpanHostPeer(t *testing.T) {
	sp := request.Span{
		HostName: "localhost",
		Host:     "127.0.0.1",
		PeerName: "peerhost",
		Peer:     "127.0.0.2",
	}

	assert.Equal(t, "localhost", request.SpanHost(&sp))
	assert.Equal(t, "peerhost", request.SpanPeer(&sp))

	sp = request.Span{
		Host: "127.0.0.1",
		Peer: "127.0.0.2",
	}

	assert.Equal(t, "127.0.0.1", request.SpanHost(&sp))
	assert.Equal(t, "127.0.0.2", request.SpanPeer(&sp))

	sp = request.Span{}

	assert.Empty(t, request.SpanHost(&sp))
	assert.Empty(t, request.SpanPeer(&sp))
}

func TestTracesInstrumentations(t *testing.T) {
	tests := []InstrTest{
		{
			name:     "all instrumentations",
			instr:    []string{instrumentations.InstrumentationALL},
			expected: []string{"GET /foo", "PUT /bar", "/grpcFoo", "/grpcGoo", "SELECT credentials", "SET", "GET", "important-topic publish", "important-topic process", "insert mycollection"},
		},
		{
			name:     "http only",
			instr:    []string{instrumentations.InstrumentationHTTP},
			expected: []string{"GET /foo", "PUT /bar"},
		},
		{
			name:     "grpc only",
			instr:    []string{instrumentations.InstrumentationGRPC},
			expected: []string{"/grpcFoo", "/grpcGoo"},
		},
		{
			name:     "redis only",
			instr:    []string{instrumentations.InstrumentationRedis},
			expected: []string{"SET", "GET"},
		},
		{
			name:     "sql only",
			instr:    []string{instrumentations.InstrumentationSQL},
			expected: []string{"SELECT credentials"},
		},
		{
			name:     "kafka only",
			instr:    []string{instrumentations.InstrumentationKafka},
			expected: []string{"important-topic publish", "important-topic process"},
		},
		{
			name:     "none",
			instr:    nil,
			expected: []string{},
		},
		{
			name:     "sql and redis",
			instr:    []string{instrumentations.InstrumentationSQL, instrumentations.InstrumentationRedis},
			expected: []string{"SELECT credentials", "SET", "GET"},
		},
		{
			name:     "kafka and grpc",
			instr:    []string{instrumentations.InstrumentationGRPC, instrumentations.InstrumentationKafka},
			expected: []string{"/grpcFoo", "/grpcGoo", "important-topic publish", "important-topic process"},
		},
		{
			name:     "mongo",
			instr:    []string{instrumentations.InstrumentationMongo},
			expected: []string{"insert mycollection"},
		},
	}

	spans := []request.Span{
		{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo", RequestStart: 100, End: 200},
		{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTPClient, Method: "PUT", Route: "/bar", RequestStart: 150, End: 175},
		{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeGRPC, Path: "/grpcFoo", RequestStart: 100, End: 200},
		{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeGRPCClient, Path: "/grpcGoo", RequestStart: 150, End: 175},
		makeSQLRequestSpan("SELECT password FROM credentials WHERE username=\"bill\""),
		{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeRedisClient, Method: "SET", Path: "redis_db", RequestStart: 150, End: 175},
		{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeRedisServer, Method: "GET", Path: "redis_db", RequestStart: 150, End: 175},
		{Type: request.EventTypeKafkaClient, Method: "process", Path: "important-topic", Statement: "test"},
		{Type: request.EventTypeKafkaServer, Method: "publish", Path: "important-topic", Statement: "test"},
		{Type: request.EventTypeMongoClient, Method: "insert", Path: "mycollection", DBNamespace: "mydatabase"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := makeTracesTestReceiver(tt.instr)
			traces := generateTracesForSpans(t, tr, spans)
			assert.Len(t, tt.expected, len(traces), tt.name)
			for i := 0; i < len(tt.expected); i++ {
				found := false
				for j := 0; j < len(traces); j++ {
					assert.Equal(t, 1, traces[j].ResourceSpans().Len(), tt.name+":"+tt.expected[i])
					if traces[j].ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Name() == tt.expected[i] {
						found = true
						break
					}
				}
				assert.True(t, found, tt.name+":"+tt.expected[i])
			}
		})
	}
}

func TestTracesSkipsInstrumented(t *testing.T) {
	svcNoExport := svc.Attrs{}

	svcNoExportTraces := svc.Attrs{}
	svcNoExportTraces.SetExportsOTelMetrics()

	svcExportTraces := svc.Attrs{}
	svcExportTraces.SetExportsOTelTraces()

	tests := []struct {
		name     string
		spans    []request.Span
		filtered bool
	}{
		{
			name:     "Foo span is not filtered",
			spans:    []request.Span{{Service: svcNoExport, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/foo", RequestStart: 100, End: 200}},
			filtered: false,
		},
		{
			name:     "/v1/metrics span is not filtered",
			spans:    []request.Span{{Service: svcNoExportTraces, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/v1/metrics", RequestStart: 100, End: 200}},
			filtered: false,
		},
		{
			name:     "/v1/traces span is filtered",
			spans:    []request.Span{{Service: svcExportTraces, Type: request.EventTypeHTTPClient, Method: "GET", Route: "/v1/traces", RequestStart: 100, End: 200}},
			filtered: true,
		},
	}

	tr := makeTracesTestReceiver([]string{instrumentations.InstrumentationALL})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			traces := generateTracesForSpans(t, tr, tt.spans)
			assert.Equal(t, tt.filtered, len(traces) == 0, tt.name)
		})
	}
}

func TestTraces_HTTPStatus(t *testing.T) {
	type testPair struct {
		httpCode   int
		statusCode string
	}

	t.Run("HTTP server testing", func(t *testing.T) {
		for _, p := range []testPair{
			{100, request.StatusCodeUnset},
			{103, request.StatusCodeUnset},
			{199, request.StatusCodeUnset},
			{200, request.StatusCodeUnset},
			{204, request.StatusCodeUnset},
			{299, request.StatusCodeUnset},
			{300, request.StatusCodeUnset},
			{399, request.StatusCodeUnset},
			{400, request.StatusCodeUnset},
			{404, request.StatusCodeUnset},
			{405, request.StatusCodeUnset},
			{499, request.StatusCodeUnset},
			{500, request.StatusCodeError},
			{5999, request.StatusCodeError},
		} {
			t.Run(fmt.Sprintf("%d_%s", p.httpCode, p.statusCode), func(t *testing.T) {
				assert.Equal(t, p.statusCode, request.HTTPSpanStatusCode(&request.Span{Status: p.httpCode, Type: request.EventTypeHTTP}))
				assert.Equal(t, p.statusCode, request.SpanStatusCode(&request.Span{Status: p.httpCode, Type: request.EventTypeHTTP}))
			})
		}
	})

	t.Run("HTTP client testing", func(t *testing.T) {
		for _, p := range []testPair{
			{100, request.StatusCodeUnset},
			{103, request.StatusCodeUnset},
			{199, request.StatusCodeUnset},
			{200, request.StatusCodeUnset},
			{204, request.StatusCodeUnset},
			{299, request.StatusCodeUnset},
			{300, request.StatusCodeUnset},
			{399, request.StatusCodeUnset},
			{400, request.StatusCodeError},
			{404, request.StatusCodeError},
			{405, request.StatusCodeError},
			{499, request.StatusCodeError},
			{500, request.StatusCodeError},
			{5999, request.StatusCodeError},
		} {
			t.Run(fmt.Sprintf("%d_%s", p.httpCode, p.statusCode), func(t *testing.T) {
				assert.Equal(t, p.statusCode, request.HTTPSpanStatusCode(&request.Span{Status: p.httpCode, Type: request.EventTypeHTTPClient}))
				assert.Equal(t, p.statusCode, request.SpanStatusCode(&request.Span{Status: p.httpCode, Type: request.EventTypeHTTPClient}))
			})
		}
	})
}

func TestTraces_GRPCStatus(t *testing.T) {
	type testPair struct {
		grpcCode   attribute.KeyValue
		statusCode string
	}

	t.Run("gRPC server testing", func(t *testing.T) {
		for _, p := range []testPair{
			{semconv.RPCGRPCStatusCodeOk, request.StatusCodeUnset},
			{semconv.RPCGRPCStatusCodeCancelled, request.StatusCodeUnset},
			{semconv.RPCGRPCStatusCodeUnknown, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeInvalidArgument, request.StatusCodeUnset},
			{semconv.RPCGRPCStatusCodeDeadlineExceeded, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeNotFound, request.StatusCodeUnset},
			{semconv.RPCGRPCStatusCodeAlreadyExists, request.StatusCodeUnset},
			{semconv.RPCGRPCStatusCodePermissionDenied, request.StatusCodeUnset},
			{semconv.RPCGRPCStatusCodeResourceExhausted, request.StatusCodeUnset},
			{semconv.RPCGRPCStatusCodeFailedPrecondition, request.StatusCodeUnset},
			{semconv.RPCGRPCStatusCodeAborted, request.StatusCodeUnset},
			{semconv.RPCGRPCStatusCodeOutOfRange, request.StatusCodeUnset},
			{semconv.RPCGRPCStatusCodeUnimplemented, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeInternal, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeUnavailable, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeDataLoss, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeUnauthenticated, request.StatusCodeUnset},
		} {
			t.Run(fmt.Sprintf("%v_%s", p.grpcCode, p.statusCode), func(t *testing.T) {
				assert.Equal(t, p.statusCode, request.GrpcSpanStatusCode(&request.Span{Status: int(p.grpcCode.Value.AsInt64()), Type: request.EventTypeGRPC}))
				assert.Equal(t, p.statusCode, request.SpanStatusCode(&request.Span{Status: int(p.grpcCode.Value.AsInt64()), Type: request.EventTypeGRPC}))
			})
		}
	})

	t.Run("gRPC client testing", func(t *testing.T) {
		for _, p := range []testPair{
			{semconv.RPCGRPCStatusCodeOk, request.StatusCodeUnset},
			{semconv.RPCGRPCStatusCodeCancelled, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeUnknown, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeInvalidArgument, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeDeadlineExceeded, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeNotFound, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeAlreadyExists, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodePermissionDenied, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeResourceExhausted, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeFailedPrecondition, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeAborted, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeOutOfRange, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeUnimplemented, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeInternal, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeUnavailable, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeDataLoss, request.StatusCodeError},
			{semconv.RPCGRPCStatusCodeUnauthenticated, request.StatusCodeError},
		} {
			t.Run(fmt.Sprintf("%v_%s", p.grpcCode, p.statusCode), func(t *testing.T) {
				assert.Equal(t, p.statusCode, request.GrpcSpanStatusCode(&request.Span{Status: int(p.grpcCode.Value.AsInt64()), Type: request.EventTypeGRPCClient}))
				assert.Equal(t, p.statusCode, request.SpanStatusCode(&request.Span{Status: int(p.grpcCode.Value.AsInt64()), Type: request.EventTypeGRPCClient}))
			})
		}
	})
}

func TestTraceGrouping(t *testing.T) {
	spans := []request.Span{}
	start := time.Now()
	for i := 0; i < 10; i++ {
		span := request.Span{
			Type:         request.EventTypeHTTP,
			RequestStart: start.UnixNano(),
			Start:        start.Add(time.Second).UnixNano(),
			End:          start.Add(3 * time.Second).UnixNano(),
			Method:       "GET",
			Route:        "/test" + strconv.Itoa(i),
			Status:       200,
			TraceID:      idgen.RandomTraceID(),
			Service:      svc.Attrs{UID: svc.UID{Instance: "1"}}, // Same service for all spans
		}
		spans = append(spans, span)
	}

	receiver := makeTracesTestReceiver([]string{"http"})

	t.Run("test sample all, same service", func(t *testing.T) {
		sampler := sdktrace.AlwaysSample()
		attrs := make(map[attr.Name]struct{})

		tr := []ptrace.Traces{}

		exporter := TestExporter{
			collector: func(td ptrace.Traces) {
				tr = append(tr, td)
			},
		}

		receiver.processSpans(t.Context(), exporter, spans, attrs, sampler)
		// We should make only one trace, all spans under the same resource attributes
		assert.Len(t, tr, 1)
	})
}

func makeSQLRequestSpan(sql string) request.Span {
	method, path := sqlprune.SQLParseOperationAndTable(sql)
	return request.Span{Type: request.EventTypeSQLClient, Method: method, Path: path, Statement: sql}
}

func generateTracesForSpans(t *testing.T, tr *tracesOTELReceiver, spans []request.Span) []ptrace.Traces {
	res := []ptrace.Traces{}
	traceAttrs, err := tracesgen.UserSelectedAttributes(tr.selectorCfg)
	require.NoError(t, err)
	for i := range spans {
		span := &spans[i]
		if tracesgen.SpanDiscarded(span, tr.is) {
			continue
		}
		tAttrs := tracesgen.TraceAttributesSelector(span, traceAttrs)

		res = append(res, tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(span, tAttrs), reporterName))
	}

	return res
}

func groupFromSpanAndAttributes(span *request.Span, attrs []attribute.KeyValue) []tracesgen.TraceSpanAndAttributes {
	groups := []tracesgen.TraceSpanAndAttributes{}
	groups = append(groups, tracesgen.TraceSpanAndAttributes{Span: span, Attributes: attrs})
	return groups
}

func makeTracesTestReceiver(instr []string) *tracesOTELReceiver {
	return makeTracesReceiver(
		otelcfg.TracesConfig{
			CommonEndpoint:    "http://something",
			BatchTimeout:      10 * time.Millisecond,
			ReportersCacheLen: 16,
			Instrumentations:  instr,
		},
		false,
		&global.ContextInfo{},
		&attributes.SelectorConfig{},
		msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10)),
	)
}

func makeTracesTestReceiverWithSpanMetrics(instr []string) *tracesOTELReceiver {
	return makeTracesReceiver(
		otelcfg.TracesConfig{
			CommonEndpoint:    "http://something",
			BatchTimeout:      10 * time.Millisecond,
			ReportersCacheLen: 16,
			Instrumentations:  instr,
		},
		true,
		&global.ContextInfo{},
		&attributes.SelectorConfig{},
		msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10)),
	)
}

type TestExporter struct {
	collector func(td ptrace.Traces)
}

func (e TestExporter) Start(_ context.Context, _ component.Host) error {
	return nil
}

func (e TestExporter) Shutdown(_ context.Context) error {
	return nil
}

func (e TestExporter) ConsumeTraces(_ context.Context, td ptrace.Traces) error {
	e.collector(td)
	return nil
}

func (e TestExporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{}
}
