// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen

import (
	"testing"
	"time"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/components/sqlprune"
	"go.opentelemetry.io/obi/pkg/components/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

var cache = expirable2.NewLRU[svc.UID, []attribute.KeyValue](1024, nil, 5*time.Minute)

const reporterName = "go.opentelemetry.io/obi"

func groupFromSpanAndAttributes(span *request.Span, attrs []attribute.KeyValue) []TraceSpanAndAttributes {
	groups := []TraceSpanAndAttributes{}
	groups = append(groups, TraceSpanAndAttributes{Span: span, Attributes: attrs})
	return groups
}

func BenchmarkGenerateTraces(b *testing.B) {
	start := time.Now()

	span := &request.Span{
		Type:         request.EventTypeHTTP,
		RequestStart: start.UnixNano(),
		Start:        start.Add(time.Second).UnixNano(),
		End:          start.Add(3 * time.Second).UnixNano(),
		Method:       "GET",
		Route:        "/test",
		Status:       200,
	}

	attrs := []attribute.KeyValue{
		attribute.String("http.method", "GET"),
		attribute.String("http.route", "/test"),
		attribute.Int("http.status_code", 200),
		attribute.String("net.host.name", "example.com"),
		attribute.String("user_agent.original", "benchmark-agent/1.0"),
		attribute.String("service.name", "test-service"),
		attribute.String("telemetry.sdk.language", "go"),
	}

	group := groupFromSpanAndAttributes(span, attrs)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		traces := GenerateTracesWithAttributes(cache, &span.Service, attrs, "host-id", group, reporterName)

		if traces.ResourceSpans().Len() == 0 {
			b.Fatal("Generated traces is empty")
		}
	}
}

func TestGenerateTraces(t *testing.T) {
	t.Run("test with subtraces - with parent spanId", func(t *testing.T) {
		start := time.Now()
		parentSpanID, _ := trace.SpanIDFromHex("89cbc1f60aab3b04")
		spanID, _ := trace.SpanIDFromHex("89cbc1f60aab3b01")
		traceID, _ := trace.TraceIDFromHex("eae56fbbec9505c102e8aabfc6b5c481")
		span := &request.Span{
			Type:         request.EventTypeHTTP,
			RequestStart: start.UnixNano(),
			Start:        start.Add(time.Second).UnixNano(),
			End:          start.Add(3 * time.Second).UnixNano(),
			Method:       "GET",
			Route:        "/test",
			Status:       200,
			ParentSpanID: parentSpanID,
			TraceID:      traceID,
			SpanID:       spanID,
			Service:      svc.Attrs{UID: svc.UID{Name: "1"}},
		}

		traces := GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(span, []attribute.KeyValue{}), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 3, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
		assert.Equal(t, "in queue", spans.At(0).Name())
		assert.Equal(t, "processing", spans.At(1).Name())
		assert.Equal(t, "GET /test", spans.At(2).Name())
		assert.Equal(t, ptrace.SpanKindInternal, spans.At(0).Kind())
		assert.Equal(t, ptrace.SpanKindInternal, spans.At(1).Kind())
		assert.Equal(t, ptrace.SpanKindServer, spans.At(2).Kind())

		assert.NotEmpty(t, spans.At(2).SpanID().String())
		assert.Equal(t, traceID.String(), spans.At(2).TraceID().String())
		topSpanID := spans.At(2).SpanID().String()
		assert.Equal(t, parentSpanID.String(), spans.At(2).ParentSpanID().String())

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.Equal(t, traceID.String(), spans.At(0).TraceID().String())
		assert.Equal(t, topSpanID, spans.At(0).ParentSpanID().String())

		assert.Equal(t, spanID.String(), spans.At(1).SpanID().String())
		assert.Equal(t, traceID.String(), spans.At(1).TraceID().String())
		assert.Equal(t, topSpanID, spans.At(1).ParentSpanID().String())

		assert.NotEqual(t, spans.At(0).SpanID().String(), spans.At(1).SpanID().String())
		assert.NotEqual(t, spans.At(1).SpanID().String(), spans.At(2).SpanID().String())
	})

	t.Run("test with subtraces - ids set bpf layer", func(t *testing.T) {
		start := time.Now()
		spanID, _ := trace.SpanIDFromHex("89cbc1f60aab3b04")
		traceID, _ := trace.TraceIDFromHex("eae56fbbec9505c102e8aabfc6b5c481")
		span := &request.Span{
			Type:         request.EventTypeHTTP,
			RequestStart: start.UnixNano(),
			Start:        start.Add(time.Second).UnixNano(),
			End:          start.Add(3 * time.Second).UnixNano(),
			Method:       "GET",
			Route:        "/test",
			Status:       200,
			SpanID:       spanID,
			TraceID:      traceID,
		}
		traces := GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(span, []attribute.KeyValue{}), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 3, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
		assert.Equal(t, "in queue", spans.At(0).Name())
		assert.Equal(t, "processing", spans.At(1).Name())
		assert.Equal(t, "GET /test", spans.At(2).Name())
		assert.Equal(t, ptrace.SpanKindInternal, spans.At(0).Kind())
		assert.Equal(t, ptrace.SpanKindInternal, spans.At(1).Kind())
		assert.Equal(t, ptrace.SpanKindServer, spans.At(2).Kind())

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.Equal(t, traceID.String(), spans.At(0).TraceID().String())

		assert.Equal(t, spanID.String(), spans.At(1).SpanID().String())
		assert.Equal(t, traceID.String(), spans.At(1).TraceID().String())

		assert.NotEmpty(t, spans.At(2).SpanID().String())
		assert.Equal(t, traceID.String(), spans.At(2).TraceID().String())
		assert.NotEqual(t, spans.At(0).SpanID().String(), spans.At(1).SpanID().String())
		assert.NotEqual(t, spans.At(1).SpanID().String(), spans.At(2).SpanID().String())
	})

	t.Run("test with subtraces - generated ids", func(t *testing.T) {
		start := time.Now()
		span := &request.Span{
			Type:         request.EventTypeHTTP,
			RequestStart: start.UnixNano(),
			Start:        start.Add(time.Second).UnixNano(),
			End:          start.Add(3 * time.Second).UnixNano(),
			Method:       "GET",
			Route:        "/test",
			Status:       200,
		}
		traces := GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(span, []attribute.KeyValue{}), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 3, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
		assert.Equal(t, "in queue", spans.At(0).Name())
		assert.Equal(t, "processing", spans.At(1).Name())
		assert.Equal(t, "GET /test", spans.At(2).Name())
		assert.Equal(t, ptrace.SpanKindInternal, spans.At(0).Kind())
		assert.Equal(t, ptrace.SpanKindInternal, spans.At(1).Kind())
		assert.Equal(t, ptrace.SpanKindServer, spans.At(2).Kind())

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())
		assert.NotEmpty(t, spans.At(1).SpanID().String())
		assert.NotEmpty(t, spans.At(1).TraceID().String())
		assert.NotEmpty(t, spans.At(2).SpanID().String())
		assert.NotEmpty(t, spans.At(2).TraceID().String())
		assert.NotEqual(t, spans.At(0).SpanID().String(), spans.At(1).SpanID().String())
		assert.NotEqual(t, spans.At(1).SpanID().String(), spans.At(2).SpanID().String())
	})

	t.Run("test without subspans - ids set bpf layer", func(t *testing.T) {
		start := time.Now()
		spanID, _ := trace.SpanIDFromHex("89cbc1f60aab3b04")
		traceID, _ := trace.TraceIDFromHex("eae56fbbec9505c102e8aabfc6b5c481")
		span := &request.Span{
			Type:         request.EventTypeHTTP,
			RequestStart: start.UnixNano(),
			End:          start.Add(3 * time.Second).UnixNano(),
			Method:       "GET",
			Route:        "/test",
			Status:       200,
			SpanID:       spanID,
			TraceID:      traceID,
		}
		traces := GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(span, []attribute.KeyValue{}), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.Equal(t, spanID.String(), spans.At(0).SpanID().String())
		assert.Equal(t, traceID.String(), spans.At(0).TraceID().String())
	})

	t.Run("test without subspans - with parent spanId", func(t *testing.T) {
		start := time.Now()
		parentSpanID, _ := trace.SpanIDFromHex("89cbc1f60aab3b04")
		traceID, _ := trace.TraceIDFromHex("eae56fbbec9505c102e8aabfc6b5c481")
		span := &request.Span{
			Type:         request.EventTypeHTTP,
			RequestStart: start.UnixNano(),
			End:          start.Add(3 * time.Second).UnixNano(),
			Method:       "GET",
			Route:        "/test",
			Status:       200,
			ParentSpanID: parentSpanID,
			TraceID:      traceID,
		}

		traces := GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(span, []attribute.KeyValue{}), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.Equal(t, parentSpanID.String(), spans.At(0).ParentSpanID().String())
		assert.Equal(t, traceID.String(), spans.At(0).TraceID().String())
	})

	t.Run("test without subspans - generated ids", func(t *testing.T) {
		start := time.Now()
		span := &request.Span{
			Type:         request.EventTypeHTTP,
			RequestStart: start.UnixNano(),
			End:          start.Add(3 * time.Second).UnixNano(),
			Method:       "GET",
		}
		traces := GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(span, []attribute.KeyValue{}), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())
	})
}

func TestGenerateTracesAttributes(t *testing.T) {
	t.Run("test SQL trace generation, no statement", func(t *testing.T) {
		span := makeSQLRequestSpan("SELECT password FROM credentials WHERE username=\"bill\"")
		tAttrs := TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())

		attrs := spans.At(0).Attributes()

		assert.Equal(t, 5, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "SELECT")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBCollectionName), "credentials")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "other_sql")
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBQueryText))
	})

	t.Run("test SQL trace generation, unknown attribute", func(t *testing.T) {
		span := makeSQLRequestSpan("SELECT password, name FROM credentials WHERE username=\"bill\"")
		tAttrs := TraceAttributesSelector(&span, map[attr.Name]struct{}{"db.operation.name": {}})
		traces := GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())

		attrs := spans.At(0).Attributes()

		assert.Equal(t, 5, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "SELECT")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBCollectionName), "credentials")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "other_sql")
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBQueryText))
	})

	t.Run("test SQL trace generation, unknown attribute", func(t *testing.T) {
		span := makeSQLRequestSpan("SELECT password FROM credentials WHERE username=\"bill\"")
		tAttrs := TraceAttributesSelector(&span, map[attr.Name]struct{}{attr.DBQueryText: {}})
		traces := GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())

		attrs := spans.At(0).Attributes()

		assert.Equal(t, 6, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "SELECT")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBCollectionName), "credentials")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "other_sql")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBQueryText), "SELECT password FROM credentials WHERE username=\"bill\"")
	})

	t.Run("test SQL trace generation, error", func(t *testing.T) {
		span := makeSQLRequestErroredSpan("SELECT * FROM obi.nonexisting")
		tAttrs := TraceAttributesSelector(&span, map[attr.Name]struct{}{attr.DBQueryText: {}})
		traces := GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())

		attrs := spans.At(0).Attributes()
		status := spans.At(0).Status()
		assert.Equal(t, ptrace.StatusCodeError, status.Code())
		assert.Equal(t, "SQL Server errored: error_code=8 sql_state=#1234 message=SQL error message", status.Message())

		assert.Equal(t, 8, attrs.Len())

		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "SELECT")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBCollectionName), "obi.nonexisting")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "other_sql")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBResponseStatusCode), "8")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.ErrorType), "#1234")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBQueryText), "SELECT * FROM obi.nonexisting")
	})

	t.Run("test Kafka trace generation", func(t *testing.T) {
		span := request.Span{Type: request.EventTypeKafkaClient, Method: "process", Path: "important-topic", Statement: "test"}
		tAttrs := TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())

		attrs := spans.At(0).Attributes()
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.MessagingOpType), "process")
		ensureTraceStrAttr(t, attrs, semconv.MessagingDestinationNameKey, "important-topic")
		ensureTraceStrAttr(t, attrs, semconv.MessagingClientIDKey, "test")
	})

	t.Run("test Mongo trace generation", func(t *testing.T) {
		span := request.Span{Type: request.EventTypeMongoClient, Method: "insert", Path: "mycollection", DBNamespace: "mydatabase", Status: 0}
		tAttrs := TraceAttributesSelector(&span, map[attr.Name]struct{}{"db.operation.name": {}})
		traces := GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())

		attrs := spans.At(0).Attributes()

		assert.Equal(t, 6, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "insert")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBCollectionName), "mycollection")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBNamespace), "mydatabase")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "mongodb")
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBQueryText))
		assert.Equal(t, ptrace.StatusCodeUnset, spans.At(0).Status().Code())
	})

	t.Run("test Mongo trace generation with error", func(t *testing.T) {
		span := request.Span{Type: request.EventTypeMongoClient, Method: "insert", Path: "mycollection", DBNamespace: "mydatabase", Status: 1, DBError: request.DBError{ErrorCode: "1", Description: "Internal MongoDB error"}}
		tAttrs := TraceAttributesSelector(&span, map[attr.Name]struct{}{"db.operation.name": {}})
		traces := GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())

		attrs := spans.At(0).Attributes()

		assert.Equal(t, 7, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "insert")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBCollectionName), "mycollection")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBNamespace), "mydatabase")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "mongodb")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBResponseStatusCode), "1")
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBQueryText))
		assert.Equal(t, ptrace.StatusCodeError, spans.At(0).Status().Code())
		assert.Equal(t, "Internal MongoDB error", spans.At(0).Status().Message())
	})

	t.Run("test env var resource attributes", func(t *testing.T) {
		defer otelcfg.RestoreEnvAfterExecution()()
		t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment=productions,source.upstream=beyla")
		span := request.Span{Type: request.EventTypeHTTP, Method: "GET", Route: "/test", Status: 200}

		tAttrs := TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := GenerateTracesWithAttributes(cache, &span.Service, otelcfg.ResourceAttrsFromEnv(&span.Service), "host-id", groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		rs := traces.ResourceSpans().At(0)
		attrs := rs.Resource().Attributes()
		ensureTraceStrAttr(t, attrs, attribute.Key("deployment.environment"), "productions")
		ensureTraceStrAttr(t, attrs, attribute.Key("source.upstream"), "beyla")
	})

	t.Run("override resource attributes", func(t *testing.T) {
		span := request.Span{Type: request.EventTypeHTTP, Method: "GET", Route: "/test", Status: 200}

		tAttrs := TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := GenerateTracesWithAttributes(cache, &span.Service,
			otelcfg.ResourceAttrsFromEnv(&span.Service), "host-id",
			groupFromSpanAndAttributes(&span, tAttrs),
			reporterName,
			attribute.String("deployment.environment", "productions"),
			attribute.String("source.upstream", "OBI"),
			semconv.OTelLibraryName("my-reporter"),
		)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		rs := traces.ResourceSpans().At(0)
		attrs := rs.Resource().Attributes()
		ensureTraceStrAttr(t, attrs, "deployment.environment", "productions")
		ensureTraceStrAttr(t, attrs, "source.upstream", "OBI")
		ensureTraceStrAttr(t, attrs, "otel.library.name", "my-reporter")
	})
}

func TestAttrsToMap(t *testing.T) {
	t.Run("test with string attribute", func(t *testing.T) {
		attrs := []attribute.KeyValue{
			attribute.String("key1", "value1"),
			attribute.String("key2", "value2"),
		}
		expected := pcommon.NewMap()
		expected.PutStr("key1", "value1")
		expected.PutStr("key2", "value2")

		result := AttrsToMap(attrs)
		assert.Equal(t, expected, result)
	})

	t.Run("test with int attribute", func(t *testing.T) {
		attrs := []attribute.KeyValue{
			attribute.Int64("key1", 10),
			attribute.Int64("key2", 20),
		}
		expected := pcommon.NewMap()
		expected.PutInt("key1", 10)
		expected.PutInt("key2", 20)

		result := AttrsToMap(attrs)
		assert.Equal(t, expected, result)
	})

	t.Run("test with float attribute", func(t *testing.T) {
		attrs := []attribute.KeyValue{
			attribute.Float64("key1", 3.14),
			attribute.Float64("key2", 2.718),
		}
		expected := pcommon.NewMap()
		expected.PutDouble("key1", 3.14)
		expected.PutDouble("key2", 2.718)

		result := AttrsToMap(attrs)
		assert.Equal(t, expected, result)
	})

	t.Run("test with bool attribute", func(t *testing.T) {
		attrs := []attribute.KeyValue{
			attribute.Bool("key1", true),
			attribute.Bool("key2", false),
		}
		expected := pcommon.NewMap()
		expected.PutBool("key1", true)
		expected.PutBool("key2", false)

		result := AttrsToMap(attrs)
		assert.Equal(t, expected, result)
	})
}

func TestCodeToStatusCode(t *testing.T) {
	t.Run("test with unset code", func(t *testing.T) {
		code := request.StatusCodeUnset
		expected := ptrace.StatusCodeUnset

		result := CodeToStatusCode(code)
		assert.Equal(t, expected, result)
	})

	t.Run("test with error code", func(t *testing.T) {
		code := request.StatusCodeError
		expected := ptrace.StatusCodeError

		result := CodeToStatusCode(code)
		assert.Equal(t, expected, result)
	})

	t.Run("test with ok code", func(t *testing.T) {
		code := request.StatusCodeOk
		expected := ptrace.StatusCodeOk

		result := CodeToStatusCode(code)
		assert.Equal(t, expected, result)
	})
}

func TestTracesAttrReuse(t *testing.T) {
	tests := []struct {
		name string
		span request.Span
		same bool
	}{
		{
			name: "Reuses the trace attributes, with svc.Instance defined",
			span: request.Span{Service: svc.Attrs{UID: svc.UID{Instance: "foo"}}, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo", RequestStart: 100, End: 200},
			same: true,
		},
		{
			name: "No Instance, no caching of trace attributes",
			span: request.Span{Service: svc.Attrs{}, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo", RequestStart: 100, End: 200},
			same: false,
		},
		{
			name: "No Service, no caching of trace attributes",
			span: request.Span{Type: request.EventTypeHTTP, Method: "GET", Route: "/foo", RequestStart: 100, End: 200},
			same: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr1 := TraceAppResourceAttrs(cache, "123", &tt.span.Service)
			attr2 := TraceAppResourceAttrs(cache, "123", &tt.span.Service)
			assert.Equal(t, tt.same, &attr1[0] == &attr2[0], tt.name)
		})
	}
}

func TestHostPeerAttributes(t *testing.T) {
	// Metrics
	tests := []struct {
		name   string
		span   request.Span
		client string
		server string
	}{
		{
			name:   "Same namespaces HTTP",
			span:   request.Span{Type: request.EventTypeHTTP, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Client in different namespace",
			span:   request.Span{Type: request.EventTypeHTTP, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client.far",
			server: "server",
		},
		{
			name:   "Same namespaces for HTTP client",
			span:   request.Span{Type: request.EventTypeHTTPClient, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Server in different namespace ",
			span:   request.Span{Type: request.EventTypeHTTPClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server.far",
		},
		{
			name:   "Same namespaces GRPC",
			span:   request.Span{Type: request.EventTypeGRPC, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Client in different namespace GRPC",
			span:   request.Span{Type: request.EventTypeGRPC, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client.far",
			server: "server",
		},
		{
			name:   "Same namespaces for GRPC client",
			span:   request.Span{Type: request.EventTypeGRPCClient, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server",
		},
		{
			name:   "Server in different namespace GRPC",
			span:   request.Span{Type: request.EventTypeGRPCClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "client",
			server: "server.far",
		},
		{
			name:   "Same namespaces for SQL client",
			span:   request.Span{Type: request.EventTypeSQLClient, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "",
			server: "server",
		},
		{
			name:   "Server in different namespace SQL",
			span:   request.Span{Type: request.EventTypeSQLClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "",
			server: "server.far",
		},
		{
			name:   "Same namespaces for Redis client",
			span:   request.Span{Type: request.EventTypeRedisClient, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "",
			server: "server",
		},
		{
			name:   "Server in different namespace Redis",
			span:   request.Span{Type: request.EventTypeRedisClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "",
			server: "server.far",
		},
		{
			name:   "Client in different namespace Redis",
			span:   request.Span{Type: request.EventTypeRedisServer, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "",
			server: "server",
		},
		{
			name:   "Server in different namespace Kafka",
			span:   request.Span{Type: request.EventTypeKafkaClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "",
			server: "server.far",
		},
		{
			name:   "Client in different namespace Kafka",
			span:   request.Span{Type: request.EventTypeKafkaServer, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "",
			server: "server",
		},
		{
			name:   "Same namespaces for Mongo client",
			span:   request.Span{Type: request.EventTypeMongoClient, PeerName: "client", HostName: "server", OtherNamespace: "same", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "",
			server: "server",
		},
		{
			name:   "Server in different namespace Mongo",
			span:   request.Span{Type: request.EventTypeMongoClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "",
			server: "server.far",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := TraceAttributesSelector(&tt.span, nil)
			if tt.server != "" {
				var found attribute.KeyValue
				for _, a := range attrs {
					if a.Key == attribute.Key(attr.ServerAddr) {
						found = a
						assert.Equal(t, tt.server, a.Value.AsString())
					}
				}
				assert.NotNil(t, found)
			}
			if tt.client != "" {
				var found attribute.KeyValue
				for _, a := range attrs {
					if a.Key == attribute.Key(attr.ClientAddr) {
						found = a
						assert.Equal(t, tt.client, a.Value.AsString())
					}
				}
				assert.NotNil(t, found)
			}
		})
	}
}

func makeSQLRequestSpan(sql string) request.Span {
	method, path := sqlprune.SQLParseOperationAndTable(sql)
	return request.Span{Type: request.EventTypeSQLClient, Method: method, Path: path, Statement: sql}
}

func makeSQLRequestErroredSpan(sql string) request.Span {
	method, path := sqlprune.SQLParseOperationAndTable(sql)
	return request.Span{
		Type:      request.EventTypeSQLClient,
		Method:    method,
		Path:      path,
		Statement: sql,
		Status:    1,
		SQLError: &request.SQLError{
			Code:     8,
			SQLState: "#1234",
			Message:  "SQL error message",
		},
	}
}

func ensureTraceStrAttr(t *testing.T, attrs pcommon.Map, key attribute.Key, val string) {
	v, ok := attrs.Get(string(key))
	assert.True(t, ok)
	assert.Equal(t, val, v.AsString())
}

func ensureTraceAttrNotExists(t *testing.T, attrs pcommon.Map, key attribute.Key) {
	_, ok := attrs.Get(string(key))
	assert.False(t, ok)
}
