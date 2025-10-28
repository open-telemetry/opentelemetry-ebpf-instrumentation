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
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/idgen"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
	"go.opentelemetry.io/obi/pkg/internal/sqlprune"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

var cache = expirable2.NewLRU[svc.UID, []attribute.KeyValue](1024, nil, 5*time.Minute)

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

	for b.Loop() {
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, attrs, "host-id", group, reporterName)

		if traces.ResourceSpans().Len() == 0 {
			b.Fatal("Generated traces is empty")
		}
	}
}

func groupFromSpanAndAttributes(span *request.Span, attrs []attribute.KeyValue) []tracesgen.TraceSpanAndAttributes {
	groups := []tracesgen.TraceSpanAndAttributes{}
	groups = append(groups, tracesgen.TraceSpanAndAttributes{Span: span, Attributes: attrs})
	return groups
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

		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(span, []attribute.KeyValue{}), reporterName)

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
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(span, []attribute.KeyValue{}), reporterName)

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
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(span, []attribute.KeyValue{}), reporterName)

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
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(span, []attribute.KeyValue{}), reporterName)

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

		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(span, []attribute.KeyValue{}), reporterName)

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
			Route:        "/test",
		}
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(span, []attribute.KeyValue{}), reporterName)

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
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(&span, tAttrs), reporterName)

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
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{"db.operation.name": {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(&span, tAttrs), reporterName)

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
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{attr.DBQueryText: {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(&span, tAttrs), reporterName)

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
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{attr.DBQueryText: {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(&span, tAttrs), reporterName)

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
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(&span, tAttrs), reporterName)

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
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{"db.operation.name": {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(&span, tAttrs), reporterName)

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
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{"db.operation.name": {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, "host-id", groupFromSpanAndAttributes(&span, tAttrs), reporterName)

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

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, otelcfg.ResourceAttrsFromEnv(&span.Service), "host-id", groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		rs := traces.ResourceSpans().At(0)
		attrs := rs.Resource().Attributes()
		ensureTraceStrAttr(t, attrs, attribute.Key("deployment.environment"), "productions")
		ensureTraceStrAttr(t, attrs, attribute.Key("source.upstream"), "beyla")
	})
	t.Run("override resource attributes", func(t *testing.T) {
		span := request.Span{Type: request.EventTypeHTTP, Method: "GET", Route: "/test", Status: 200}

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service,
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

func TestTraceSampling(t *testing.T) {
	spans := []request.Span{}
	start := time.Now()
	for i := range 10 {
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
	for i := range 10 {
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
		mc := otelcfg.MetricsConfig{
			Features: []string{otelcfg.FeatureSpan},
		}

		receiver := makeTracesTestReceiverWithSpanMetrics(mc.AnySpanMetricsEnabled(), []string{"http"})

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

func TestAttrsToMap(t *testing.T) {
	t.Run("test with string attribute", func(t *testing.T) {
		attrs := []attribute.KeyValue{
			attribute.String("key1", "value1"),
			attribute.String("key2", "value2"),
		}
		expected := pcommon.NewMap()
		expected.PutStr("key1", "value1")
		expected.PutStr("key2", "value2")

		result := tracesgen.AttrsToMap(attrs)
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

		result := tracesgen.AttrsToMap(attrs)
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

		result := tracesgen.AttrsToMap(attrs)
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

		result := tracesgen.AttrsToMap(attrs)
		assert.Equal(t, expected, result)
	})
}

func TestCodeToStatusCode(t *testing.T) {
	t.Run("test with unset code", func(t *testing.T) {
		code := request.StatusCodeUnset
		expected := ptrace.StatusCodeUnset

		result := tracesgen.CodeToStatusCode(code)
		assert.Equal(t, expected, result)
	})

	t.Run("test with error code", func(t *testing.T) {
		code := request.StatusCodeError
		expected := ptrace.StatusCodeError

		result := tracesgen.CodeToStatusCode(code)
		assert.Equal(t, expected, result)
	})

	t.Run("test with ok code", func(t *testing.T) {
		code := request.StatusCodeOk
		expected := ptrace.StatusCodeOk

		result := tracesgen.CodeToStatusCode(code)
		assert.Equal(t, expected, result)
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
			expected: []string{"GET /foo", "PUT /bar", "/grpcFoo", "/grpcGoo", "SELECT credentials", "SET", "GET", "publish important-topic", "process important-topic", "insert mycollection"},
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
			expected: []string{"publish important-topic", "process important-topic"},
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
			expected: []string{"/grpcFoo", "/grpcGoo", "publish important-topic", "process important-topic"},
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
				for j := range traces {
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
			attr1 := tracesgen.TraceAppResourceAttrs(cache, "123", &tt.span.Service)
			attr2 := tracesgen.TraceAppResourceAttrs(cache, "123", &tt.span.Service)
			assert.Equal(t, tt.same, &attr1[0] == &attr2[0], tt.name)
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
			attrs := tracesgen.TraceAttributesSelector(&tt.span, nil)
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

func TestTraceGrouping(t *testing.T) {
	spans := []request.Span{}
	start := time.Now()
	for i := range 10 {
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

//nolint:unparam
func ensureTraceAttrNotExists(t *testing.T, attrs pcommon.Map, key attribute.Key) {
	_, ok := attrs.Get(string(key))
	assert.False(t, ok)
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

func makeTracesTestReceiverWithSpanMetrics(enabled bool, instr []string) *tracesOTELReceiver {
	return makeTracesReceiver(
		otelcfg.TracesConfig{
			CommonEndpoint:    "http://something",
			BatchTimeout:      10 * time.Millisecond,
			ReportersCacheLen: 16,
			Instrumentations:  instr,
		},
		enabled,
		&global.ContextInfo{},
		&attributes.SelectorConfig{},
		msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10)),
	)
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
