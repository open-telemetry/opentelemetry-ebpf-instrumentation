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
	"go.uber.org/zap/zapcore"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
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

var hostID = &meta.NodeMeta{HostID: "host-id"}

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
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, attrs, hostID, group, reporterName)

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

		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(span, []attribute.KeyValue{}), reporterName)

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
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(span, []attribute.KeyValue{}), reporterName)

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
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(span, []attribute.KeyValue{}), reporterName)

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
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(span, []attribute.KeyValue{}), reporterName)

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

		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(span, []attribute.KeyValue{}), reporterName)

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
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(span, []attribute.KeyValue{}), reporterName)

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
		span.HostName = "postgresql"
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

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
		ensureTraceStrAttr(t, attrs, semconv.PeerServiceKey, "postgresql")
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBQueryText))
	})

	t.Run("test SQL server trace generation", func(t *testing.T) {
		span := makeSQLServerRequestSpan("SELECT password FROM credentials WHERE username=\"bill\"")
		span.HostName = "postgresql"
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.Equal(t, ptrace.SpanKindServer, spans.At(0).Kind())

		attrs := spans.At(0).Attributes()

		assert.Equal(t, 5, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "SELECT")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBCollectionName), "credentials")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "other_sql")
		ensureTraceAttrNotExists(t, attrs, semconv.PeerServiceKey)
	})

	t.Run("test SQL trace generation, unknown attribute", func(t *testing.T) {
		span := makeSQLRequestSpan("SELECT password, name FROM credentials WHERE username=\"bill\"")
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{"db.operation.name": {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

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
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBQueryText))
	})

	t.Run("test SQL trace generation, unknown attribute", func(t *testing.T) {
		span := makeSQLRequestSpan("SELECT password FROM credentials WHERE username=\"bill\"")
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{attr.DBQueryText: {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())

		attrs := spans.At(0).Attributes()

		assert.Equal(t, 7, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "SELECT")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBCollectionName), "credentials")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "other_sql")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBQueryText), "SELECT password FROM credentials WHERE username=\"bill\"")
	})

	t.Run("test SQL trace generation, error", func(t *testing.T) {
		span := makeSQLRequestErroredSpan("SELECT * FROM obi.nonexisting")
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{attr.DBQueryText: {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

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

		assert.Equal(t, 9, attrs.Len())

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
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

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

	t.Run("test MQTT trace generation", func(t *testing.T) {
		span := request.Span{Type: request.EventTypeMQTTClient, Method: "publish", Path: "sensors/temperature", Statement: "mqtt-client-1"}
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())

		attrs := spans.At(0).Attributes()
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.MessagingOpType), "publish")
		ensureTraceStrAttr(t, attrs, semconv.MessagingDestinationNameKey, "sensors/temperature")
		ensureTraceStrAttr(t, attrs, semconv.MessagingClientIDKey, "mqtt-client-1")
	})

	t.Run("test NATS trace generation", func(t *testing.T) {
		span := request.Span{
			Type:          request.EventTypeNATSClient,
			Method:        "publish",
			Path:          "updates.orders",
			Statement:     "nats-client-1",
			ContentLength: 42,
		}
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())

		attrs := spans.At(0).Attributes()
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.MessagingOpType), "publish")
		ensureTraceStrAttr(t, attrs, semconv.MessagingDestinationNameKey, "updates.orders")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.MessagingSystem), "nats")
		ensureTraceStrAttr(t, attrs, semconv.MessagingClientIDKey, "nats-client-1")
		ensureTraceIntAttr(t, attrs, semconv.MessagingMessageEnvelopeSizeKey, 42)
	})

	t.Run("test Mongo trace generation", func(t *testing.T) {
		span := request.Span{Type: request.EventTypeMongoClient, Method: "insert", Path: "mycollection", DBNamespace: "mydatabase", Status: 0}
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{"db.operation.name": {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

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
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBQueryText))
		assert.Equal(t, ptrace.StatusCodeUnset, spans.At(0).Status().Code())
	})
	t.Run("test Mongo trace generation with error", func(t *testing.T) {
		span := request.Span{Type: request.EventTypeMongoClient, Method: "insert", Path: "mycollection", DBNamespace: "mydatabase", Status: 1, DBError: request.DBError{ErrorCode: "1", Description: "Internal MongoDB error"}}
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{"db.operation.name": {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())

		attrs := spans.At(0).Attributes()

		assert.Equal(t, 8, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "insert")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBCollectionName), "mycollection")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBNamespace), "mydatabase")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "mongodb")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBResponseStatusCode), "1")
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBQueryText))
		assert.Equal(t, ptrace.StatusCodeError, spans.At(0).Status().Code())
		assert.Equal(t, "Internal MongoDB error", spans.At(0).Status().Message())
	})
	t.Run("test Couchbase trace generation", func(t *testing.T) {
		span := request.Span{Type: request.EventTypeCouchbaseClient, Method: "GET", Path: "mycollection", DBNamespace: "mybucket.myscope", Status: 0}
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{"db.operation.name": {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())

		attrs := spans.At(0).Attributes()

		assert.Equal(t, 7, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "GET")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBCollectionName), "mycollection")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBNamespace), "mybucket.myscope")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "couchbase")
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBQueryText))
		assert.Equal(t, ptrace.StatusCodeUnset, spans.At(0).Status().Code())
	})
	t.Run("test Couchbase trace generation with error", func(t *testing.T) {
		span := request.Span{Type: request.EventTypeCouchbaseClient, Method: "GET", Path: "mycollection", DBNamespace: "mybucket.myscope", Status: 1, DBError: request.DBError{ErrorCode: "1", Description: "KEY_NOT_FOUND"}}
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{"db.operation.name": {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())

		attrs := spans.At(0).Attributes()

		assert.Equal(t, 8, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "GET")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBCollectionName), "mycollection")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBNamespace), "mybucket.myscope")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "couchbase")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBResponseStatusCode), "1")
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBQueryText))
		assert.Equal(t, ptrace.StatusCodeError, spans.At(0).Status().Code())
		assert.Equal(t, "KEY_NOT_FOUND", spans.At(0).Status().Message())
	})
	t.Run("test Couchbase trace generation with db.query.text", func(t *testing.T) {
		span := request.Span{
			Type:        request.EventTypeCouchbaseClient,
			Method:      "SET",
			Path:        "mycollection",
			DBNamespace: "mybucket.myscope",
			Statement:   `SET user::42 TTL=3600 {"name":"alice"}`,
			Status:      0,
		}
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{"db.operation.name": {}, "db.query.text": {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
		attrs := spans.At(0).Attributes()

		assert.Equal(t, 8, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "SET")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBQueryText), `SET user::42 TTL=3600 {"name":"alice"}`)
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "couchbase")
	})
	t.Run("test Couchbase trace generation does not emit db.query.text when not selected", func(t *testing.T) {
		span := request.Span{
			Type:        request.EventTypeCouchbaseClient,
			Method:      "SET",
			Path:        "mycollection",
			DBNamespace: "mybucket.myscope",
			Statement:   `SET user::42 TTL=3600 {"name":"alice"}`,
			Status:      0,
		}
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{"db.operation.name": {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
		attrs := spans.At(0).Attributes()
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBQueryText))
	})
	t.Run("test Memcached trace generation", func(t *testing.T) {
		span := request.Span{Type: request.EventTypeMemcachedClient, Method: "GET", Path: "session-key", Status: 0}
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{"db.operation.name": {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())
		assert.Equal(t, "GET", spans.At(0).Name())

		attrs := spans.At(0).Attributes()

		assert.Equal(t, 5, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "GET")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "memcached")
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBCollectionName))
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBQueryText))
		assert.Equal(t, ptrace.StatusCodeUnset, spans.At(0).Status().Code())
	})
	t.Run("test Memcached trace generation with db.query.text", func(t *testing.T) {
		span := request.Span{Type: request.EventTypeMemcachedClient, Method: "GET", Path: "session-key", Status: 0}
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{"db.operation.name": {}, "db.query.text": {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
		attrs := spans.At(0).Attributes()

		assert.Equal(t, 6, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "GET")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBQueryText), "session-key")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "memcached")
	})
	t.Run("test Memcached trace generation with error", func(t *testing.T) {
		span := request.Span{Type: request.EventTypeMemcachedServer, Method: "GET", Path: "session-key", Status: 1, DBError: request.DBError{ErrorCode: "SERVER_ERROR", Description: "SERVER_ERROR out of memory"}}
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{"db.operation.name": {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())
		assert.Equal(t, "GET", spans.At(0).Name())

		attrs := spans.At(0).Attributes()

		assert.Equal(t, 5, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "GET")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "memcached")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBResponseStatusCode), "SERVER_ERROR")
		ensureTraceAttrNotExists(t, attrs, semconv.PeerServiceKey)
		assert.Equal(t, ptrace.StatusCodeError, spans.At(0).Status().Code())
		assert.Equal(t, "SERVER_ERROR out of memory", spans.At(0).Status().Message())
	})
	t.Run("test SQL++ trace generation", func(t *testing.T) {
		span := request.Span{
			Type:        request.EventTypeHTTPClient,
			SubType:     request.HTTPSubtypeSQLPP,
			Method:      "SELECT",
			Route:       "travel-sample._default.airline",
			DBNamespace: "travel-sample",
			DBSystem:    "couchbase",
			Statement:   "SELECT * FROM `travel-sample`._default.airline WHERE id = 10",
			Host:        "localhost",
			HostPort:    8093,
			Status:      200,
		}
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{attr.DBQueryText: {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())
		assert.Equal(t, "SELECT travel-sample._default.airline", spans.At(0).Name())

		attrs := spans.At(0).Attributes()

		assert.Equal(t, 8, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "SELECT")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBCollectionName), "travel-sample._default.airline")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBNamespace), "travel-sample")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "couchbase")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBQueryText), "SELECT * FROM `travel-sample`._default.airline WHERE id = 10")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.ServerAddr), "localhost")
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.HTTPResponseStatusCode))
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.ErrorType))
		assert.Equal(t, ptrace.StatusCodeUnset, spans.At(0).Status().Code())
	})
	t.Run("test SQL++ trace generation without db.query.text", func(t *testing.T) {
		span := request.Span{
			Type:        request.EventTypeHTTPClient,
			SubType:     request.HTTPSubtypeSQLPP,
			Method:      "SELECT",
			Route:       "travel-sample._default.airline",
			DBNamespace: "travel-sample",
			DBSystem:    "couchbase",
			Statement:   "SELECT * FROM `travel-sample`._default.airline WHERE id = 10",
			Host:        "localhost",
			HostPort:    8093,
			Status:      200,
		}
		// Without db.query.text in optional attributes
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
		attrs := spans.At(0).Attributes()

		assert.Equal(t, 7, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "SELECT")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBCollectionName), "travel-sample._default.airline")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBNamespace), "travel-sample")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "couchbase")
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBQueryText))
		assert.Equal(t, ptrace.StatusCodeUnset, spans.At(0).Status().Code())
	})
	t.Run("test SQL++ trace generation with error", func(t *testing.T) {
		span := request.Span{
			Type:        request.EventTypeHTTPClient,
			SubType:     request.HTTPSubtypeSQLPP,
			Method:      "SELECT",
			Route:       "travel-sample._default.nonexistent",
			DBNamespace: "travel-sample",
			DBSystem:    "couchbase",
			Statement:   "SELECT * FROM `travel-sample`._default.nonexistent",
			Host:        "localhost",
			HostPort:    8093,
			Status:      404,
			DBError: request.DBError{
				ErrorCode:   "12003",
				Description: "Keyspace not found in CB datastore: default:travel-sample._default.nonexistent",
			},
		}
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{attr.DBQueryText: {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().Len())
		assert.Equal(t, 1, traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()

		assert.NotEmpty(t, spans.At(0).SpanID().String())
		assert.NotEmpty(t, spans.At(0).TraceID().String())
		assert.Equal(t, "SELECT travel-sample._default.nonexistent", spans.At(0).Name())

		attrs := spans.At(0).Attributes()

		assert.Equal(t, 10, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "SELECT")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBCollectionName), "travel-sample._default.nonexistent")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBNamespace), "travel-sample")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "couchbase")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBQueryText), "SELECT * FROM `travel-sample`._default.nonexistent")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.ErrorType), "12003")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBResponseStatusCode), "12003")
		assert.Equal(t, ptrace.StatusCodeError, spans.At(0).Status().Code())
		assert.Equal(t, "Keyspace not found in CB datastore: default:travel-sample._default.nonexistent", spans.At(0).Status().Message())
	})
	t.Run("test SQL++ trace generation with minimal attributes", func(t *testing.T) {
		span := request.Span{
			Type:     request.EventTypeHTTPClient,
			SubType:  request.HTTPSubtypeSQLPP,
			Method:   "INSERT",
			DBSystem: "couchbase",
			Host:     "localhost",
			HostPort: 8093,
			Status:   200,
		}
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
		// When no Route or DBNamespace, trace name falls back to operation + host:port
		assert.Equal(t, "INSERT localhost:8093", spans.At(0).Name())

		attrs := spans.At(0).Attributes()

		// Only required attributes: server.addr, server.port, peer.service, db.system.name, db.operation.name
		assert.Equal(t, 5, attrs.Len())
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBOperation), "INSERT")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.DBSystemName), "couchbase")
		ensureTraceStrAttr(t, attrs, attribute.Key(attr.ServerAddr), "localhost")
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBCollectionName))
		ensureTraceAttrNotExists(t, attrs, attribute.Key(attr.DBNamespace))
		assert.Equal(t, ptrace.StatusCodeUnset, spans.At(0).Status().Code())
	})
	t.Run("test env var resource attributes", func(t *testing.T) {
		defer otelcfg.RestoreEnvAfterExecution()()
		t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment=productions,source.upstream=obi")
		span := request.Span{Type: request.EventTypeHTTP, Method: "GET", Route: "/test", Status: 200}

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, otelcfg.ResourceAttrsFromEnv(&span.Service), hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		rs := traces.ResourceSpans().At(0)
		attrs := rs.Resource().Attributes()
		ensureTraceStrAttr(t, attrs, attribute.Key("deployment.environment"), "productions")
		ensureTraceStrAttr(t, attrs, attribute.Key("source.upstream"), "obi")
	})
	t.Run("override resource attributes", func(t *testing.T) {
		span := request.Span{Type: request.EventTypeHTTP, Method: "GET", Route: "/test", Status: 200}

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service,
			otelcfg.ResourceAttrsFromEnv(&span.Service), hostID,
			groupFromSpanAndAttributes(&span, tAttrs),
			reporterName,
			attribute.String("deployment.environment", "productions"),
			attribute.String("source.upstream", "OBI"),
			semconv.OTelScopeName("my-reporter"),
		)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		rs := traces.ResourceSpans().At(0)
		attrs := rs.Resource().Attributes()
		ensureTraceStrAttr(t, attrs, "deployment.environment", "productions")
		ensureTraceStrAttr(t, attrs, "source.upstream", "OBI")
		ensureTraceStrAttr(t, attrs, "otel.scope.name", "my-reporter")
	})

	makeOpenAISpan := func(ai *request.VendorOpenAI) request.Span {
		return request.Span{
			Type:    request.EventTypeHTTPClient,
			SubType: request.HTTPSubtypeOpenAI,
			Method:  "POST",
			Path:    "https://api.openai.com/v1/responses",
			Status:  200,
			GenAI:   &request.GenAI{OpenAI: ai},
		}
	}

	makeAnthropicSpan := func(ai *request.VendorAnthropic) request.Span {
		return request.Span{
			Type:    request.EventTypeHTTPClient,
			SubType: request.HTTPSubtypeAnthropic,
			Method:  "POST",
			Path:    "https://api.anthropic.com/v1/messages",
			Status:  200,
			GenAI:   &request.GenAI{Anthropic: ai},
		}
	}

	t.Run("OpenAI span - core attributes, no optional", func(t *testing.T) {
		span := makeOpenAISpan(&request.VendorOpenAI{
			ID:            "resp_abc123",
			OperationName: "response",
			ResponseModel: "gpt-5-mini-2025-08-07",
			Temperature:   1.0,
			TopP:          1.0,
			Usage:         request.OpenAIUsage{InputTokens: 36, OutputTokens: 691, TotalTokens: 727},
			Request: request.OpenAIInput{
				Input:        "How do I check if a Python object is an instance of a class?",
				Instructions: "You are a coding assistant that talks like a pirate.",
				Model:        "gpt-5-mini",
			},
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		require.Equal(t, 1, traces.ResourceSpans().Len())
		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()

		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIProviderNameKey, "openai")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIOperationNameKey, "response")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIResponseIDKey, "resp_abc123")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIRequestModelKey, "gpt-5-mini")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIResponseModelKey, "gpt-5-mini-2025-08-07")
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIInputMessagesKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIOutputMessagesKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAISystemInstructionsKey)
	})

	t.Run("OpenAI span - optional GenAIInput enabled", func(t *testing.T) {
		span := makeOpenAISpan(&request.VendorOpenAI{
			ID:            "resp_abc123",
			OperationName: "response",
			ResponseModel: "gpt-5-mini-2025-08-07",
			Temperature:   1.0,
			Request: request.OpenAIInput{
				Input:        "How do I check if a Python object is an instance of a class?",
				Instructions: "You are a coding assistant that talks like a pirate.",
				Model:        "gpt-5-mini",
			},
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{attr.GenAIInput: {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIInputMessagesKey, "How do I check if a Python object is an instance of a class?")
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIOutputMessagesKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAISystemInstructionsKey)
	})

	t.Run("OpenAI span - optional GenAIOutput enabled", func(t *testing.T) {
		span := makeOpenAISpan(&request.VendorOpenAI{
			ID:            "resp_abc123",
			OperationName: "response",
			ResponseModel: "gpt-5-mini-2025-08-07",
			Output:        []byte(`[{"type":"message","role":"assistant","content":"Arrr!"}]`),
			Request:       request.OpenAIInput{Model: "gpt-5-mini"},
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{attr.GenAIOutput: {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIOutputMessagesKey, `[{"type":"message","role":"assistant","content":"Arrr!"}]`)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIInputMessagesKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAISystemInstructionsKey)
	})

	t.Run("OpenAI span - optional GenAIInstructions enabled", func(t *testing.T) {
		span := makeOpenAISpan(&request.VendorOpenAI{
			ID:            "resp_abc123",
			OperationName: "response",
			ResponseModel: "gpt-5-mini-2025-08-07",
			Request: request.OpenAIInput{
				Model:        "gpt-5-mini",
				Instructions: "You are a coding assistant that talks like a pirate.",
			},
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{attr.GenAIInstructions: {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAISystemInstructionsKey, "You are a coding assistant that talks like a pirate.")
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIInputMessagesKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIOutputMessagesKey)
	})

	t.Run("OpenAI span - instructions not emitted when empty even if attr enabled", func(t *testing.T) {
		span := makeOpenAISpan(&request.VendorOpenAI{
			ID:            "resp_abc123",
			OperationName: "response",
			ResponseModel: "gpt-5-mini-2025-08-07",
			Request:       request.OpenAIInput{Model: "gpt-5-mini"}, // no Instructions
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{attr.GenAIInstructions: {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAISystemInstructionsKey)
	})

	t.Run("OpenAI span - all optional attributes enabled", func(t *testing.T) {
		span := makeOpenAISpan(&request.VendorOpenAI{
			ID:            "resp_abc123",
			OperationName: "response",
			ResponseModel: "gpt-5-mini-2025-08-07",
			Temperature:   1.0,
			TopP:          1.0,
			Usage:         request.OpenAIUsage{InputTokens: 36, OutputTokens: 691},
			Output:        []byte(`[{"type":"message","role":"assistant","content":"Arrr!"}]`),
			Request: request.OpenAIInput{
				Input:        "How do I check if a Python object is an instance of a class?",
				Instructions: "You are a coding assistant that talks like a pirate.",
				Model:        "gpt-5-mini",
			},
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{
			attr.GenAIInput:        {},
			attr.GenAIOutput:       {},
			attr.GenAIInstructions: {},
		})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIInputMessagesKey, "How do I check if a Python object is an instance of a class?")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIOutputMessagesKey, `[{"type":"message","role":"assistant","content":"Arrr!"}]`)
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAISystemInstructionsKey, "You are a coding assistant that talks like a pirate.")
	})

	t.Run("OpenAI span - optional GenAIMetadata enabled", func(t *testing.T) {
		span := makeOpenAISpan(&request.VendorOpenAI{
			ID:            "resp_abc123",
			OperationName: "response",
			ResponseModel: "gpt-5-mini-2025-08-07",
			Request:       request.OpenAIInput{Model: "gpt-5-mini"},
			Metadata:      []byte(`{"session_id":"sess_42","user":"alice"}`),
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{attr.GenAIMetadata: {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceStrAttr(t, spanAttrs, attribute.Key(attr.GenAIMetadata), `{"session_id":"sess_42","user":"alice"}`)
	})

	t.Run("OpenAI span - GenAIMetadata not emitted when metadata is empty", func(t *testing.T) {
		span := makeOpenAISpan(&request.VendorOpenAI{
			ID:            "resp_abc123",
			OperationName: "response",
			ResponseModel: "gpt-5-mini-2025-08-07",
			Request:       request.OpenAIInput{Model: "gpt-5-mini"},
			Metadata:      nil, // no metadata
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{attr.GenAIMetadata: {}})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceAttrNotExists(t, spanAttrs, attribute.Key(attr.GenAIMetadata))
	})

	t.Run("OpenAI span - GenAIMetadata not emitted without attr selector", func(t *testing.T) {
		span := makeOpenAISpan(&request.VendorOpenAI{
			ID:            "resp_abc123",
			OperationName: "response",
			ResponseModel: "gpt-5-mini-2025-08-07",
			Request:       request.OpenAIInput{Model: "gpt-5-mini"},
			Metadata:      []byte(`{"session_id":"sess_42"}`),
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{}) // GenAIMetadata NOT in optional set
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceAttrNotExists(t, spanAttrs, attribute.Key(attr.GenAIMetadata))
	})

	t.Run("OpenAI span - error response", func(t *testing.T) {
		span := makeOpenAISpan(&request.VendorOpenAI{
			OperationName: "response",
			Request:       request.OpenAIInput{Model: "gpt-5-mini"},
			Error: request.OpenAIError{
				Type:    "insufficient_quota",
				Message: "You exceeded your current quota, please check your plan and billing details.",
			},
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceStrAttr(t, spanAttrs, semconv.ErrorTypeKey, "insufficient_quota")
		ensureTraceStrAttr(t, spanAttrs, attribute.Key("error.message"), "You exceeded your current quota, please check your plan and billing details.")
	})

	t.Run("OpenAI span - chat completions (prompt/completion token fields)", func(t *testing.T) {
		span := makeOpenAISpan(&request.VendorOpenAI{
			ID:            "chatcmpl-DBTg5Ms2mJhaAhZ56Wq8QSf2djw3S",
			OperationName: "chat.completion",
			ResponseModel: "gpt-4o-mini-2024-07-18",
			Temperature:   1.0,
			Usage:         request.OpenAIUsage{PromptTokens: 396, CompletionTokens: 816},
			Choices:       []byte(`[{"index":0,"message":{"role":"assistant","content":"I now can give a great answer"},"finish_reason":"stop"}]`),
			Request: request.OpenAIInput{
				Model:       "gpt-4o-mini",
				Temperature: 1.0,
				Messages:    []byte(`[{"role":"system","content":"You are a helpful travel assistant."},{"role":"user","content":"Plan a 6-day luxury trip to London."}]`),
			},
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{
			attr.GenAIInput:  {},
			attr.GenAIOutput: {},
		})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIProviderNameKey, "openai")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIOperationNameKey, "chat.completion")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIResponseIDKey, "chatcmpl-DBTg5Ms2mJhaAhZ56Wq8QSf2djw3S")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIRequestModelKey, "gpt-4o-mini")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIResponseModelKey, "gpt-4o-mini-2024-07-18")
		// input/output messages come through the optional attrs
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIOutputMessagesKey, `[{"index":0,"message":{"role":"assistant","content":"I now can give a great answer"},"finish_reason":"stop"}]`)
	})

	t.Run("OpenAI span - temperature from request when response temperature is zero", func(t *testing.T) {
		span := makeOpenAISpan(&request.VendorOpenAI{
			OperationName: "response",
			ResponseModel: "gpt-5-mini-2025-08-07",
			Temperature:   0, // not set in response
			Request: request.OpenAIInput{
				Model:       "gpt-5-mini",
				Temperature: 0.7,
			},
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		v, ok := spanAttrs.Get(string(semconv.GenAIRequestTemperatureKey))
		require.True(t, ok, "gen_ai.request.temperature should be present")
		assert.InDelta(t, 0.7, v.Double(), 0.001)
	})

	t.Run("OpenAI span - nil OpenAI field keeps span with no GenAI attrs", func(t *testing.T) {
		span := request.Span{
			Type:    request.EventTypeHTTPClient,
			SubType: request.HTTPSubtypeOpenAI,
			Method:  "POST",
			Status:  200,
			GenAI:   &request.GenAI{OpenAI: nil}, // explicitly nil
		}

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{
			attr.GenAIInput:        {},
			attr.GenAIOutput:       {},
			attr.GenAIInstructions: {},
		})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIProviderNameKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIOperationNameKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIInputMessagesKey)
	})

	t.Run("Anthropic span", func(t *testing.T) {
		span := makeAnthropicSpan(&request.VendorAnthropic{
			Input: request.AnthropicRequest{
				Model: "claude-sonnet-4-6",
			},
			Output: request.AnthropicResponse{
				ID:    "msg_01QCj5VkxPS3NQUtrt5Npjcr",
				Type:  "message",
				Model: "claude-sonnet-4-6",
				Usage: request.AnthropicUsage{
					InputTokens:  15,
					OutputTokens: 35,
				},
			},
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIProviderNameKey, "anthropic")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIOperationNameKey, "message")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIResponseIDKey, "msg_01QCj5VkxPS3NQUtrt5Npjcr")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIRequestModelKey, "claude-sonnet-4-6")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIResponseModelKey, "claude-sonnet-4-6")
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIInputMessagesKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIOutputMessagesKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAISystemInstructionsKey)
	})

	t.Run("Anthropic span - optional attributes and error request id", func(t *testing.T) {
		span := makeAnthropicSpan(&request.VendorAnthropic{
			Input: request.AnthropicRequest{
				Model:    "claude-sonnet-4-6",
				Messages: []byte(`[{"role":"user","content":"Explain quantum computing in simple terms"}]`),
				System:   "Be concise.",
				Tools:    []byte(`[{"name":"calculator","description":"Performs arithmetic"}]`),
			},
			Output: request.AnthropicResponse{
				Model:     "claude-sonnet-4-6",
				Type:      "message",
				Content:   []byte(`[{"type":"text","text":"Quantum computing uses superposition."}]`),
				RequestID: "req_011CZLkWqu2dABS8vFB9G6Lz",
				Usage: request.AnthropicUsage{
					InputTokens:  17,
					OutputTokens: 37,
				},
				Error: &request.AnthropicError{
					Type:    "authentication_error",
					Message: "invalid x-api-key",
				},
			},
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{
			attr.GenAIInput:        {},
			attr.GenAIOutput:       {},
			attr.GenAIInstructions: {},
			attr.GenAIMetadata:     {},
		})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIProviderNameKey, "anthropic")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIResponseIDKey, "req_011CZLkWqu2dABS8vFB9G6Lz")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIInputMessagesKey, `[{"role":"user","content":"Explain quantum computing in simple terms"}]`)
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIOutputMessagesKey, `[{"type":"text","text":"Quantum computing uses superposition."}]`)
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAISystemInstructionsKey, "Be concise.")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIToolDefinitionsKey, `[{"name":"calculator","description":"Performs arithmetic"}]`)
		ensureTraceStrAttr(t, spanAttrs, semconv.ErrorTypeKey, "authentication_error")
		ensureTraceStrAttr(t, spanAttrs, attribute.Key("error.message"), "invalid x-api-key")
	})

	t.Run("Anthropic span - nil Anthropic means no GenAI attrs", func(t *testing.T) {
		span := request.Span{
			Type:    request.EventTypeHTTPClient,
			SubType: request.HTTPSubtypeAnthropic,
			Method:  "POST",
			Status:  200,
			GenAI:   &request.GenAI{Anthropic: nil},
		}

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{
			attr.GenAIInput:        {},
			attr.GenAIOutput:       {},
			attr.GenAIInstructions: {},
			attr.GenAIMetadata:     {},
		})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIProviderNameKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIOperationNameKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIInputMessagesKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIOutputMessagesKey)
	})

	makeGeminiSpan := func(ai *request.VendorGemini) request.Span {
		return request.Span{
			Type:    request.EventTypeHTTPClient,
			SubType: request.HTTPSubtypeGemini,
			Method:  "POST",
			Path:    "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
			Status:  200,
			GenAI:   &request.GenAI{Gemini: ai},
		}
	}

	t.Run("Gemini span", func(t *testing.T) {
		span := makeGeminiSpan(&request.VendorGemini{
			Model: "gemini-2.0-flash",
			Output: request.GeminiResponse{
				ResponseID:   "resp_abc123def456",
				ModelVersion: "gemini-2.0-flash",
				UsageMetadata: request.GeminiUsage{
					PromptTokenCount:     12,
					CandidatesTokenCount: 45,
				},
				Candidates: []request.GeminiCandidate{
					{FinishReason: "STOP"},
				},
			},
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIProviderNameKey, "gcp.gemini")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIOperationNameKey, "generate_content")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIResponseIDKey, "resp_abc123def456")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIRequestModelKey, "gemini-2.0-flash")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIResponseModelKey, "gemini-2.0-flash")
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIInputMessagesKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIOutputMessagesKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAISystemInstructionsKey)
	})

	t.Run("Gemini span - dynamic operation name", func(t *testing.T) {
		span := makeGeminiSpan(&request.VendorGemini{
			Model:     "text-embedding-004",
			Operation: "embed_content",
			Output: request.GeminiResponse{
				ModelVersion: "text-embedding-004",
				UsageMetadata: request.GeminiUsage{
					PromptTokenCount:     5,
					CandidatesTokenCount: 0,
				},
			},
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIOperationNameKey, "embed_content")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIRequestModelKey, "text-embedding-004")
	})

	t.Run("Gemini span - optional attributes and error", func(t *testing.T) {
		span := makeGeminiSpan(&request.VendorGemini{
			Model: "gemini-2.0-flash",
			Input: request.GeminiRequest{
				Contents:          []byte(`[{"parts":[{"text":"Explain eBPF"}],"role":"user"}]`),
				SystemInstruction: &request.GeminiContent{Parts: []byte(`[{"text":"Be concise."}]`), Role: "system"},
				Tools:             []byte(`[{"functionDeclarations":[{"name":"get_weather"}]}]`),
				GenerationConfig: &request.GeminiGenCfg{
					Temperature:     0.7,
					TopP:            0.9,
					TopK:            40,
					MaxOutputTokens: 256,
				},
			},
			Output: request.GeminiResponse{
				ResponseID:   "resp_sys789",
				ModelVersion: "gemini-2.0-flash",
				Candidates: []request.GeminiCandidate{
					{
						Content:      &request.GeminiContent{Parts: []byte(`[{"text":"eBPF runs sandboxed programs in the kernel."}]`), Role: "model"},
						FinishReason: "STOP",
					},
				},
				UsageMetadata: request.GeminiUsage{
					PromptTokenCount:     28,
					CandidatesTokenCount: 8,
				},
				Error: &request.GeminiError{
					Code:    404,
					Message: "model not found",
					Status:  "NOT_FOUND",
				},
			},
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{
			attr.GenAIInput:        {},
			attr.GenAIOutput:       {},
			attr.GenAIInstructions: {},
			attr.GenAIMetadata:     {},
		})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIProviderNameKey, "gcp.gemini")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIOperationNameKey, "generate_content")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIResponseIDKey, "resp_sys789")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIInputMessagesKey, `[{"parts":[{"text":"Explain eBPF"}],"role":"user"}]`)
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIOutputMessagesKey, `[{"text":"eBPF runs sandboxed programs in the kernel."}]`)
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAISystemInstructionsKey, `[{"text":"Be concise."}]`)
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIToolDefinitionsKey, `[{"functionDeclarations":[{"name":"get_weather"}]}]`)
		ensureTraceStrAttr(t, spanAttrs, semconv.ErrorTypeKey, "NOT_FOUND")
		ensureTraceStrAttr(t, spanAttrs, attribute.Key("error.message"), "model not found")
	})

	t.Run("Gemini span - nil Gemini means no GenAI attrs", func(t *testing.T) {
		span := request.Span{
			Type:    request.EventTypeHTTPClient,
			SubType: request.HTTPSubtypeGemini,
			Method:  "POST",
			Status:  200,
			GenAI:   &request.GenAI{Gemini: nil},
		}

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{
			attr.GenAIInput:        {},
			attr.GenAIOutput:       {},
			attr.GenAIInstructions: {},
			attr.GenAIMetadata:     {},
		})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIProviderNameKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIOperationNameKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIInputMessagesKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIOutputMessagesKey)
	})

	makeQwenSpan := func(ai *request.VendorOpenAI) request.Span {
		return request.Span{
			Type:    request.EventTypeHTTPClient,
			SubType: request.HTTPSubtypeQwen,
			Method:  "POST",
			Path:    "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
			Status:  200,
			GenAI:   &request.GenAI{Qwen: ai},
		}
	}

	t.Run("Qwen span", func(t *testing.T) {
		span := makeQwenSpan(&request.VendorOpenAI{
			OperationName: "chat.completion",
			ID:            "chatcmpl-qwen123",
			Request: request.OpenAIInput{
				Model: "qwen-plus",
			},
			ResponseModel: "qwen-plus",
			Usage: request.OpenAIUsage{
				PromptTokens:     12,
				CompletionTokens: 8,
			},
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIProviderNameKey, "qwen")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIOperationNameKey, "chat.completion")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIResponseIDKey, "chatcmpl-qwen123")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIRequestModelKey, "qwen-plus")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIResponseModelKey, "qwen-plus")
	})

	t.Run("Qwen span - optional attributes", func(t *testing.T) {
		span := makeQwenSpan(&request.VendorOpenAI{
			OperationName: "generation",
			ID:            "req-qwen123",
			Request: request.OpenAIInput{
				Model:        "qwen-turbo",
				Prompt:       "Explain eBPF",
				Instructions: "Be concise",
			},
			ResponseModel: "qwen-turbo",
			Output:        []byte(`{"text":"eBPF runs in the kernel."}`),
			Usage: request.OpenAIUsage{
				InputTokens:  7,
				OutputTokens: 6,
			},
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{
			attr.GenAIInput:        {},
			attr.GenAIOutput:       {},
			attr.GenAIInstructions: {},
		})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIProviderNameKey, "qwen")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIInputMessagesKey, "Explain eBPF")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIOutputMessagesKey, `{"text":"eBPF runs in the kernel."}`)
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAISystemInstructionsKey, "Be concise")
	})

	t.Run("Qwen span - nil Qwen means no GenAI attrs", func(t *testing.T) {
		span := request.Span{
			Type:    request.EventTypeHTTPClient,
			SubType: request.HTTPSubtypeQwen,
			Method:  "POST",
			Status:  200,
			GenAI:   &request.GenAI{Qwen: nil},
		}

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{
			attr.GenAIInput:        {},
			attr.GenAIOutput:       {},
			attr.GenAIInstructions: {},
			attr.GenAIMetadata:     {},
		})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIProviderNameKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIOperationNameKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIInputMessagesKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIOutputMessagesKey)
	})

	makeBedrockSpan := func(ai *request.VendorBedrock) request.Span {
		return request.Span{
			Type:    request.EventTypeHTTPClient,
			SubType: request.HTTPSubtypeAWSBedrock,
			Method:  "POST",
			Path:    "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-5-sonnet-20241022-v1:0/invoke",
			Status:  200,
			GenAI:   &request.GenAI{Bedrock: ai},
		}
	}

	t.Run("Bedrock span", func(t *testing.T) {
		span := makeBedrockSpan(&request.VendorBedrock{
			Model: "anthropic.claude-3-5-sonnet-20241022-v1:0",
			Output: request.BedrockResponse{
				InputTokens:  25,
				OutputTokens: 18,
				StopReason:   "end_turn",
			},
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIProviderNameKey, "aws.bedrock")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIOperationNameKey, "invoke_model")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIRequestModelKey, "anthropic.claude-3-5-sonnet-20241022-v1:0")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIResponseModelKey, "anthropic.claude-3-5-sonnet-20241022-v1:0")
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIInputMessagesKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIOutputMessagesKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAISystemInstructionsKey)
	})

	t.Run("Bedrock span - optional attributes and error", func(t *testing.T) {
		span := makeBedrockSpan(&request.VendorBedrock{
			Model: "anthropic.claude-3-5-sonnet-20241022-v1:0",
			Input: request.BedrockRequest{
				Messages:    []byte(`[{"role":"user","content":[{"type":"text","text":"Explain eBPF"}]}]`),
				System:      "Be concise.",
				Tools:       []byte(`[{"name":"get_weather","description":"Get weather"}]`),
				MaxTokens:   1024,
				Temperature: 0.7,
				TopP:        0.9,
			},
			Output: request.BedrockResponse{
				Content:      []byte(`[{"type":"text","text":"eBPF runs sandboxed programs in the kernel."}]`),
				StopReason:   "end_turn",
				InputTokens:  25,
				OutputTokens: 18,
				ErrorType:    "ValidationException",
				ErrorMessage: "The provided model identifier is invalid.",
			},
		})

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{
			attr.GenAIInput:        {},
			attr.GenAIOutput:       {},
			attr.GenAIInstructions: {},
			attr.GenAIMetadata:     {},
		})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIProviderNameKey, "aws.bedrock")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIOperationNameKey, "invoke_model")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIInputMessagesKey, `[{"role":"user","content":[{"type":"text","text":"Explain eBPF"}]}]`)
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIOutputMessagesKey, `[{"type":"text","text":"eBPF runs sandboxed programs in the kernel."}]`)
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAISystemInstructionsKey, "Be concise.")
		ensureTraceStrAttr(t, spanAttrs, semconv.GenAIToolDefinitionsKey, `[{"name":"get_weather","description":"Get weather"}]`)
		ensureTraceStrAttr(t, spanAttrs, semconv.ErrorTypeKey, "ValidationException")
		ensureTraceStrAttr(t, spanAttrs, attribute.Key("error.message"), "The provided model identifier is invalid.")
	})

	t.Run("Bedrock span - nil Bedrock means no GenAI attrs", func(t *testing.T) {
		span := request.Span{
			Type:    request.EventTypeHTTPClient,
			SubType: request.HTTPSubtypeAWSBedrock,
			Method:  "POST",
			Status:  200,
			GenAI:   &request.GenAI{Bedrock: nil},
		}

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{
			attr.GenAIInput:        {},
			attr.GenAIOutput:       {},
			attr.GenAIInstructions: {},
			attr.GenAIMetadata:     {},
		})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spanAttrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIProviderNameKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIOperationNameKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIInputMessagesKey)
		ensureTraceAttrNotExists(t, spanAttrs, semconv.GenAIOutputMessagesKey)
	})

	t.Run("test HTTP server span with extracted headers", func(t *testing.T) {
		span := request.Span{
			Type:   request.EventTypeHTTP,
			Method: "GET",
			Path:   "/api/v1/users",
			Route:  "/api/v1/users",
			Status: 200,
			RequestHeaders: map[string][]string{
				"Content-Type": {"application/json"},
				"X-Request-Id": {"abc-123"},
			},
			ResponseHeaders: map[string][]string{
				"X-Response-Id": {"resp-456"},
			},
		}

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
		attrs := spans.At(0).Attributes()

		ensureTraceStrSliceAttr(t, attrs, "http.request.header.content-type", []string{"application/json"})
		ensureTraceStrSliceAttr(t, attrs, "http.request.header.x-request-id", []string{"abc-123"})
		ensureTraceStrSliceAttr(t, attrs, "http.response.header.x-response-id", []string{"resp-456"})
		ensureTraceAttrNotExists(t, attrs, "http.request.header.authorization")
	})
	t.Run("test HTTP client span with extracted headers", func(t *testing.T) {
		span := request.Span{
			Type:   request.EventTypeHTTPClient,
			Method: "POST",
			Path:   "/external/api",
			Status: 201,
			RequestHeaders: map[string][]string{
				"Authorization": {"***"},
			},
			ResponseHeaders: map[string][]string{
				"X-Ratelimit-Remaining": {"42"},
			},
		}

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		assert.Equal(t, 1, traces.ResourceSpans().Len())
		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
		attrs := spans.At(0).Attributes()

		ensureTraceStrSliceAttr(t, attrs, "http.request.header.authorization", []string{"***"})
		ensureTraceStrSliceAttr(t, attrs, "http.response.header.x-ratelimit-remaining", []string{"42"})
	})
	t.Run("test HTTP client url.full prefers FullPath with original host", func(t *testing.T) {
		span := request.Span{
			Type:      request.EventTypeHTTPClient,
			Method:    "GET",
			Path:      "/external/api",
			FullPath:  "/external/api?foo=bar",
			Status:    200,
			Host:      "api.example.com",
			HostPort:  443,
			Statement: "https;api.example.com",
		}

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		attrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceStrAttr(t, attrs, semconv.URLFullKey, "https://api.example.com/external/api?foo=bar")
	})
	t.Run("test HTTP client url.full falls back to Path when FullPath is empty", func(t *testing.T) {
		span := request.Span{
			Type:      request.EventTypeHTTPClient,
			Method:    "GET",
			Path:      "/external/api",
			Status:    200,
			Host:      "api.example.com",
			HostPort:  443,
			Statement: "https;api.example.com",
		}

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		attrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceStrAttr(t, attrs, semconv.URLFullKey, "https://api.example.com/external/api")
	})
	t.Run("test HTTP client url.full uses FullPath as-is without original host", func(t *testing.T) {
		span := request.Span{
			Type:     request.EventTypeHTTPClient,
			Method:   "GET",
			Path:     "/external/api",
			FullPath: "https://upstream.example.com/external/api?foo=bar",
			Status:   200,
		}

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		attrs := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes()
		ensureTraceStrAttr(t, attrs, semconv.URLFullKey, "https://upstream.example.com/external/api?foo=bar")
	})
	t.Run("test JSON-RPC server span with error", func(t *testing.T) {
		span := request.Span{
			Type:    request.EventTypeHTTP,
			Method:  "POST",
			Path:    "/rpc",
			Route:   "/rpc",
			Status:  200,
			SubType: request.HTTPSubtypeJSONRPC,
			JSONRPC: &request.JSONRPC{
				Method:       "subtract",
				Version:      "2.0",
				RequestID:    "1",
				ErrorCode:    -32601,
				ErrorMessage: "Method not found",
			},
		}
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
		topSpan := spans.At(spans.Len() - 1)
		attrs := topSpan.Attributes()
		status := topSpan.Status()

		assert.Equal(t, "subtract", topSpan.Name())
		assert.Equal(t, ptrace.StatusCodeError, status.Code())
		assert.Equal(t, "Method not found", status.Message())

		ensureTraceStrAttr(t, attrs, "rpc.system", "jsonrpc")
		ensureTraceStrAttr(t, attrs, "rpc.method", "subtract")
		ensureTraceStrAttr(t, attrs, "jsonrpc.protocol.version", "2.0")
		ensureTraceStrAttr(t, attrs, "jsonrpc.request.id", "1")
		ensureTraceStrAttr(t, attrs, "rpc.response.status_code", "-32601")
	})
	t.Run("test JSON-RPC server span without error", func(t *testing.T) {
		span := request.Span{
			Type:    request.EventTypeHTTP,
			Method:  "POST",
			Path:    "/rpc",
			Route:   "/rpc",
			Status:  200,
			SubType: request.HTTPSubtypeJSONRPC,
			JSONRPC: &request.JSONRPC{
				Method:    "subtract",
				Version:   "2.0",
				RequestID: "1",
			},
		}
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
		topSpan := spans.At(spans.Len() - 1)
		attrs := topSpan.Attributes()
		status := topSpan.Status()

		assert.Equal(t, "subtract", topSpan.Name())
		assert.Equal(t, ptrace.StatusCodeUnset, status.Code())
		assert.Empty(t, status.Message())

		ensureTraceStrAttr(t, attrs, "rpc.system", "jsonrpc")
		ensureTraceStrAttr(t, attrs, "rpc.method", "subtract")
		ensureTraceStrAttr(t, attrs, "jsonrpc.protocol.version", "2.0")
		ensureTraceStrAttr(t, attrs, "jsonrpc.request.id", "1")
		ensureTraceAttrNotExists(t, attrs, "rpc.response.status_code")
	})
	t.Run("test JSON-RPC client span with error", func(t *testing.T) {
		span := request.Span{
			Type:    request.EventTypeHTTPClient,
			Method:  "POST",
			Path:    "/rpc",
			Status:  200,
			SubType: request.HTTPSubtypeJSONRPC,
			JSONRPC: &request.JSONRPC{
				Method:       "getUser",
				Version:      "2.0",
				RequestID:    "42",
				ErrorCode:    -32600,
				ErrorMessage: "Invalid Request",
			},
		}
		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
		assert.Equal(t, 1, spans.Len())
		topSpan := spans.At(0)
		attrs := topSpan.Attributes()
		status := topSpan.Status()

		assert.Equal(t, "getUser", topSpan.Name())
		assert.Equal(t, ptrace.StatusCodeError, status.Code())
		assert.Equal(t, "Invalid Request", status.Message())

		ensureTraceStrAttr(t, attrs, "rpc.system", "jsonrpc")
		ensureTraceStrAttr(t, attrs, "rpc.method", "getUser")
		ensureTraceStrAttr(t, attrs, "jsonrpc.protocol.version", "2.0")
		ensureTraceStrAttr(t, attrs, "jsonrpc.request.id", "42")
		ensureTraceStrAttr(t, attrs, "rpc.response.status_code", "-32600")
	})
	t.Run("test HTTP span without headers has no header attributes", func(t *testing.T) {
		span := request.Span{
			Type:   request.EventTypeHTTP,
			Method: "GET",
			Path:   "/health",
			Status: 200,
		}

		tAttrs := tracesgen.TraceAttributesSelector(&span, map[attr.Name]struct{}{})
		traces := tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(&span, tAttrs), reporterName)

		spans := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
		attrs := spans.At(0).Attributes()

		// No header attributes should be present
		ensureTraceAttrNotExists(t, attrs, "http.request.header.content-type")
		ensureTraceAttrNotExists(t, attrs, "http.response.header.content-type")
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

	receiver := makeTracesTestReceiver([]instrumentations.Instrumentation{instrumentations.InstrumentationHTTP})

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
		receiver := makeTracesTestReceiverWithSpanMetrics(true, []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP})

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
		receiver := makeTracesTestReceiver([]instrumentations.Instrumentation{instrumentations.InstrumentationHTTP})

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
			instr:    []instrumentations.Instrumentation{instrumentations.InstrumentationALL},
			expected: []string{"GET /foo", "PUT /bar", "/grpcFoo", "/grpcGoo", "SELECT credentials", "SET", "GET", "publish important-topic", "process important-topic", "publish sensors/temperature", "process sensors/#", "publish updates.orders", "process updates.orders", "insert mycollection", "GET couchbase-collection", "GET", "DELETE"},
		},
		{
			name:     "http only",
			instr:    []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP},
			expected: []string{"GET /foo", "PUT /bar"},
		},
		{
			name:     "grpc only",
			instr:    []instrumentations.Instrumentation{instrumentations.InstrumentationGRPC},
			expected: []string{"/grpcFoo", "/grpcGoo"},
		},
		{
			name:     "redis only",
			instr:    []instrumentations.Instrumentation{instrumentations.InstrumentationRedis},
			expected: []string{"SET", "GET"},
		},
		{
			name:     "sql only",
			instr:    []instrumentations.Instrumentation{instrumentations.InstrumentationSQL},
			expected: []string{"SELECT credentials"},
		},
		{
			name:     "kafka only",
			instr:    []instrumentations.Instrumentation{instrumentations.InstrumentationKafka},
			expected: []string{"publish important-topic", "process important-topic"},
		},
		{
			name:     "mqtt only",
			instr:    []instrumentations.Instrumentation{instrumentations.InstrumentationMQTT},
			expected: []string{"publish sensors/temperature", "process sensors/#"},
		},
		{
			name:     "nats only",
			instr:    []instrumentations.Instrumentation{instrumentations.InstrumentationNATS},
			expected: []string{"publish updates.orders", "process updates.orders"},
		},
		{
			name:     "none",
			instr:    nil,
			expected: []string{},
		},
		{
			name:     "sql and redis",
			instr:    []instrumentations.Instrumentation{instrumentations.InstrumentationSQL, instrumentations.InstrumentationRedis},
			expected: []string{"SELECT credentials", "SET", "GET"},
		},
		{
			name:     "kafka and grpc",
			instr:    []instrumentations.Instrumentation{instrumentations.InstrumentationGRPC, instrumentations.InstrumentationKafka},
			expected: []string{"/grpcFoo", "/grpcGoo", "publish important-topic", "process important-topic"},
		},
		{
			name:     "mongo",
			instr:    []instrumentations.Instrumentation{instrumentations.InstrumentationMongo},
			expected: []string{"insert mycollection"},
		},
		{
			name:     "couchbase",
			instr:    []instrumentations.Instrumentation{instrumentations.InstrumentationCouchbase},
			expected: []string{"GET couchbase-collection"},
		},
		{
			name:     "memcached",
			instr:    []instrumentations.Instrumentation{instrumentations.InstrumentationMemcached},
			expected: []string{"GET", "DELETE"},
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
		{Type: request.EventTypeMQTTClient, Method: "publish", Path: "sensors/temperature", Statement: "mqtt-client"},
		{Type: request.EventTypeMQTTServer, Method: "process", Path: "sensors/#", Statement: "mqtt-server"},
		{Type: request.EventTypeNATSClient, Method: "publish", Path: "updates.orders"},
		{Type: request.EventTypeNATSServer, Method: "process", Path: "updates.orders"},
		{Type: request.EventTypeMongoClient, Method: "insert", Path: "mycollection", DBNamespace: "mydatabase"},
		{Type: request.EventTypeCouchbaseClient, Method: "GET", Path: "couchbase-collection", DBNamespace: "mybucket.myscope"},
		{Type: request.EventTypeMemcachedClient, Method: "GET", Path: "session-key"},
		{Type: request.EventTypeMemcachedServer, Method: "DELETE", Path: "session-key"},
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

	host123 := &meta.NodeMeta{HostID: "123"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr1 := tracesgen.TraceAppResourceAttrs(cache, host123, &tt.span.Service)
			attr2 := tracesgen.TraceAppResourceAttrs(cache, host123, &tt.span.Service)
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

	tr := makeTracesTestReceiver([]instrumentations.Instrumentation{instrumentations.InstrumentationALL})

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

func TestHTTPServerURLSchemeAttribute(t *testing.T) {
	tests := []struct {
		name     string
		span     request.Span
		expected string
	}{
		{
			name: "HTTPS server span",
			span: request.Span{
				Type:           request.EventTypeHTTP,
				Method:         "GET",
				Path:           "/hello",
				Status:         200,
				Peer:           "1.1.1.1",
				Host:           "srv",
				HostPort:       443,
				Statement:      "https;api.example.com",
				Service:        svc.Attrs{UID: svc.UID{Namespace: "default"}},
				PeerName:       "client",
				HostName:       "srv",
				OtherNamespace: "default",
			},
			expected: "https",
		},
		{
			name: "HTTP server span",
			span: request.Span{
				Type:           request.EventTypeHTTP,
				Method:         "POST",
				Path:           "/submit",
				Status:         201,
				Peer:           "2.2.2.2",
				Host:           "srv",
				HostPort:       80,
				Statement:      "http;api.example.com",
				Service:        svc.Attrs{UID: svc.UID{Namespace: "default"}},
				PeerName:       "client",
				HostName:       "srv",
				OtherNamespace: "default",
			},
			expected: "http",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := tracesgen.TraceAttributesSelector(&tt.span, nil)
			var (
				found bool
				value string
			)
			for _, attr := range attrs {
				if attr.Key == semconv.URLSchemeKey {
					found = true
					value = attr.Value.AsString()
					break
				}
			}

			assert.True(t, found, "url.scheme attribute missing")
			assert.Equal(t, tt.expected, value)
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
			name:   "Server in different namespace NATS",
			span:   request.Span{Type: request.EventTypeNATSClient, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
			client: "",
			server: "server.far",
		},
		{
			name:   "Client in different namespace NATS",
			span:   request.Span{Type: request.EventTypeNATSServer, PeerName: "client", HostName: "server", OtherNamespace: "far", Service: svc.Attrs{UID: svc.UID{Namespace: "same"}}},
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

	receiver := makeTracesTestReceiver([]instrumentations.Instrumentation{instrumentations.InstrumentationHTTP})

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

func TestCreateZapLoggerDevLevels(t *testing.T) {
	tests := []struct {
		name    string
		level   string
		enabled map[zapcore.Level]bool
	}{
		{
			name:  "panic downgraded to error",
			level: "panic",
			enabled: map[zapcore.Level]bool{
				zapcore.DebugLevel: false,
				zapcore.InfoLevel:  false,
				zapcore.WarnLevel:  false,
				zapcore.ErrorLevel: true,
				zapcore.PanicLevel: true,
			},
		},
		{
			name:  "unsupported level - using default",
			level: "wrongLevel",
			enabled: map[zapcore.Level]bool{
				zapcore.DebugLevel: false,
				zapcore.InfoLevel:  false,
				zapcore.WarnLevel:  false,
				zapcore.ErrorLevel: false,
				zapcore.PanicLevel: false,
			},
		},
		{
			name:  "warn level",
			level: "warn",
			enabled: map[zapcore.Level]bool{
				zapcore.DebugLevel: false,
				zapcore.InfoLevel:  false,
				zapcore.WarnLevel:  true,
				zapcore.ErrorLevel: true,
				zapcore.PanicLevel: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := createZapLoggerDev(tt.level)
			require.NotNil(t, logger)
			for level, expected := range tt.enabled {
				assert.Equal(t, expected, logger.Core().Enabled(level))
			}
		})
	}
}

func makeSQLRequestSpan(sql string) request.Span {
	method, path := sqlprune.SQLParseOperationAndTable(sql)
	return request.Span{Type: request.EventTypeSQLClient, Method: method, Path: path, Statement: sql}
}

func makeSQLServerRequestSpan(sql string) request.Span {
	method, path := sqlprune.SQLParseOperationAndTable(sql)
	return request.Span{Type: request.EventTypeSQLServer, Method: method, Path: path, Statement: sql}
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

func ensureTraceStrSliceAttr(t *testing.T, attrs pcommon.Map, key attribute.Key, vals []string) {
	t.Helper()
	v, ok := attrs.Get(string(key))
	require.True(t, ok, "expected attribute %s", key)
	slice := v.Slice()
	got := make([]string, slice.Len())
	for i := 0; i < slice.Len(); i++ {
		got[i] = slice.At(i).Str()
	}
	assert.Equal(t, vals, got)
}

func ensureTraceIntAttr(t *testing.T, attrs pcommon.Map, key attribute.Key, val int64) {
	t.Helper()
	v, ok := attrs.Get(string(key))
	require.True(t, ok, "expected attribute %s", key)
	assert.Equal(t, val, v.Int())
}

func ensureTraceAttrNotExists(t *testing.T, attrs pcommon.Map, key attribute.Key) {
	_, ok := attrs.Get(string(key))
	assert.False(t, ok)
}

func makeTracesTestReceiver(instr []instrumentations.Instrumentation) *tracesOTELReceiver {
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

func makeTracesTestReceiverWithSpanMetrics(enabled bool, instr []instrumentations.Instrumentation) *tracesOTELReceiver {
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

		res = append(res, tracesgen.GenerateTracesWithAttributes(cache, &span.Service, []attribute.KeyValue{}, hostID, groupFromSpanAndAttributes(span, tAttrs), reporterName))
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
