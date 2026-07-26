// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package logsgen_test

import (
	"testing"
	"time"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
	"go.opentelemetry.io/obi/pkg/export/otel/logsgen"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
)

var (
	cache  = expirable2.NewLRU[svc.UID, []attribute.KeyValue](1024, nil, 5*time.Minute)
	hostID = &meta.NodeMeta{HostID: "host-id"}
)

func group(span *request.Span) []tracesgen.TraceSpanAndAttributes {
	return []tracesgen.TraceSpanAndAttributes{{Span: span, Attributes: nil}}
}

func TestGenerateLogs_ObservableGap(t *testing.T) {
	start := time.Now()
	traceID, _ := trace.TraceIDFromHex("eae56fbbec9505c102e8aabfc6b5c481")
	spanID, _ := trace.SpanIDFromHex("89cbc1f60aab3b01")
	span := &request.Span{
		Type:         request.EventTypeHTTP,
		RequestStart: start.UnixNano(),
		Start:        start.Add(time.Second).UnixNano(),
		End:          start.Add(3 * time.Second).UnixNano(),
		TraceID:      traceID,
		SpanID:       spanID,
	}

	logs := logsgen.GenerateLogs(cache, &span.Service, nil, hostID, group(span), "go.opentelemetry.io/obi")

	require.Equal(t, 1, logs.ResourceLogs().Len())
	require.Equal(t, 1, logs.ResourceLogs().At(0).ScopeLogs().Len())
	records := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	require.Equal(t, 1, records.Len())

	lr := records.At(0)
	assert.Equal(t, "request.queue_processing", lr.EventName())
	assert.Equal(t, traceID.String(), lr.TraceID().String())
	assert.Equal(t, spanID.String(), lr.SpanID().String())

	queueDuration, ok := lr.Attributes().Get("queue.duration")
	require.True(t, ok)
	assert.InDelta(t, 1.0, queueDuration.Double(), 0.01)

	processingDuration, ok := lr.Attributes().Get("processing.duration")
	require.True(t, ok)
	assert.InDelta(t, 2.0, processingDuration.Double(), 0.01)
}

func TestGenerateLogs_NoObservableGap(t *testing.T) {
	start := time.Now()
	traceID, _ := trace.TraceIDFromHex("eae56fbbec9505c102e8aabfc6b5c481")
	span := &request.Span{
		Type:         request.EventTypeHTTP,
		RequestStart: start.UnixNano(),
		Start:        start.UnixNano(), // no gap
		End:          start.Add(time.Second).UnixNano(),
		TraceID:      traceID,
	}

	logs := logsgen.GenerateLogs(cache, &span.Service, nil, hostID, group(span), "go.opentelemetry.io/obi")

	records := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	assert.Equal(t, 0, records.Len(), "no log record should be emitted when there's no observable queue gap")
}

func TestGenerateLogs_ObservableGapButInvalidSpanID(t *testing.T) {
	// span.SpanID is invalid (e.g. eBPF failed to assign one). tracesgen.go's
	// suppressed-span path would generate a fresh random SpanID for the
	// parent in this case, so reusing span.SpanID verbatim here would
	// correlate the log record with the wrong (mismatched) span_id.
	// Instead, no log record should be emitted at all.
	start := time.Now()
	traceID, _ := trace.TraceIDFromHex("eae56fbbec9505c102e8aabfc6b5c481")
	span := &request.Span{
		Type:         request.EventTypeHTTP,
		RequestStart: start.UnixNano(),
		Start:        start.Add(time.Second).UnixNano(), // observable gap
		End:          start.Add(3 * time.Second).UnixNano(),
		TraceID:      traceID,
		// SpanID intentionally left as the zero value (invalid)
	}
	require.False(t, span.SpanID.IsValid())

	logs := logsgen.GenerateLogs(cache, &span.Service, nil, hostID, group(span), "go.opentelemetry.io/obi")

	records := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	assert.Equal(t, 0, records.Len(), "no log record should be emitted when the span has no valid SpanID to correlate against")
}
