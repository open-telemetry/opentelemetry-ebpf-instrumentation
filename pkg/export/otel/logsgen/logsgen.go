// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package logsgen // import "go.opentelemetry.io/obi/pkg/export/otel/logsgen"

import (
	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
)

// EventNameQueueProcessing is the fixed EventName used on every log record
// this package emits.
const EventNameQueueProcessing = "request.queue_processing"

// GenerateLogs builds a plog.Logs payload containing, for each span in spans
// that had an observable queue gap (RequestStart < Start), a single combined
// log record describing queue and processing duration in seconds,
// correlated to the parent trace span via trace_id/span_id.
//
// Spans without an observable gap produce no log record — the resulting
// plog.Logs may have zero LogRecords; callers should check for that before
// sending an otherwise-empty batch.
func GenerateLogs(
	cache *expirable2.LRU[svc.UID, []attribute.KeyValue],
	svcAttrs *svc.Attrs,
	envResourceAttrs []attribute.KeyValue,
	nodeMeta *meta.NodeMeta,
	spans []tracesgen.TraceSpanAndAttributes,
	reporterName string,
	attrSelector attributes.Selection,
	extraResAttrs ...attribute.KeyValue,
) plog.Logs {
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()

	resourceAttrs := tracesgen.TraceAppResourceAttrs(cache, nodeMeta, svcAttrs)
	resourceAttrs = append(resourceAttrs, envResourceAttrs...)
	resourceAttrs = otelcfg.FilterResourceAttrs(resourceAttrs, attrSelector)
	extraResAttrs = otelcfg.FilterResourceAttrs(extraResAttrs, attrSelector)
	resourceAttrs = append(resourceAttrs, extraResAttrs...)
	resourceAttrsMap := tracesgen.AttrsToMap(resourceAttrs)
	resourceAttrsMap.PutStr(string(semconv.OTelScopeNameKey), reporterName)
	resourceAttrsMap.MoveTo(rl.Resource().Attributes())

	sl := rl.ScopeLogs().AppendEmpty()

	for _, spanWithAttributes := range spans {
		span := spanWithAttributes.Span
		t := span.Timings()
		start := tracesgen.SpanStartTime(t)
		if !t.Start.After(start) || !span.SpanID.IsValid() {
			continue // no observable queue gap, or no valid SpanID to correlate against
		}

		lr := sl.LogRecords().AppendEmpty()
		lr.SetTimestamp(pcommon.NewTimestampFromTime(t.End))
		lr.SetTraceID(pcommon.TraceID(span.TraceID))
		lr.SetSpanID(pcommon.SpanID(span.SpanID))
		lr.SetEventName(EventNameQueueProcessing)
		lr.SetSeverityNumber(plog.SeverityNumberInfo)
		lr.SetSeverityText("INFO")

		attrs := lr.Attributes()
		attrs.PutDouble("queue.duration", t.Start.Sub(t.RequestStart).Seconds())
		attrs.PutDouble("processing.duration", t.End.Sub(t.Start).Seconds())
	}

	return logs
}
