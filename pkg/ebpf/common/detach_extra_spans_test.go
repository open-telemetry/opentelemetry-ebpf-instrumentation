// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/otel/idgen"
)

func batchedSpans(parent trace.SpanID) []request.Span {
	traceID := idgen.RandomTraceID()
	spanID := idgen.RandomSpanID()

	spans := make([]request.Span, 3)
	for i := range spans {
		spans[i] = request.Span{TraceID: traceID, SpanID: spanID, ParentSpanID: parent}
	}

	return spans
}

func TestDetachExtraSpansUnparentedBatchGetsOneTraceEach(t *testing.T) {
	spans := batchedSpans(trace.SpanID{})
	batchTraceID := spans[0].TraceID

	detachExtraSpans(spans)

	seen := map[trace.TraceID]struct{}{batchTraceID: {}}
	for i := range spans {
		require.NotContains(t, seen, spans[i].TraceID,
			"a parentless batched span must not share a trace with the rest of the batch")
		seen[spans[i].TraceID] = struct{}{}

		assert.True(t, spans[i].TraceID.IsValid())
		assert.False(t, spans[i].SpanID.IsValid())
		assert.False(t, spans[i].ParentSpanID.IsValid())
	}
}

func TestDetachExtraSpansParentedBatchStaysInOneTrace(t *testing.T) {
	parent := idgen.RandomSpanID()
	spans := batchedSpans(parent)
	batchTraceID := spans[0].TraceID

	detachExtraSpans(spans)

	for i := range spans {
		assert.Equal(t, batchTraceID, spans[i].TraceID,
			"a batch with a parent request stays in the parent's trace")
		assert.Equal(t, parent, spans[i].ParentSpanID)
		assert.False(t, spans[i].SpanID.IsValid())
	}
}
