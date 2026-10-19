// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

// consumeTraces invalidates the underlying proto structures, as a real
// exporter may do after taking ownership of the trace data.
func consumeTraces(_ context.Context, td ptrace.Traces) error {
	type traces struct {
		orig  unsafe.Pointer
		state unsafe.Pointer
	}
	type request struct {
		resourceSpans []unsafe.Pointer
	}
	req := (*request)((*traces)(unsafe.Pointer(&td)).orig)
	req.resourceSpans[0] = nil
	return nil
}

func TestTracesExporterCountsBeforeConsumption(t *testing.T) {
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	ss.Spans().AppendEmpty()

	reporter := &countingTracesReporter{}
	ie := &obiTracesExporter{send: consumeTraces, reporter: reporter}
	require.NotPanics(t, func() { require.NoError(t, ie.ConsumeTraces(t.Context(), td)) })
	require.EqualValues(t, 1, reporter.exports.Load())
}
