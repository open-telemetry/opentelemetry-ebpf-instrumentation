// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

// consumingTracesExporter simulates a real exporter that takes ownership of
// the trace data and invalidates the underlying proto structures (as happens
// with proto pooling / data recycling in production pipelines).
type consumingTracesExporter struct{}

func (consumingTracesExporter) Start(context.Context, component.Host) error { return nil }

func (consumingTracesExporter) Shutdown(context.Context) error { return nil }

func (consumingTracesExporter) Capabilities() consumer.Capabilities { return consumer.Capabilities{} }

func (consumingTracesExporter) ConsumeTraces(_ context.Context, td ptrace.Traces) error {
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

func TestInstrumentedTracesExporter_ConsumeTraces(t *testing.T) {
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	ss.Spans().AppendEmpty()

	ie := &instrumentedTracesExporter{
		Traces:   consumingTracesExporter{},
		internal: imetrics.NoopReporter{},
	}
	require.NotPanics(t, func() { require.NoError(t, ie.ConsumeTraces(t.Context(), td)) })
}
