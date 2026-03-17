// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

func TestProcessEventsLoopDoesntBlock(t *testing.T) {
	instr, err := New(
		t.Context(),
		&global.ContextInfo{
			Prometheus: &connector.PrometheusManager{},
		},
		&obi.Config{
			ChannelBufferLen: 1,
			Traces: otelcfg.TracesConfig{
				TracesEndpoint: "http://something",
			},
		},
	)

	events := make(chan discover.Event[*ebpf.Instrumentable])

	go instr.instrumentedEventLoop(t.Context(), events)

	for i := range app.PID(100) {
		events <- discover.Event[*ebpf.Instrumentable]{
			Obj:  &ebpf.Instrumentable{FileInfo: &exec.FileInfo{Pid: i}},
			Type: discover.EventCreated,
		}
	}

	assert.NoError(t, err)
}

// TestInstrumenter_WithDynamicPIDSelector verifies that when the caller passes a selector via
// ContextInfo.AppO11y.DynamicPIDSelector, New uses it and the caller can add/remove PIDs on it directly.
func TestInstrumenter_WithDynamicPIDSelector(t *testing.T) {
	sel := discover.NewDynamicPIDSelector()
	ctxInfo := &global.ContextInfo{
		Prometheus: &connector.PrometheusManager{},
		AppO11y:    global.AppO11y{DynamicPIDSelector: sel},
	}
	_, err := New(
		t.Context(),
		ctxInfo,
		&obi.Config{ChannelBufferLen: 1, Traces: otelcfg.TracesConfig{TracesEndpoint: "http://localhost"}},
	)
	require.NoError(t, err)

	sel.AddPIDs(1, 2, 3)
	sel.AddPIDs(2, 4)
	sel.RemovePIDs(2)
	sel.RemovePIDs(99)
	pids, ok := sel.GetPIDs()
	require.True(t, ok)
	assert.Equal(t, []app.PID{1, 3, 4}, pids)
}
