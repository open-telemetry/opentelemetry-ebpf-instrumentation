// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/components/connector"
	"go.opentelemetry.io/obi/pkg/components/discover"
	"go.opentelemetry.io/obi/pkg/components/ebpf"
	"go.opentelemetry.io/obi/pkg/components/exec"
	"go.opentelemetry.io/obi/pkg/components/pipe/global"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestProcessEventsLoopDoesntBlock(t *testing.T) {
	instr, err := New(
		t.Context(),
		&global.ContextInfo{
			Prometheus: &connector.PrometheusManager{},
		},
		&obi.Config{
			ChannelBufferLen: 1,
			Traces: otel.TracesConfig{
				TracesEndpoint: "http://something",
			},
		},
	)

	events := make(chan discover.Event[*ebpf.Instrumentable])

	go instr.instrumentedEventLoop(t.Context(), events)

	for i := 0; i < 100; i++ {
		events <- discover.Event[*ebpf.Instrumentable]{
			Obj:  &ebpf.Instrumentable{FileInfo: &exec.FileInfo{Pid: int32(i)}},
			Type: discover.EventCreated,
		}
	}

	assert.NoError(t, err)
}
