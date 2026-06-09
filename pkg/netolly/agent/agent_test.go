// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"io"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/tcmanager"
	"go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func TestFlowsStopReturnsRunnerCancelTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	const shutdownTimeout = 20 * time.Millisecond

	blocked := make(chan struct{})
	defer close(blocked)

	instancer := swarm.Instancer{}
	instancer.Add(swarm.DirectInstance(func(_ context.Context) {
		<-blocked
	}), swarm.WithID("stuck-runner"))

	graph, err := instancer.Instance(ctx)
	require.NoError(t, err)

	graph.Start(ctx, swarm.WithCancelTimeout(shutdownTimeout))
	cancel()

	flows := &Flows{
		cfg:          &obi.Config{ShutdownTimeout: shutdownTimeout},
		graph:        graph,
		ifaceManager: tcmanager.NewInterfaceManager(),
		ebpf:         testEBPFFetcher{},
	}

	err = flows.stop()
	require.Error(t, err)
	require.NotErrorIs(t, err, errShutdownTimeout)

	var cancelTimeoutErr swarm.CancelTimeoutError
	require.ErrorAs(t, err, &cancelTimeoutErr)
	require.Contains(t, cancelTimeoutErr.Error(), "stuck-runner")
}

type testEBPFFetcher struct{}

func (testEBPFFetcher) Close() error { return nil }

func (testEBPFFetcher) LookupAndDeleteMap() map[ebpf.NetFlowId]*ebpf.NetFlowMetrics { return nil }

func (testEBPFFetcher) ReadRingBuf() (ringbuf.Record, error) { return ringbuf.Record{}, io.EOF }

func (testEBPFFetcher) LookupPacketStats() (ebpf.NetPacketCount, error) {
	return ebpf.NetPacketCount{}, nil
}

func (testEBPFFetcher) DebugEventsMap() *cebpf.Map { return nil }
