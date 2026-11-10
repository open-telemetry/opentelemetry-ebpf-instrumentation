// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"net"
	"testing"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

const drainAfterSignal = 200 * time.Millisecond

type noopFetcher struct{}

func (noopFetcher) Close() error                    { return nil }
func (noopFetcher) StatsEventsMap() *ciliumebpf.Map { return nil }
func (noopFetcher) DebugEventsMap() *ciliumebpf.Map { return nil }

func TestRunForwardsRecordsDrainedAfterTheSignal(t *testing.T) {
	exported := msg.NewQueue[[]*ebpf.Stat](msg.ChannelBufferLen(10))
	exportedStats := exported.Subscribe()

	stats := Stats{
		agentIP: net.ParseIP("1.2.3.4"),
		ctxInfo: &global.ContextInfo{OverrideStatsExportQueue: exported},
		cfg:     &obi.Config{ChannelBufferLen: 10, ChannelSendTimeout: time.Minute, ShutdownTimeout: 10 * time.Second},
		fetcher: noopFetcher{},
	}

	originalTracer := newRingBufTracer
	t.Cleanup(func() { newRingBufTracer = originalTracer })
	newRingBufTracer = func(_ *Stats, out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
		return func(ctx context.Context) {
			defer out.MarkCloseable()
			<-ctx.Done()
			time.Sleep(drainAfterSignal)
			drainCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer cancel()
			out.SendCtx(drainCtx, []*ebpf.Stat{fakeRetransmitRecord(777, 888)})
		}
	}

	ctx, signal := context.WithCancel(t.Context())
	runDone := make(chan error, 1)
	go func() {
		runDone <- stats.Run(ctx)
	}()
	signal()

	drained := testutil.ReadChannel(t, exportedStats, 5*time.Second)
	require.Len(t, drained, 1)
	require.True(t, drained[0].TCPRetransmit)

	select {
	case err := <-runDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "Stats agent did not stop")
	}
}
