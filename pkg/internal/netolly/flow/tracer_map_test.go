// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type emptyMapFetcher struct{}

func (emptyMapFetcher) LookupAndDeleteMap() map[ebpf.NetFlowId]*ebpf.NetFlowMetrics { return nil }

func (emptyMapFetcher) LookupPacketStats() (ebpf.NetPacketCount, error) {
	return ebpf.NetPacketCount{}, nil
}

func TestMapTracer_StopsEvictionGoroutine(t *testing.T) {
	tracer := NewMapTracer(&global.ContextInfo{Metrics: imetrics.NoopReporter{}}, emptyMapFetcher{}, time.Hour)
	ctx, cancel := context.WithCancel(t.Context())
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		tracer.TraceLoop(msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(10)))(ctx)
	}()
	require.Eventually(t, evictionGoroutineRunning, 5*time.Second, 10*time.Millisecond)

	cancel()
	<-loopDone

	assert.Eventually(t, func() bool { return !evictionGoroutineRunning() }, 5*time.Second, 10*time.Millisecond)
}

func evictionGoroutineRunning() bool {
	buf := make([]byte, 1<<20)
	return strings.Contains(string(buf[:runtime.Stack(buf, true)]), "(*MapTracer).evictionSynchronization")
}
