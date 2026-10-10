// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

type ringbufStatsReport struct {
	name  string
	stats RingbufWriteStats
}

type ringbufStatsReporter struct {
	imetrics.NoopReporter
	reports chan ringbufStatsReport
}

func (r *ringbufStatsReporter) BPFRingbufWriteCounts(name string, writes, failures uint64) {
	r.reports <- ringbufStatsReport{name: name, stats: RingbufWriteStats{Writes: writes, Failures: failures}}
}

func TestSumRingbufWriteStats(t *testing.T) {
	stats := sumRingbufWriteStats([]RingbufWriteStats{
		{Writes: 3, Failures: 1},
		{Writes: 5, Failures: 2},
	})
	assert.Equal(t, RingbufWriteStats{Writes: 8, Failures: 3}, stats)
}

func TestReadRingbufWriteStatsError(t *testing.T) {
	_, err := ReadRingbufWriteStats(&ebpf.Map{})
	require.Error(t, err)
}

func TestCollectRingbufWriteMetrics(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	ticks := make(chan time.Time)
	reporter := &ringbufStatsReporter{reports: make(chan ringbufStatsReport, 2)}
	var reads atomic.Int32
	reader := func() (RingbufWriteStats, error) {
		switch reads.Add(1) {
		case 1:
			return RingbufWriteStats{}, errors.New("lookup failed")
		case 2:
			return RingbufWriteStats{Writes: 7, Failures: 2}, nil
		default:
			return RingbufWriteStats{Writes: 10, Failures: 4}, nil
		}
	}
	done := make(chan struct{})
	go func() {
		collectRingbufWriteMetrics(
			ctx,
			"gpu_events",
			ticks,
			reader,
			reporter,
			slog.New(slog.NewTextHandler(io.Discard, nil)),
		)
		close(done)
	}()

	ticks <- time.Now()
	ticks <- time.Now()
	ticks <- time.Now()

	firstReport := <-reporter.reports
	assert.Equal(t, "gpu_events", firstReport.name)
	assert.Equal(t, RingbufWriteStats{Writes: 7, Failures: 2}, firstReport.stats)

	secondReport := <-reporter.reports
	assert.Equal(t, "gpu_events", secondReport.name)
	assert.Equal(t, RingbufWriteStats{Writes: 3, Failures: 2}, secondReport.stats)

	cancel()
	require.Eventually(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond)
}

func TestStartRingbufWriteMetricsOncePerRingbuf(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reporter := &ringbufStatsReporter{reports: make(chan ringbufStatsReport, 10)}
	eventContext := NewEBPFEventContext()
	var firstReads atomic.Int32
	var secondReads atomic.Int32
	var gpuReads atomic.Int32
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	eventContext.StartRingbufWriteMetrics(ctx, true, EventsRingbufName, &ebpf.Map{}, reporter, log)
	eventContext.startRingbufWriteMetrics(ctx, EventsRingbufName, time.Millisecond, func() (RingbufWriteStats, error) {
		firstReads.Add(1)
		return RingbufWriteStats{}, nil
	}, reporter, log)
	eventContext.startRingbufWriteMetrics(ctx, EventsRingbufName, time.Millisecond, func() (RingbufWriteStats, error) {
		secondReads.Add(1)
		return RingbufWriteStats{}, nil
	}, reporter, log)
	eventContext.startRingbufWriteMetrics(ctx, "gpu_events", time.Millisecond, func() (RingbufWriteStats, error) {
		gpuReads.Add(1)
		return RingbufWriteStats{}, nil
	}, reporter, log)

	require.Eventually(t, func() bool {
		return firstReads.Load() > 0 && gpuReads.Load() > 0
	}, time.Second, time.Millisecond)
	cancel()
	assert.Positive(t, firstReads.Load())
	assert.Zero(t, secondReads.Load())
	assert.Positive(t, gpuReads.Load())

	eventContext.startRingbufWriteMetrics(ctx, "", 0, nil, nil, nil)
	(*EBPFEventContext)(nil).startRingbufWriteMetrics(ctx, EventsRingbufName, time.Second, nil, nil, nil)
	eventContext.StartRingbufWriteMetrics(ctx, false, "", nil, nil, nil)
	(*EBPFEventContext)(nil).StartRingbufWriteMetrics(ctx, true, EventsRingbufName, &ebpf.Map{}, reporter, log)
}
