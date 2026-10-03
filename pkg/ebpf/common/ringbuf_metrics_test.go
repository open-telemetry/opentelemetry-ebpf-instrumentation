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

func (r *ringbufStatsReporter) BPFRingbufWriteStats(name string, writes, failures uint64) {
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
	reporter := &ringbufStatsReporter{reports: make(chan ringbufStatsReport, 1)}
	var reads atomic.Int32
	reader := func() (RingbufWriteStats, error) {
		if reads.Add(1) == 1 {
			return RingbufWriteStats{}, errors.New("lookup failed")
		}
		return RingbufWriteStats{Writes: 7, Failures: 2}, nil
	}
	done := make(chan struct{})
	go func() {
		collectRingbufWriteMetrics(
			ctx,
			ticks,
			reader,
			reporter,
			slog.New(slog.NewTextHandler(io.Discard, nil)),
		)
		close(done)
	}()

	ticks <- time.Now()
	ticks <- time.Now()
	report := <-reporter.reports
	assert.Equal(t, EventsRingbufName, report.name)
	assert.Equal(t, RingbufWriteStats{Writes: 7, Failures: 2}, report.stats)

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

func TestStartRingbufWriteMetricsOnlyOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reporter := &ringbufStatsReporter{reports: make(chan ringbufStatsReport, 2)}
	eventContext := NewEBPFEventContext()
	var firstReads atomic.Int32
	var secondReads atomic.Int32
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	eventContext.StartRingbufWriteMetrics(ctx, time.Millisecond, func() (RingbufWriteStats, error) {
		firstReads.Add(1)
		return RingbufWriteStats{}, nil
	}, reporter, log)
	eventContext.StartRingbufWriteMetrics(ctx, time.Millisecond, func() (RingbufWriteStats, error) {
		secondReads.Add(1)
		return RingbufWriteStats{}, nil
	}, reporter, log)

	select {
	case <-reporter.reports:
	case <-time.After(time.Second):
		require.Fail(t, "ring buffer metrics were not collected")
	}
	cancel()
	assert.Positive(t, firstReads.Load())
	assert.Zero(t, secondReads.Load())

	eventContext.StartRingbufWriteMetrics(ctx, 0, nil, nil, nil)
	(*EBPFEventContext)(nil).StartRingbufWriteMetrics(ctx, time.Second, nil, nil, nil)
}
