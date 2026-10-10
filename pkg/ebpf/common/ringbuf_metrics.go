// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"context"
	"log/slog"
	"time"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

// EventsRingbufName identifies the shared application-events ring buffer.
const EventsRingbufName = "events"

// RingbufWriteStats contains cumulative write counters from the eBPF map.
type RingbufWriteStats = BpfRingbufWriteStatsT

// ReadRingbufWriteStats reads and sums the per-CPU ring buffer write counters.
func ReadRingbufWriteStats(statsMap *ebpf.Map) (RingbufWriteStats, error) {
	var perCPU []RingbufWriteStats
	if err := statsMap.Lookup(uint32(0), &perCPU); err != nil {
		return RingbufWriteStats{}, err
	}
	return sumRingbufWriteStats(perCPU), nil
}

func sumRingbufWriteStats(perCPU []RingbufWriteStats) RingbufWriteStats {
	var total RingbufWriteStats
	for i := range perCPU {
		total.Writes += perCPU[i].Writes
		total.Failures += perCPU[i].Failures
	}
	return total
}

// StartRingbufWriteMetrics starts one collector for a ring buffer.
func (ctx *EBPFEventContext) StartRingbufWriteMetrics(
	runCtx context.Context,
	enabled bool,
	ringbufName string,
	statsMap *ebpf.Map,
	reporter imetrics.Reporter,
	log *slog.Logger,
) {
	if !enabled || ctx == nil || ringbufName == "" || statsMap == nil || reporter == nil {
		return
	}

	ctx.startRingbufWriteMetrics(
		runCtx,
		ringbufName,
		reporter.BpfInternalMetricsScrapeInterval(),
		func() (RingbufWriteStats, error) {
			return ReadRingbufWriteStats(statsMap)
		},
		reporter,
		log,
	)
}

func (ctx *EBPFEventContext) startRingbufWriteMetrics(
	runCtx context.Context,
	ringbufName string,
	interval time.Duration,
	reader func() (RingbufWriteStats, error),
	reporter imetrics.Reporter,
	log *slog.Logger,
) {
	if ctx == nil || ringbufName == "" || interval <= 0 || reader == nil || reporter == nil {
		return
	}

	if _, loaded := ctx.ringbufStatsCollectors.LoadOrStore(ringbufName, struct{}{}); loaded {
		return
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		collectRingbufWriteMetrics(runCtx, ringbufName, ticker.C, reader, reporter, log)
	}()
}

func collectRingbufWriteMetrics(
	ctx context.Context,
	ringbufName string,
	ticks <-chan time.Time,
	reader func() (RingbufWriteStats, error),
	reporter imetrics.Reporter,
	log *slog.Logger,
) {
	var lastWrites uint64
	var lastFailures uint64

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			stats, err := reader()
			if err != nil {
				log.Debug("can't retrieve ring buffer write stats", "error", err)
				continue
			}
			reporter.BPFRingbufWriteCounts(
				ringbufName,
				stats.Writes-lastWrites,
				stats.Failures-lastFailures,
			)
			lastWrites = stats.Writes
			lastFailures = stats.Failures
		}
	}
}
