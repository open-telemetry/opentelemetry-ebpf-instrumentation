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
type RingbufWriteStats struct {
	Writes   uint64
	Failures uint64
}

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

// StartRingbufWriteMetrics starts one collector for the shared events ring buffer.
func (ctx *EBPFEventContext) StartRingbufWriteMetrics(
	runCtx context.Context,
	interval time.Duration,
	reader func() (RingbufWriteStats, error),
	reporter imetrics.Reporter,
	log *slog.Logger,
) {
	if ctx == nil || interval <= 0 || reader == nil || reporter == nil {
		return
	}

	ctx.ringbufStatsOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			collectRingbufWriteMetrics(runCtx, ticker.C, reader, reporter, log)
		}()
	})
}

func collectRingbufWriteMetrics(
	ctx context.Context,
	ticks <-chan time.Time,
	reader func() (RingbufWriteStats, error),
	reporter imetrics.Reporter,
	log *slog.Logger,
) {
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
			reporter.BPFRingbufWriteStats(EventsRingbufName, stats.Writes, stats.Failures)
		}
	}
}
