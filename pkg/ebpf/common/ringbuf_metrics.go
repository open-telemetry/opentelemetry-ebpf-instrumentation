// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

// EventsRingbufName identifies the shared application-events ring buffer.
const EventsRingbufName = "events"

// RingbufWriteStats contains cumulative write counters from the eBPF map.
type RingbufWriteStats struct {
	Writes   uint64
	Failures uint64
}

// StartRingbufWriteMetrics starts one collector for the shared events ring buffer.
func (e *EBPFEventContext) StartRingbufWriteMetrics(
	ctx context.Context,
	interval time.Duration,
	reader func() (RingbufWriteStats, error),
	reporter imetrics.Reporter,
	log *slog.Logger,
) {
	if e == nil || interval <= 0 || reader == nil || reporter == nil {
		return
	}

	e.ringbufStatsOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			collectRingbufWriteMetrics(ctx, ticker.C, reader, reporter, log)
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
