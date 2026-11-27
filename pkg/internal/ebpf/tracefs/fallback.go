// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracefs // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tracefs"

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

type ProbeType string

const (
	Uprobe ProbeType = "uprobe"
	Kprobe ProbeType = "kprobe"

	shutdownTimeoutMultiplier = 3
)

type Options struct {
	Type ProbeType
	// Targets are kernel symbols or executable:offset[(ref_ctr_offset)] targets.
	Targets []string
	PID     uint32
	Return  bool
}

var fallbackUsed atomic.Bool

var fallbackLogs = map[ProbeType]*struct{ success, failure sync.Once }{
	Uprobe: {},
	Kprobe: {},
}

// EffectiveShutdownTimeout allows for per-event RCU waits on older kernels
// which cannot remove tracefs probes as a group.
func EffectiveShutdownTimeout(configured time.Duration) time.Duration {
	if fallbackUsed.Load() {
		return shutdownTimeoutMultiplier * configured
	}
	return configured
}

type AttachFuncs[T io.Closer] struct {
	PMU               func() (T, error)
	TraceFS           func() (T, error)
	TraceFSDuplicates func() (T, error)
}

func WithFallback[T io.Closer](kind ProbeType, attach AttachFuncs[T]) (T, error) {
	link, pmuErr := attach.PMU()
	if pmuErr == nil {
		return link, nil
	}

	lastErr := pmuErr
	var traceErr error
	retry := func(attempt func() (T, error)) {
		slog.Debug("retrying probe through tracefs", "probe_type", kind, "error", lastErr)
		link, lastErr = attempt()
		traceErr = errors.Join(traceErr, lastErr)
	}
	if errors.Is(lastErr, unix.EACCES) {
		retry(attach.TraceFS)
	}

	// Either the PMU or the named tracefs attempt can report an ambiguous symbol.
	if kind == Kprobe && errors.Is(lastErr, unix.EADDRNOTAVAIL) && attach.TraceFSDuplicates != nil {
		retry(attach.TraceFSDuplicates)
	}

	if lastErr == nil {
		fallbackUsed.Store(true)
		fallbackLogs[kind].success.Do(func() {
			slog.Info("attached probe through tracefs", "probe_type", kind, "pmu_error", pmuErr)
		})
		return link, nil
	}

	if traceErr == nil {
		return link, pmuErr
	}

	fallbackLogs[kind].failure.Do(func() {
		msg := "tracefs fallback failed"
		if errors.Is(lastErr, os.ErrPermission) {
			msg += "; ensure tracefs is writable (CAP_DAC_OVERRIDE may be required)"
		}
		slog.Error(msg, "probe_type", kind, "pmu_error", pmuErr, "error", traceErr)
	})

	var zero T
	return zero, errors.Join(pmuErr, traceErr)
}
