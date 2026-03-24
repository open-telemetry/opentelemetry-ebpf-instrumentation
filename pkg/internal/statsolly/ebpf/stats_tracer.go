// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

type (
	StatsTCPRtt              StatsTcpRttT
	StatsTCPFailedConnection StatsTcpFailedConnectionT
)

// Hook point names, grouped by attach type.
const (
	// Kprobes: kernel function names.
	KprobeTCPClose = "tcp_close"

	// Tracepoints: group/name.
	TracepointInetSockSetState = "sock/inet_sock_set_state"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type tcp_rtt_t -type tcp_failed_connection_t -target amd64,arm64 Stats ../../../../bpf/statsolly/stats.c -- -I../../../../bpf

type StatsFetcher struct {
	log         *slog.Logger
	statsEvents *ebpf.Map
	closables   []io.Closer
}

func tlog() *slog.Logger {
	return slog.With("component", "ebpf.StatFetcher")
}

func NewStatsFetcher(cfg *config.EBPFTracer) (*StatsFetcher, error) {
	tlog := tlog()
	if err := rlimit.RemoveMemlock(); err != nil {
		tlog.Warn("can't remove mem lock. The agent could not be able to start eBPF programs",
			"error", err)
	}

	objects := StatsObjects{}
	spec, err := LoadStats()
	if err != nil {
		return nil, fmt.Errorf("loading BPF data: %w", err)
	}

	ebpfconvenience.SetupMapSizes(spec, cfg.MapsConfig.GlobalScaleFactor)

	sharedMaps := map[string]*ebpf.Map{}
	var mu sync.Mutex
	if err := ebpfconvenience.LoadSpec(spec, &objects, map[string]any{
		"g_bpf_debug": cfg.BpfDebug,
	}, sharedMaps, &mu, ""); err != nil {
		return nil, fmt.Errorf("loading stats eBPF spec: %w", err)
	}

	kps := map[string]ebpfcommon.ProbeDesc{
		KprobeTCPClose: {
			Required: true,
			Start:    objects.ObiKprobeTcpCloseSrtt,
		},
	}
	kpClosables, err := kprobes(tlog, kps)
	if err != nil {
		return nil, err
	}

	tps := map[string]ebpfcommon.ProbeDesc{
		TracepointInetSockSetState: {
			Required: true,
			Start:    objects.ObiTracepointInetSockSetState,
		},
	}
	tpClosables, err := tracepoints(tlog, tps)
	if err != nil {
		return nil, err
	}

	return &StatsFetcher{
		log:         tlog,
		statsEvents: objects.StatsEvents,
		closables:   append(kpClosables, tpClosables...),
	}, nil
}

// Close any resources that are taken
func (m *StatsFetcher) Close() error {
	m.log.Debug("unregistering eBPF objects")

	var errs []error
	for _, c := range m.closables {
		if c != nil {
			errs = append(errs, c.Close())
		}
	}
	return errors.Join(errs...)
}

// StatsEventsMap returns the ring buffer map for stats events.
// The caller (ForwardRingbuf) is responsible for creating and closing the reader.
func (m *StatsFetcher) StatsEventsMap() *ebpf.Map {
	return m.statsEvents
}

func kprobes(log *slog.Logger, probes map[string]ebpfcommon.ProbeDesc) ([]io.Closer, error) {
	var closables []io.Closer
	for funcName, desc := range probes {
		if desc.Start != nil {
			kp, err := link.Kprobe(funcName, desc.Start, nil)
			if err != nil {
				if desc.Required {
					return closables, fmt.Errorf("kprobe %s: %w", funcName, err)
				}
				log.Warn("kprobe failed", "function", funcName, "error", err)
				continue
			}
			closables = append(closables, kp)
		}
		if desc.End != nil {
			krp, err := link.Kretprobe(funcName, desc.End, nil)
			if err != nil {
				if desc.Required {
					return closables, fmt.Errorf("kretprobe %s: %w", funcName, err)
				}
				log.Warn("kretprobe failed", "function", funcName, "error", err)
				continue
			}
			closables = append(closables, krp)
		}
	}
	return closables, nil
}

func tracepoints(log *slog.Logger, probes map[string]ebpfcommon.ProbeDesc) ([]io.Closer, error) {
	var closables []io.Closer
	for funcName, desc := range probes {
		if desc.Start == nil {
			continue
		}
		parts := strings.SplitN(funcName, "/", 2)
		if len(parts) != 2 {
			return closables, fmt.Errorf("invalid tracepoint %q: must be group/name", funcName)
		}
		tp, err := link.Tracepoint(parts[0], parts[1], desc.Start, nil)
		if err != nil {
			if desc.Required {
				return closables, fmt.Errorf("tracepoint %s: %w", funcName, err)
			}
			log.Warn("tracepoint failed", "tracepoint", funcName, "error", err)
			continue
		}
		closables = append(closables, tp)
	}
	return closables, nil
}
