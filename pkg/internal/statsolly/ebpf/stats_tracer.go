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

	var closables []io.Closer

	for funcName, program := range map[string]*ebpf.Program{
		KprobeTCPClose: objects.ObiKprobeTcpCloseSrtt,
	} {
		kp, kerr := link.Kprobe(funcName, program, nil)
		if kerr != nil {
			closeAll(closables)
			return nil, fmt.Errorf("kprobe attachment failed %s: %w", funcName, kerr)
		}
		closables = append(closables, kp)
	}

	for funcName, program := range map[string]*ebpf.Program{
		TracepointInetSockSetState: objects.ObiTracepointInetSockSetState,
	} {
		parts := strings.SplitN(funcName, "/", 2)
		if len(parts) != 2 {
			closeAll(closables)
			return nil, fmt.Errorf("invalid tracepoint %q: must be group/name", funcName)
		}
		tp, terr := link.Tracepoint(parts[0], parts[1], program, nil)
		if terr != nil {
			closeAll(closables)
			return nil, fmt.Errorf("tracepoint attachment failed %s: %w", funcName, terr)
		}
		closables = append(closables, tp)
	}

	return &StatsFetcher{
		log:         tlog,
		statsEvents: objects.StatsEvents,
		closables:   closables,
	}, nil
}

func closeAll(closables []io.Closer) {
	for _, c := range closables {
		if c != nil {
			c.Close()
		}
	}
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
