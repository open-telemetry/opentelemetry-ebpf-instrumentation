// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
)

type StatsTCPRtt StatsTcpRttT

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type tcp_rtt_t -target amd64,arm64 Stats ../../../../bpf/statsolly/stats.c -- -I../../../../bpf

type StatsFetcher struct {
	log           *slog.Logger
	ringbufReader *ringbuf.Reader
	closables     []io.Closer
}

func tlog() *slog.Logger {
	return slog.With("component", "ebpf.StatFetcher")
}

func NewStatsFetcher() (*StatsFetcher, error) {
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

	// Debug events map is unsupported due to pinning
	spec.Maps["debug_events"] = &ebpf.MapSpec{
		Name:       "dummy_map",
		Type:       ebpf.RingBuf,
		Pinning:    ebpf.PinNone,
		MaxEntries: uint32(os.Getpagesize()),
	}

	// msg_buffer_mem map is unsupported due to pinning
	const kMsgBufferSizeMax = 4096

	spec.Maps["msg_buffer_mem"] = &ebpf.MapSpec{
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  uint32(kMsgBufferSizeMax),
		MaxEntries: 1,
	}

	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	ktc, err := link.Kprobe("tcp_close", objects.ObiKprobeTcpCloseSrtt, nil)
	if err != nil {
		tlog.Error("opening %s: %s", "tcp_close", err)
		return nil, fmt.Errorf("opening kprobe: %w", err)
	}

	// read events from ringbuffer
	stats, err := ringbuf.NewReader(objects.StatsEvents)
	if err != nil {
		return nil, fmt.Errorf("accessing to ringbuffer: %w", err)
	}
	var closables []io.Closer
	return &StatsFetcher{
		log:           tlog,
		ringbufReader: stats,
		closables:     append(closables, ktc),
	}, nil
}

// Close any resources that are taken
func (m *StatsFetcher) Close() error {
	m.log.Debug("unregistering eBPF objects")

	var errs []error
	// m.ringbufReader.Read is a blocking operation, so we need to close the ring buffer
	// from another goroutine to avoid the system not being able to exit if there
	// isn't traffic in a given interface
	if m.ringbufReader != nil {
		if err := m.ringbufReader.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	for _, c := range m.closables {
		if c != nil {
			if err := c.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}

	var errStrings []string
	for _, err := range errs {
		errStrings = append(errStrings, err.Error())
	}
	return errors.New(`errors: "` + strings.Join(errStrings, `", "`) + `"`)
}

func (m *StatsFetcher) ReadRingBuf() (ringbuf.Record, error) {
	return m.ringbufReader.Read()
}
