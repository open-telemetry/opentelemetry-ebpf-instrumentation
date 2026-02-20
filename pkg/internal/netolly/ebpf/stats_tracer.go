// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
)

type AppNetTCPRtt NetStatsAppNetTcpRttT

// pino
// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type app_net_tcp_rtt_t -target amd64,arm64 NetStats ../../../../bpf/appnetworktracer/appnetworktracer.c -- -I../../../../bpf

type StatsFetcher struct {
	log           *slog.Logger
	objects       *NetStatsObjects // pino
	ringbufReader *ringbuf.Reader
	//cacheMaxSize  int
}

func NewStatsFetcher() (*StatsFetcher, error) {
	tlog := tlog()
	if err := rlimit.RemoveMemlock(); err != nil {
		tlog.Warn("can't remove mem lock. The agent could not be able to start eBPF programs",
			"error", err)
	}

	objects := NetStatsObjects{}
	spec, err := LoadNetStats()
	if err != nil {
		return nil, fmt.Errorf("loading BPF data: %w", err)
	}

	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	ktc, err := link.Kprobe("tcp_close", objects.ObiKprobeTcpCloseRtt, nil)
	if err != nil {
		log.Fatalf("opening %s: %s", "tcp_close", err)
	}
	defer ktc.Close()

	// read events from ringbuffer
	stats, err := ringbuf.NewReader(objects.AppNetworkEvents)
	if err != nil {
		return nil, fmt.Errorf("accessing to ringbuffer: %w", err)
	}
	return &StatsFetcher{
		log:           tlog,
		objects:       &objects,
		ringbufReader: stats,
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
	if m.objects != nil {
		errs = append(errs, m.closeObjects()...)
	}
	if len(errs) == 0 {
		return nil
	}

	var errStrings []string
	for _, err := range errs {
		errStrings = append(errStrings, err.Error())
	}
	return errors.New(`errors: "` + strings.Join(errStrings, `", "`) + `"`)
}

func (m *StatsFetcher) closeObjects() []error {
	var errs []error
	if err := m.objects.ObiKprobeTcpCloseRtt.Close(); err != nil {
		errs = append(errs, err)
	}
	m.objects = nil
	return errs
}

func (m *StatsFetcher) ReadRingBuf() (ringbuf.Record, error) {
	return m.ringbufReader.Read()
}

// LookupAndDeleteMap reads all the entries from the eBPF map and removes them from it.
// It returns a map where the key
// For synchronization purposes, we get/delete a whole snapshot of the flows map.
// This way we avoid missing packets that could be updated on the
// ebpf side while we process/aggregate them here
// Changing this method invocation by BatchLookupAndDelete could improve performance
// TODO: detect whether BatchLookupAndDelete is supported (Kernel>=5.6) and use it selectively
// Supported Lookup/Delete operations by kernel: https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
// Race conditions here causes that some flows are lost in high-load scenarios
// func (m *StatsFetcher) LookupAndDeleteMap() map[NetFlowId][]NetFlowMetrics {
// 	flowMap := m.objects.AggregatedFlows // PINOOOOO

// 	iterator := flowMap.Iterate()
// 	flows := make(map[NetFlowId][]NetFlowMetrics, m.cacheMaxSize)

// 	id := NetFlowId{}
// 	var metrics []NetFlowMetrics
// 	// Changing Iterate+Delete by LookupAndDelete would prevent some possible race conditions
// 	// TODO: detect whether LookupAndDelete is supported (Kernel>=4.20) and use it selectively
// 	for iterator.Next(&id, &metrics) {
// 		if err := flowMap.Delete(id); err != nil {
// 			m.log.Debug("couldn't delete flow entry", "flowId", id, "error", err)
// 		}
// 		// We observed that eBFP PerCPU map might insert multiple times the same key in the map
// 		// (probably due to race conditions) so we need to re-join metrics again at userspace
// 		// TODO: instrument how many times the keys are is repeated in the same eviction
// 		flows[id] = append(flows[id], metrics...)
// 	}
// 	return flows
// }

// func isLittleEndian() bool {
// 	var a uint16 = 1

// 	return *(*byte)(unsafe.Pointer(&a)) == 1
// }

// func htons(a uint16) uint16 {
// 	if isLittleEndian() {
// 		var arr [2]byte
// 		binary.LittleEndian.PutUint16(arr[:], a)
// 		return binary.BigEndian.Uint16(arr[:])
// 	}
// 	return a
// }

// func kProbes(bpfObjects NetStatsObjects) map[string]ebpfcommon.ProbeDesc {
// 	kp := map[string]ebpfcommon.ProbeDesc{}

// 	if true { // p.cfg.AppNetworkMetrics.TCPRtt
// 		kp["tcp_close"] = ebpfcommon.ProbeDesc{
// 			Required: true,
// 			Start:    bpfObjects.ObiKprobeTcpCloseRtt,
// 		}
// 	}

// 	return kp
// }
