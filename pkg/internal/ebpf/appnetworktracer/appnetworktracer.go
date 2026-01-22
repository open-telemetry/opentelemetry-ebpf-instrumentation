// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package appnetworktracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/appnetworktracer"

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type app_net_tcp_rtt_t -target amd64,arm64 Bpf ../../../../bpf/appnetworktracer/appnetworktracer.c -- -I../../../../bpf

type AppNetTcpRtt BpfAppNetTcpRttT

type Tracer struct {
	pidsFilter ebpfcommon.ServiceFilter
	cfg        *obi.Config
	metrics    imetrics.Reporter
	bpfObjects BpfObjects
	closers    []io.Closer
	log        *slog.Logger
}

func tlog() *slog.Logger {
	return slog.With("component", "generic.AppNetworkTracer")
}

func New(pidFilter ebpfcommon.ServiceFilter, cfg *obi.Config, metrics imetrics.Reporter) *Tracer {
	return &Tracer{
		log:        tlog(),
		cfg:        cfg,
		metrics:    metrics,
		pidsFilter: pidFilter,
	}
}

// Updating these requires updating the constants below in pid.h
// #define MAX_CONCURRENT_PIDS 3001 // estimate: 1000 concurrent processes (including children) * 3 namespaces per pid
// #define PRIME_HASH 192053 // closest prime to 3001 * 64
const (
	maxConcurrentPids = 3001
	primeHash         = 192053
)

func pidSegmentBit(k uint64) (uint32, uint32) {
	h := uint32(k % primeHash)
	segment := h / 64
	bit := h & 63

	return segment, bit
}

func (p *Tracer) buildPidFilter() []uint64 {
	result := make([]uint64, maxConcurrentPids)
	for nsid, pids := range p.pidsFilter.CurrentPIDs(ebpfcommon.PIDTypeKProbes) {
		for pid := range pids {
			// skip any pids that might've been added, but are not tracked by the kprobes
			p.log.Debug("Reallowing pid", "pid", pid, "namespace", nsid)

			k := (uint64(nsid) << 32) | uint64(pid)

			segment, bit := pidSegmentBit(k)

			v := result[segment]
			v |= (1 << bit)
			result[segment] = v
		}
	}

	return result
}

func (p *Tracer) rebuildValidPids() {
	if p.bpfObjects.ValidPids != nil {
		v := p.buildPidFilter()

		p.log.Debug("number of segments in pid filter cache", "len", len(v))

		for i, segment := range v {
			err := p.bpfObjects.ValidPids.Put(uint32(i), segment)
			if err != nil {
				p.log.Error("Error setting up pid in BPF space, sizes of Go and BPF maps don't match", "error", err, "i", i)
			}
		}
	}
}

func (p *Tracer) AllowPID(pid, ns uint32, svc *svc.Attrs) {
	p.pidsFilter.AllowPID(pid, ns, svc, ebpfcommon.PIDTypeKProbes)
	p.rebuildValidPids()
}

func (p *Tracer) BlockPID(pid, ns uint32) {
	p.pidsFilter.BlockPID(pid, ns)
	p.rebuildValidPids()
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	spec, err := LoadBpf()
	if err != nil {
		return nil, fmt.Errorf("can't load bpf collection from reader: %w", err)
	}

	// TODO pino check this
	//ebpfcommon.FixupSpec(spec, p.cfg.EBPF.OverrideBPFLoopEnabled)

	return spec, err
}

func (p *Tracer) SetupTailCalls() {
}

// TODO pino check this
func (p *Tracer) Constants() map[string]any {
	return map[string]any{
		"g_bpf_debug": p.cfg.EBPF.BpfDebug,
	}
}

func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets) {}

func (p *Tracer) ProcessBinary(_ *exec.FileInfo) {}

func (p *Tracer) BpfObjects() any {
	return &p.bpfObjects
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	kp := map[string]ebpfcommon.ProbeDesc{}
	if p.cfg.AppNetworkMetrics.Enabled {
		// TODO pino add all kprobes
	}
	if p.cfg.AppNetworkMetrics.Rtt {
		kp["tcp_close"] = ebpfcommon.ProbeDesc{
			Required: true,
			Start:    p.bpfObjects.ObiKprobeTcpCloseRtt,
		}
	}

	// TODO pino
	// if p.cfg.EBPF.ContextPropagation.IsEnabled() {
	// 	// tcp_rate_check_app_limited and tcp_sendmsg_fastopen are backup
	// 	// for tcp_sendmsg_locked which doesn't fire on certain kernels
	// 	// if sk_msg is attached.
	// 	kp["tcp_rate_check_app_limited"] = ebpfcommon.ProbeDesc{
	// 		Required: false,
	// 		Start:    p.bpfObjects.ObiKprobeTcpRateCheckAppLimited,
	// 	}
	// 	kp["tcp_sendmsg_fastopen"] = ebpfcommon.ProbeDesc{
	// 		Required: false,
	// 		Start:    p.bpfObjects.ObiKprobeTcpRateCheckAppLimited,
	// 	}
	// }

	return kp
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg { return nil }

func (p *Tracer) SockOps() []ebpfcommon.SockOps { return nil }

func (p *Tracer) Iters() []*ebpfcommon.Iter {
	return nil
}

func (p *Tracer) RecordInstrumentedLib(uint64, []io.Closer) {}

func (p *Tracer) AddInstrumentedLibRef(uint64) {}

func (p *Tracer) UnlinkInstrumentedLib(uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(uint64) bool {
	return false
}

func (p *Tracer) Run(ctx context.Context, ebpfEventContext *ebpfcommon.EBPFEventContext, eventsChan *msg.Queue[[]request.Span]) {
	// At this point we now have loaded the bpf objects, which means we should insert any
	// pids that are allowed into the bpf map
	if p.bpfObjects.ValidPids != nil {
		p.rebuildValidPids()
	} else {
		p.log.Error("BPF Pids map is not created yet, this is a bug.")
	}

	p.log.Info("Launching p.AppNetworkTracer")

	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.AppNetworkEvents,
		p.pidsFilter,
		p.handleAppNetworkEvent,
		p.log,
		p.metrics,
		eventsChan,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)

}

func (p *Tracer) Required() bool {
	return false // TODO pino check
}

func (p *Tracer) handleAppNetworkEvent(_ *ebpfcommon.EBPFParseContext, _ *config.EBPFTracer, record *ringbuf.Record, _ ebpfcommon.ServiceFilter) (request.Span, bool, error) {
	fmt.Println("pino handleAppNetworkEvent")

	eventType := record.RawSample[0]

	switch eventType {
	case ebpfcommon.EventTypeAppNetTcpRtt:
		fmt.Println("yeeeeee rtt")
		return p.readTcpRttIntoSpan(record)
	default:
		p.log.Error("unknown net app event")
	}

	return request.Span{}, false, nil
}

func (p *Tracer) readTcpRttIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ebpfcommon.ReinterpretCast[AppNetTcpRtt](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	return request.Span{
		Type: request.EventTypeAppNetTcpRtt,
		Pid: request.PidInfo{
			HostPID:   event.PidInfo.HostPid,
			UserPID:   event.PidInfo.UserPid,
			Namespace: event.PidInfo.Ns,
		},
	}, false, nil
}
