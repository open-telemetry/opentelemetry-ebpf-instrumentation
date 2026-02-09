// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package appnetworktracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/appnetworktracer"

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
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

// The following consts need to coincide with some C identifiers defined in bpf/appnetworktracer/types.h
const (
	EventTypeAppNetTCPRtt = 1 // event_app_net_tcp_rtt Application Network metrics related event - RTT
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type app_net_tcp_rtt_t -target amd64,arm64 Bpf ../../../../bpf/appnetworktracer/appnetworktracer.c -- -I../../../../bpf

type (
	AppNetTCPRtt BpfAppNetTcpRttT
	Tracer       struct {
		pidsFilter            ebpfcommon.ServiceFilter
		cfg                   *obi.Config
		metrics               imetrics.Reporter
		bpfObjects            BpfObjects
		closers               []io.Closer
		log                   *slog.Logger
		isGenericTracerActive bool
		iters                 []*ebpfcommon.Iter
	}
)

func New(pidFilter ebpfcommon.ServiceFilter, cfg *obi.Config, metrics imetrics.Reporter, isGenericTracerActive bool) *Tracer {
	return &Tracer{
		log:                   slog.With("component", "generic.AppNetworkTracer"),
		cfg:                   cfg,
		metrics:               metrics,
		pidsFilter:            pidFilter,
		isGenericTracerActive: isGenericTracerActive,
		iters:                 []*ebpfcommon.Iter{},
	}
}

// TODO: all the code related to pid management has been copied from the generictracer
// and will be removed and put into a pkg common to the generictracer and the appnetworktracer

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

func (p *Tracer) AllowPID(pid app.PID, ns uint32, svc *svc.Attrs) {
	if !p.isGenericTracerActive {
		p.pidsFilter.AllowPID(pid, ns, svc, ebpfcommon.PIDTypeKProbes)
		p.rebuildValidPids()
	}
}

func (p *Tracer) BlockPID(pid app.PID, ns uint32) {
	if !p.isGenericTracerActive {
		p.pidsFilter.BlockPID(pid, ns)
		p.rebuildValidPids()
	}
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	spec, err := LoadBpf()
	if err != nil {
		return nil, fmt.Errorf("can't load bpf collection from reader: %w", err)
	}

	return spec, err
}

func (p *Tracer) SetupTailCalls() {
}

func (p *Tracer) Constants() map[string]any {
	m := make(map[string]any, 2)
	m["g_bpf_debug"] = p.cfg.EBPF.BpfDebug
	if p.cfg.Discovery.BPFPidFilterOff {
		m["filter_pids"] = int32(0)
	} else {
		m["filter_pids"] = int32(1)
	}
	return m
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

	if p.cfg.AppNetworkMetrics.Rtt {
		kp["tcp_close"] = ebpfcommon.ProbeDesc{
			Required: true,
			Start:    p.bpfObjects.ObiKprobeTcpCloseRtt,
		}
	}

	return kp
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program { return nil }

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg { return nil }

func (p *Tracer) SockOps() []ebpfcommon.SockOps { return nil }

func (p *Tracer) Iters() []*ebpfcommon.Iter { return nil }

func (p *Tracer) Tracing() []*ebpfcommon.Tracing { return nil }

func (p *Tracer) RecordInstrumentedLib(uint64, []io.Closer) {}

func (p *Tracer) AddInstrumentedLibRef(uint64) {}

func (p *Tracer) UnlinkInstrumentedLib(uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(uint64) bool { return false }

func (p *Tracer) Run(ctx context.Context, _ *ebpfcommon.EBPFEventContext, eventsChan *msg.Queue[[]request.Span]) {
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
	return false
}

func (p *Tracer) handleAppNetworkEvent(_ *ebpfcommon.EBPFParseContext, _ *config.EBPFTracer, record *ringbuf.Record, _ ebpfcommon.ServiceFilter) (request.Span, bool, error) {
	eventType := record.RawSample[0]

	switch eventType {
	case EventTypeAppNetTCPRtt:
		return p.readTCPRttIntoSpan(record)
	default:
		p.log.Error("unknown net app event", "eventType", eventType)
	}

	return request.Span{}, true, nil
}

func (p *Tracer) readTCPRttIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ebpfcommon.ReinterpretCast[AppNetTCPRtt](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	peer := ""
	hostname := ""
	hostPort := 0
	if event.Conn.S_port != 0 || event.Conn.D_port != 0 {
		peer, hostname = reqHostInfo(event.Conn.S_addr, event.Conn.D_addr)
		hostPort = int(event.Conn.D_port)
	}

	peerPort := int(event.Conn.S_port)
	return request.Span{
		Type:     request.EventTypeAppNetTCPRtt,
		Peer:     peer,
		PeerPort: peerPort,
		Host:     hostname,
		HostPort: hostPort,
		Pid: request.PidInfo{
			HostPID:   app.PID(event.PidInfo.HostPid),
			UserPID:   app.PID(event.PidInfo.UserPid),
			Namespace: event.PidInfo.Ns,
		},
		AppNet: &request.AppNet{
			TCPRtt: request.TCPRtt{
				Srtt: event.Srtt,
			},
		},
	}, false, nil
}

func reqHostInfo(srcAddr, dstAddr [16]uint8) (source, target string) {
	src := make(net.IP, net.IPv6len)
	dst := make(net.IP, net.IPv6len)
	copy(src, srcAddr[:])
	copy(dst, dstAddr[:])

	srcStr := src.String()
	dstStr := dst.String()

	if src.IsUnspecified() {
		srcStr = ""
	}

	if dst.IsUnspecified() {
		dstStr = ""
	}

	return srcStr, dstStr
}
