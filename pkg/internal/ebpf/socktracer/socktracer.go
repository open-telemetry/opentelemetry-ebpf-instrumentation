// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package socktracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/socktracer"

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 SocktracerEgress ../../../../bpf/socktracer/egress.c -- -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 SocktracerIngress ../../../../bpf/socktracer/ingress.c -- -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 SocktracerSockops ../../../../bpf/socktracer/sockops.c -- -I../../../../bpf

type Tracer struct {
	cfg         *obi.Config
	egressObjs  SocktracerEgressObjects
	ingressObjs SocktracerIngressObjects
	sockopsObjs SocktracerSockopsObjects
	closers     []io.Closer
	log         *slog.Logger
	pidsMu      sync.Mutex
	pids        map[app.PID]struct{}
}

func setConstant[T int32 | uint32](m map[string]any, name string, value bool) {
	if value {
		m[name] = T(1)
	} else {
		m[name] = T(0)
	}
}

func New(cfg *obi.Config) *Tracer {
	log := slog.With("component", "socktracer")

	return &Tracer{
		log:  log,
		cfg:  cfg,
		pids: make(map[app.PID]struct{}),
	}
}

func (p *Tracer) AllowPID(pid app.PID, _ uint32, _ *exec.FileInfo) {
	p.pidsMu.Lock()
	p.pids[pid] = struct{}{}
	p.pidsMu.Unlock()

	p.backfillPidForSockets(pid)
}

func (p *Tracer) BlockPID(pid app.PID, _ uint32) {
	p.pidsMu.Lock()
	defer p.pidsMu.Unlock()
	delete(p.pids, pid)
}

func (p *Tracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	egressSpec, err := LoadSocktracerEgress()
	if err != nil {
		return nil, fmt.Errorf("loading egress spec: %w", err)
	}

	ingressSpec, err := LoadSocktracerIngress()
	if err != nil {
		return nil, fmt.Errorf("loading ingress spec: %w", err)
	}

	sockopsSpec, err := LoadSocktracerSockops()
	if err != nil {
		return nil, fmt.Errorf("loading sockops spec: %w", err)
	}

	return []*ebpfcommon.SpecBundle{
		{
			Spec:      egressSpec,
			Objects:   &p.egressObjs,
			Constants: p.egressConstants(),
		},
		{
			Spec:      ingressSpec,
			Objects:   &p.ingressObjs,
			Constants: p.ingressConstants(),
		},
		{
			Spec:      sockopsSpec,
			Objects:   &p.sockopsObjs,
			Constants: p.sockopsConstants(),
		},
	}, nil
}

func (p *Tracer) injectFlags() uint32 {
	flags := uint32(0)

	if p.cfg.EBPF.ContextPropagation.HasHeaders() {
		flags |= 1 // k_inject_http_headers
	}

	if p.cfg.EBPF.ContextPropagation.HasTCP() {
		flags |= 2 // k_inject_tcp_options
	}

	return flags
}

func (p *Tracer) tcpMaxCapturedBytes() uint32 {
	bs := p.cfg.EBPF.BufferSizes
	return max(bs.TCP, bs.MySQL, bs.Kafka, bs.Postgres)
}

func (p *Tracer) egressConstants() map[string]any {
	c := make(map[string]any)
	c["inject_flags"] = p.injectFlags()
	c["http_max_captured_bytes"] = p.cfg.EBPF.BufferSizes.HTTP
	c["tcp_max_captured_bytes"] = p.tcpMaxCapturedBytes()
	c["max_transaction_time"] = uint64(p.cfg.EBPF.MaxTransactionTime.Nanoseconds())
	c["g_bpf_debug"] = p.cfg.EBPF.BpfDebug

	setConstant[uint32](c, "track_request_headers", p.cfg.EBPF.TrackRequestHeaders)
	setConstant[uint32](c, "high_request_volume", p.cfg.EBPF.HighRequestVolume)
	setConstant[int32](c, "filter_pids", !p.cfg.Discovery.BPFPidFilterOff)
	c["wakeup_data_bytes"] = uint32(p.cfg.EBPF.WakeupLen) * uint32(unsafe.Sizeof(ebpfcommon.HTTPRequestTrace{}))

	return c
}

func (p *Tracer) ingressConstants() map[string]any {
	c := make(map[string]any)
	c["http_max_captured_bytes"] = p.cfg.EBPF.BufferSizes.HTTP
	c["tcp_max_captured_bytes"] = p.tcpMaxCapturedBytes()
	c["g_bpf_debug"] = p.cfg.EBPF.BpfDebug

	setConstant[uint32](c, "high_request_volume", p.cfg.EBPF.HighRequestVolume)
	c["wakeup_data_bytes"] = uint32(p.cfg.EBPF.WakeupLen) * uint32(unsafe.Sizeof(ebpfcommon.HTTPRequestTrace{}))

	return c
}

func (p *Tracer) sockopsConstants() map[string]any {
	c := make(map[string]any)
	c["inject_flags"] = p.injectFlags()
	c["g_bpf_debug"] = p.cfg.EBPF.BpfDebug

	setConstant[int32](c, "filter_pids", !p.cfg.Discovery.BPFPidFilterOff)

	return c
}

func (p *Tracer) SetupTailCalls() {}

func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets) {}

func (p *Tracer) ProcessBinary(_ *exec.FileInfo) {}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg {
	return []ebpfcommon.SockMsg{
		{
			Program:  p.egressObjs.ObiSocketEgress,
			MapFD:    p.sockopsObjs.SockDir.FD(),
			AttachAs: ebpf.AttachSkMsgVerdict,
		},
	}
}

func (p *Tracer) SockOps() []ebpfcommon.SockOps {
	return []ebpfcommon.SockOps{
		{
			Program:  p.sockopsObjs.ObiSockmapTracker,
			AttachAs: ebpf.AttachCGroupSockOps,
		},
		{
			Program:  p.ingressObjs.ObiSocketIngress,
			AttachAs: ebpf.AttachCGroupInetIngress,
		},
		{
			Program:  p.sockopsObjs.ObiPostBind4,
			AttachAs: ebpf.AttachCGroupInet4PostBind,
		},
		{
			Program:  p.sockopsObjs.ObiPostBind6,
			AttachAs: ebpf.AttachCGroupInet6PostBind,
		},
	}
}

func (p *Tracer) Iters() []*ebpfcommon.Iter {
	return nil
}

func (p *Tracer) Tracing() []*ebpfcommon.Tracing {
	return nil
}

func (p *Tracer) RecordInstrumentedLib(uint64, []io.Closer) {}

func (p *Tracer) AddInstrumentedLibRef(uint64) {}

func (p *Tracer) UnlinkInstrumentedLib(uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(uint64) bool {
	return false
}

func (p *Tracer) Run(ctx context.Context, _ *ebpfcommon.EBPFEventContext, _ *msg.Queue[[]request.Span]) {
	p.log.Debug("socktracer started")

	<-ctx.Done()

	p.egressObjs.Close()
	p.ingressObjs.Close()
	p.sockopsObjs.Close()

	p.log.Debug("socktracer terminated")
}

func (p *Tracer) SetEventContext(_ *ebpfcommon.EBPFEventContext) {}

func (p *Tracer) Capabilities() ebpfcommon.TracerCapability { return ebpfcommon.CapSocketTracing }

func (p *Tracer) Required() bool {
	return false
}
