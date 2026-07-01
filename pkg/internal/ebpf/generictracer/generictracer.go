// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"context"
	"debug/elf"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/netns"
	"go.opentelemetry.io/obi/pkg/internal/netolly/ifaces"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 Bpf ../../../../bpf/generictracer/generictracer.c -- -I../../../../bpf

type Tracer struct {
	pidsFilter       ebpfcommon.ServiceFilter
	cfg              *obi.Config
	metrics          imetrics.Reporter
	bpfObjects       BpfObjects
	closers          []io.Closer
	log              *slog.Logger
	qdiscs           map[ifaces.Interface]*netlink.GenericQdisc
	egressFilters    map[ifaces.Interface]*netlink.BpfFilter
	ingressFilters   map[ifaces.Interface]*netlink.BpfFilter
	instrumentedLibs ebpfcommon.InstrumentedLibsT
	libsMux          sync.Mutex
	iters            []*ebpfcommon.Iter
	eventCtx         *ebpfcommon.EBPFEventContext
	jvmUSDTManager   ebpfcommon.USDTSpecManager
	customSpan       *customSpanRuntime
}

// customSpanSpecMgr returns the spec manager that hands out IDs into the
// shared obi_usdt_specs map. The manager lives on the EBPFEventContext so
// every generictracer instance (e.g. one for non-Go binaries plus a
// piggy-backed one for Go binaries) hands out distinct IDs.
func (p *Tracer) customSpanSpecMgr() *ebpfcommon.USDTSpecManager {
	if p.eventCtx == nil {
		// Fall back to a per-tracer manager when the event context isn't
		// wired yet (e.g. early init paths in tests). The integration
		// path always sets eventCtx before any attach happens.
		return &ebpfcommon.USDTSpecManager{}
	}
	return &p.eventCtx.CustomSpanSpecMgr
}

// customSpanRuntime is the per-tracer userspace state for custom_span spans.
// Cookies are stable across rediscovery so spans defined once stay valid.
type customSpanRuntime struct {
	spans    []customSpanBinding
	registry *CustomSpanRegistry
	pairer   *CustomSpanPairer
	builder  *CustomSpanBuilder
}

type customSpanBinding struct {
	cookie uint64
	span   config.CustomSpanSpec
}

func tlog() *slog.Logger {
	return slog.With("component", "generic.Tracer")
}

func New(pidFilter ebpfcommon.ServiceFilter, cfg *obi.Config, metrics imetrics.Reporter) *Tracer {
	return &Tracer{
		log:              tlog(),
		cfg:              cfg,
		metrics:          metrics,
		pidsFilter:       pidFilter,
		qdiscs:           map[ifaces.Interface]*netlink.GenericQdisc{},
		egressFilters:    map[ifaces.Interface]*netlink.BpfFilter{},
		ingressFilters:   map[ifaces.Interface]*netlink.BpfFilter{},
		instrumentedLibs: make(ebpfcommon.InstrumentedLibsT),
		libsMux:          sync.Mutex{},
		iters:            []*ebpfcommon.Iter{},
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

func (p *Tracer) AllowPID(pid app.PID, ns uint32, fi *exec.FileInfo) {
	p.pidsFilter.AllowPID(pid, ns, fi, ebpfcommon.PIDTypeKProbes)
	p.rebuildValidPids()
}

func (p *Tracer) BlockPID(pid app.PID, ns uint32) {
	p.pidsFilter.BlockPID(pid, ns)
	p.rebuildValidPids()
}

func (p *Tracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	if p.cfg.EBPF.TrackRequestHeaders ||
		p.cfg.EBPF.ContextPropagation.IsEnabled() {
		p.log.Info("Enabling trace information parsing", "bpf_loop_enabled", ebpfcommon.SupportsEBPFLoops(p.log, p.cfg.EBPF.OverrideBPFLoopEnabled))
	}

	spec, err := LoadBpf()
	if err != nil {
		return nil, fmt.Errorf("can't load bpf collection from reader: %w", err)
	}

	ebpfcommon.FixupSpec(spec, p.cfg.EBPF.OverrideBPFLoopEnabled)

	return []*ebpfcommon.SpecBundle{{Spec: spec, Objects: &p.bpfObjects, Constants: p.constants()}}, nil
}

// initCustomSpan builds per-tracer state for custom_span spans. Idempotent
// across calls — cookies are derived from the span index.
func (p *Tracer) initCustomSpan() {
	if p.customSpan != nil {
		return
	}
	if p.cfg == nil || !p.cfg.EBPF.CustomSpans.Enabled() {
		return
	}
	spans := p.cfg.EBPF.CustomSpans.Spans
	if len(spans) == 0 {
		return
	}

	ttl := p.cfg.EBPF.CustomSpans.TTL
	if ttl <= 0 {
		ttl = config.CustomSpanDefaultTTL
	}

	registry := NewCustomSpanRegistry()
	pairer := NewCustomSpanPairer(ttl)
	rt := &customSpanRuntime{
		registry: registry,
		pairer:   pairer,
		builder:  NewCustomSpanBuilder(registry, pairer),
		spans:    make([]customSpanBinding, 0, len(spans)),
	}

	for idx := range spans {
		cookie := uint64(idx) + 1
		spanCopy := spans[idx]
		rt.spans = append(rt.spans, customSpanBinding{cookie: cookie, span: spanCopy})
		registry.Register(NewCustomSpanDef(&spanCopy, cookie))
	}

	p.customSpan = rt
	p.log.Info("custom_span enabled",
		"spans", len(spans),
		"ttl", ttl,
	)
}

func (p *Tracer) SetupTailCalls() {
	p.initCustomSpan()
	// Order must match the k_tail_* enum in bpf/generictracer/k_tracer_tailcall.h
	for i, prog := range []*ebpf.Program{
		// HTTP/1
		p.bpfObjects.ObiProtocolHttp,           // 0  k_tail_protocol_http
		p.bpfObjects.ObiContinueProtocolHttp,   // 1  k_tail_continue_protocol_http
		p.bpfObjects.ObiContinue2ProtocolHttp,  // 2  k_tail_continue2_protocol_http
		p.bpfObjects.ObiContinueProtocolHttpTp, // 3  k_tail_continue_protocol_http_tp
		// TCP
		p.bpfObjects.ObiProtocolTcp, // 4  k_tail_protocol_tcp
		// generic
		p.bpfObjects.ObiHandleBufWithArgs, // 5  k_tail_handle_buf_with_args
		nil,                               // 6  k_tail_continue_netfd_read (gotracer-only)
		// HTTP/2 + gRPC
		p.bpfObjects.ObiProtocolHttp2,                                   // 7
		p.bpfObjects.ObiProtocolHttp2GrpcFrames,                         // 8
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrame,               // 9
		p.bpfObjects.ObiProtocolHttp2GrpcHandleEndFrame,                 // 10
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrameServer,         // 11
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrameServerFinalize, // 12
		// Large buffer multi-batch emission
		p.bpfObjects.ObiLargeBufEmitContinue, // 13  k_tail_large_buf_emit_continue
	} {
		if prog == nil {
			continue
		}
		p.log.Debug("loading program into tail call jump table", "index", i, "program", prog.String())
		if err := p.bpfObjects.JumpTable.Update(uint32(i), uint32(prog.FD()), ebpf.UpdateAny); err != nil {
			p.log.Error("error loading info tail call jump table", "error", err)
		}
	}
}

func (p *Tracer) constants() map[string]any {
	m := make(map[string]any, 2)

	m["wakeup_data_bytes"] = uint32(p.cfg.EBPF.WakeupLen) * uint32(unsafe.Sizeof(ebpfcommon.HTTPRequestTrace{}))

	// The eBPF side does some basic filtering of events that do not belong to
	// processes which we monitor. We filter more accurately in the userspace, but
	// for performance reasons we enable the PID based filtering in eBPF.
	// This must match httpfltr.go, otherwise we get partial events in userspace.
	if p.cfg.Discovery.BPFPidFilterOff {
		m["filter_pids"] = int32(0)
	} else {
		m["filter_pids"] = int32(1)
	}

	if p.cfg.EBPF.TrackRequestHeaders ||
		p.cfg.EBPF.ContextPropagation.IsEnabled() {
		m["capture_header_buffer"] = int32(1)
	} else {
		m["capture_header_buffer"] = int32(0)
	}

	if p.cfg.EBPF.HighRequestVolume {
		m["high_request_volume"] = uint32(1)
	} else {
		m["high_request_volume"] = uint32(0)
	}

	if p.cfg.EBPF.DisableBlackBoxCP {
		m["disable_black_box_cp"] = uint32(1)
	} else {
		m["disable_black_box_cp"] = uint32(0)
	}

	m["http_max_captured_bytes"] = p.cfg.EBPF.BufferSizes.HTTP
	m["tcp_max_captured_bytes"] = p.cfg.EBPF.BufferSizes.TCP
	m["mysql_max_captured_bytes"] = p.cfg.EBPF.BufferSizes.MySQL
	m["kafka_max_captured_bytes"] = p.cfg.EBPF.BufferSizes.Kafka
	m["postgres_max_captured_bytes"] = p.cfg.EBPF.BufferSizes.Postgres
	m["mssql_max_captured_bytes"] = p.cfg.EBPF.BufferSizes.MSSQL

	m["max_transaction_time"] = uint64(p.cfg.EBPF.MaxTransactionTime.Nanoseconds())

	m["g_bpf_debug"] = p.cfg.EBPF.BpfDebug
	m["g_bpf_traceparent_enabled"] = p.cfg.EBPF.TrackRequestHeaders || p.cfg.EBPF.ContextPropagation.IsEnabled()
	m["jvm_sampling_interval_ns"] = uint64(0)
	if p.cfg.JVMRuntimeMetrics.Enabled {
		m["jvm_sampling_interval_ns"] = uint64(p.cfg.JVMRuntimeMetrics.SamplingInterval.Nanoseconds())
	}
	m["has_attach_cookie"] = uint32(0)
	if ebpfcommon.HasAttachCookie() {
		m["has_attach_cookie"] = uint32(1)
	}

	return m
}

func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets) {}

func (p *Tracer) ProcessBinary(_ *exec.FileInfo) {}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	kp := map[string]ebpfcommon.ProbeDesc{
		// Both sys accept probes use the same kretprobe.
		// We could tap into __sys_accept4, but we might be more prone to
		// issues with the internal kernel code changing.
		"sys_accept": {
			Required: true,
			End:      p.bpfObjects.ObiKretprobeSysAccept4,
		},
		"sys_accept4": {
			Required: true,
			End:      p.bpfObjects.ObiKretprobeSysAccept4,
		},
		"security_socket_accept": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeSecuritySocketAccept,
		},
		// Tracking of HTTP client calls, by tapping into connect
		"sys_connect": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeSysConnect,
			End:      p.bpfObjects.ObiKretprobeSysConnect,
		},
		"sock_recvmsg": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeSockRecvmsg,
			End:      p.bpfObjects.ObiKretprobeSockRecvmsg,
		},
		"tcp_connect": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeTcpConnect,
		},
		"udp_sendmsg": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeUdpSendmsg,
		},
		"tcp_close": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeTcpClose,
		},
		"sock_def_error_report": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeSockDefErrorReport,
		},
		"tcp_sendmsg": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeTcpSendmsg,
			End:      p.bpfObjects.ObiKretprobeTcpSendmsg,
		},
		// Reading more than 160 bytes
		"tcp_recvmsg": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeTcpRecvmsg,
			End:      p.bpfObjects.ObiKretprobeTcpRecvmsg,
		},
		"tcp_cleanup_rbuf": {
			Start: p.bpfObjects.ObiKprobeTcpCleanupRbuf, // this kprobe runs the same code as recvmsg return, we use it because kretprobes can be unreliable.
		},
		"sys_clone": {
			Required: true,
			End:      p.bpfObjects.ObiKretprobeSysClone,
		},
		"sys_clone3": {
			Required: false,
			End:      p.bpfObjects.ObiKretprobeSysClone,
		},
		"sys_exit": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeSysExit,
		},
		"unix_stream_recvmsg": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeUnixStreamRecvmsg,
			End:      p.bpfObjects.ObiKretprobeUnixStreamRecvmsg,
		},
		"unix_stream_sendmsg": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeUnixStreamSendmsg,
			End:      p.bpfObjects.ObiKretprobeUnixStreamSendmsg,
		},
		"inet_csk_listen_stop": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeInetCskListenStop,
		},
		"sys_ioctl": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeSysIoctl,
		},
	}

	if p.cfg.EBPF.ContextPropagation.IsEnabled() {
		// tcp_rate_check_app_limited and tcp_sendmsg_fastopen are backup
		// for tcp_sendmsg_locked which doesn't fire on certain kernels
		// if sk_msg is attached.
		kp["tcp_rate_check_app_limited"] = ebpfcommon.ProbeDesc{
			Required: false,
			Start:    p.bpfObjects.ObiKprobeTcpRateCheckAppLimited,
		}
		kp["tcp_sendmsg_fastopen"] = ebpfcommon.ProbeDesc{
			Required: false,
			Start:    p.bpfObjects.ObiKprobeTcpRateCheckAppLimited,
		}
	}

	return kp
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	m := map[string]map[string][]*ebpfcommon.ProbeDesc{
		"libssl.so": {
			"SSL_read": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeSslRead,
				End:      p.bpfObjects.ObiUretprobeSslRead,
			}},
			"SSL_write": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeSslWrite,
				End:      p.bpfObjects.ObiUretprobeSslWrite,
			}},
			"SSL_read_ex": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeSslReadEx,
				End:      p.bpfObjects.ObiUretprobeSslReadEx,
			}},
			"SSL_write_ex2": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeSslWriteEx2,
				End:      p.bpfObjects.ObiUretprobeSslWriteEx2,
			}},
			"SSL_write_ex": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeSslWriteEx,
				End:      p.bpfObjects.ObiUretprobeSslWriteEx,
			}},
			"SSL_shutdown": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeSslShutdown,
			}},
		},
		"libSystem.Security.Cryptography.Native.OpenSsl.so": {
			"CryptoNative_SslRead": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeSslRead,
				End:      p.bpfObjects.ObiUretprobeSslRead,
			}},
			"CryptoNative_SslWrite": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeSslWrite,
				End:      p.bpfObjects.ObiUretprobeSslWrite,
			}},
			"CryptoNative_SslShutdown": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeSslShutdown,
			}},
		},
		"nginx": {
			"ngx_http_upstream_init": {{ // on upstream dispatch
				Required: false,
				Start:    p.bpfObjects.ObiNgxHttpUpstreamInit,
			}},
			"ngx_event_connect_peer": {{
				Required: false,
				End:      p.bpfObjects.ObiNgxEventConnectPeerRet,
			}},
		},
		"node": {
			"uv_fs_access": {{
				Required: false,
				Start:    p.bpfObjects.ObiUvFsAccess,
			}},
		},
		"libuv.so": {
			"uv_fs_access": {{
				Required: false,
				Start:    p.bpfObjects.ObiUvFsAccess,
			}},
		},
		"libruby": {
			"rb_ary_shift": {{
				Required: false,
				Start:    p.bpfObjects.ObiRbAryShift,
			}},
			"rb_obj_call_init_kw": {{
				Required: false,
				Start:    p.bpfObjects.ObiRbObjCallInitKw,
			}},
		},
		"libpython3.": {
			"context_run": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeContextRun,
				End:      p.bpfObjects.ObiUretprobeContextRun,
			}},
			"context_run.lto_priv.0": {{ // In Python 3.14, context_run has different symbols due to Link Time Optimization
				Required: false,
				Start:    p.bpfObjects.ObiUprobeContextRun,
				End:      p.bpfObjects.ObiUretprobeContextRun,
			}},
			"PyContext_CopyCurrent": {{
				Required: false,
				End:      p.bpfObjects.ObiUprobeCopyContext,
			}},
			"context_new_from_vars": {{ // In Docker, PyContext_CopyCurrent has Tail Recursion Optimization, so we need this function instead
				Required: false,
				End:      p.bpfObjects.ObiUprobeCopyContext,
			}},
		},
		"_asyncio": {
			"_asyncio_Task___init__": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeTaskInit,
				End:      p.bpfObjects.ObiUprobeTaskInitRet,
			}},
		},
		"_asyncio[< 3.12]": {
			"task_step": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeTaskStepLegacy,
				End:      p.bpfObjects.ObiUprobeTaskStepRet,
			}},
		},
		"_asyncio[>= 3.12]": {
			"task_step": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeTaskStep,
				End:      p.bpfObjects.ObiUprobeTaskStepRet,
			}},
		},
	}
	if p.cfg.JVMRuntimeMetrics.Enabled {
		m["libjvm.so"] = map[string][]*ebpfcommon.ProbeDesc{
			"report_gc_heap_summary": {{
				Required:      false,
				Start:         p.bpfObjects.ObiUprobeReportGcHeapSummary,
				SymbolMatcher: ebpfcommon.SymbolMatcherContains,
			}},
		}
	}
	return m
}

func (p *Tracer) USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc {
	if p.cfg == nil {
		return nil
	}
	out := map[string][]*ebpfcommon.USDTProbeDesc{}
	if p.cfg.JVMRuntimeMetrics.Enabled {
		out["libjvm.so"] = []*ebpfcommon.USDTProbeDesc{
			{
				Provider:    "hotspot",
				Name:        "mem__pool__gc__begin",
				Program:     p.bpfObjects.ObiUsdtHotspotMemPoolGcBegin,
				SpecsMap:    p.bpfObjects.ObiUsdtSpecs,
				IPMap:       p.bpfObjects.ObiUsdtIpToSpecId,
				SpecManager: &p.jvmUSDTManager,
			},
			{
				Provider:    "hotspot",
				Name:        "mem__pool__gc__end",
				Program:     p.bpfObjects.ObiUsdtHotspotMemPoolGcEnd,
				SpecsMap:    p.bpfObjects.ObiUsdtSpecs,
				IPMap:       p.bpfObjects.ObiUsdtIpToSpecId,
				SpecManager: &p.jvmUSDTManager,
			},
		}
	}
	if p.customSpan != nil {
		// One bucket under the auto-discover marker covers both static
		// stapsdt notes in the exe and libstapsdt-backed runtime .so's.
		out[ebpfcommon.USDTAutoDiscoverLib] = append(out[ebpfcommon.USDTAutoDiscoverLib], p.customSpanProbes()...)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// customSpanProbes expands every configured span into its
// USDTProbeDesc(s):
//   - paired USDT span → 2 descs (start+end) sharing a cookie
//   - single-shot USDT → 1 desc
//   - function-mode (Function:) → 1 desc, symbol-based uprobe at entry
//
// Pre-5.15 kernels lack bpf_get_attach_cookie, so BPF resolves specs via
// the IP map. Two custom_spans that target the same USDT probe (e.g.
// `cache.hit` and a `cache.match` variant) share an IP and the
// last-write-wins behavior masks one. We skip the match-filtered
// variant on those kernels so the unfiltered base probe attaches
// cleanly. Cookie-aware kernels keep both.
func (p *Tracer) customSpanProbes() []*ebpfcommon.USDTProbeDesc {
	if p.customSpan == nil {
		return nil
	}
	hasCookie := ebpfcommon.HasAttachCookie()
	specMgr := p.customSpanSpecMgr()
	specsMap := p.bpfObjects.ObiUsdtSpecs
	ipMap := p.bpfObjects.ObiUsdtIpToSpecId
	descs := make([]*ebpfcommon.USDTProbeDesc, 0, 2*len(p.customSpan.spans))
	for _, binding := range p.customSpan.spans {
		span := binding.span
		cookie := binding.cookie

		if !hasCookie && span.HasMatch() {
			continue
		}

		if span.IsAnyFunction() {
			descs = append(descs, p.functionModeProbe(&span, cookie, specMgr, specsMap, ipMap))
			continue
		}

		rewrite := obiebpf.MakeCustomSpanSpecRewrite(&span, cookie)
		switch {
		case span.IsUSDTSpan():
			descs = append(descs,
				p.usdtSpanProbe(span.USDTStartProbe(), p.bpfObjects.ObiCustomSpanStart, cookie, rewrite, specMgr, specsMap, ipMap),
				p.usdtSpanProbe(span.USDTEndProbe(), p.bpfObjects.ObiCustomSpanEnd, cookie, rewrite, specMgr, specsMap, ipMap),
			)
		case span.IsUSDTNoRet():
			descs = append(descs,
				p.usdtSpanProbe(span.USDTNoRetProbe(), p.bpfObjects.ObiCustomSpanEvent, cookie, rewrite, specMgr, specsMap, ipMap),
			)
		}
	}
	return descs
}

func (p *Tracer) functionModeProbe(span *config.CustomSpanSpec, cookie uint64,
	specMgr *ebpfcommon.USDTSpecManager, specsMap, ipMap *ebpf.Map,
) *ebpfcommon.USDTProbeDesc {
	isPaired := span.IsFunctionSpan()
	entryProg := p.bpfObjects.ObiCustomSpanEvent
	var retProg *ebpf.Program
	if isPaired {
		entryProg = p.bpfObjects.ObiCustomSpanStart
		retProg = p.bpfObjects.ObiCustomSpanFuncRet
	}
	builder := func(elfFile any) (any, error) {
		ef, _ := elfFile.(*elf.File)
		lang := obiebpf.FunctionLangC
		if ef != nil {
			lang = obiebpf.DetectFunctionLang(ef)
		}
		var (
			compiled obiebpf.CompiledCustomSpanSpec
			err      error
		)
		autoOK := false
		if lang == obiebpf.FunctionLangGo && ef != nil {
			var slots []obiebpf.AutoAttrSlot
			compiled, slots, err = obiebpf.BuildFunctionAutoSpec(ef, span, cookie, runtime.GOARCH)
			if err != nil {
				p.log.Debug("custom_span: auto attr extraction unavailable",
					"span", span.Name, "error", err)
			} else {
				autoOK = true
				if len(span.Attrs) > 0 {
					manual, mErr := obiebpf.BuildFunctionABISpec(span, cookie, runtime.GOARCH, lang)
					if mErr != nil {
						err = mErr
					} else {
						compiled, slots = obiebpf.MergeManualOverAuto(compiled, manual, slots)
					}
				}
				if err == nil && p.customSpan != nil {
					p.customSpan.registry.SetAutoSlots(cookie, slots)
				}
			}
		}
		if !autoOK {
			compiled, err = obiebpf.BuildFunctionABISpec(span, cookie, runtime.GOARCH, lang)
		}
		if err != nil {
			return nil, err
		}
		if isPaired {
			// Go yields the OS thread on I/O so TID-based pairing breaks
			// for any function that makes RPC/network calls. Pair on the
			// goroutine pointer instead (stable across goroutine moves).
			if lang == obiebpf.FunctionLangGo {
				compiled.Spec.PairKind = obiebpf.ObiUSDTPairG()
			} else {
				compiled.Spec.PairKind = obiebpf.ObiUSDTPairTid()
			}
		}
		return compiled.Spec, nil
	}
	return &ebpfcommon.USDTProbeDesc{
		Function:          span.FunctionSymbol(),
		BuildFunctionSpec: builder,
		Program:           entryProg,
		ReturnProgram:     retProg,
		SpecsMap:          specsMap,
		IPMap:             ipMap,
		SpecManager:       specMgr,
		Cookie:            cookie,
	}
}

func (p *Tracer) usdtSpanProbe(probeIdent string, program *ebpf.Program, cookie uint64,
	rewrite ebpfcommon.USDTSpecRewriter,
	specMgr *ebpfcommon.USDTSpecManager, specsMap, ipMap *ebpf.Map,
) *ebpfcommon.USDTProbeDesc {
	provider, name, _ := splitProbeIdent(probeIdent)
	return &ebpfcommon.USDTProbeDesc{
		Provider:    provider,
		Name:        name,
		Program:     program,
		SpecsMap:    specsMap,
		IPMap:       ipMap,
		SpecManager: specMgr,
		Cookie:      cookie,
		RewriteSpec: rewrite,
	}
}

// splitProbeIdent splits a "provider:name" identifier as validated by the
// config layer.
func splitProbeIdent(probe string) (string, string, bool) {
	return strings.Cut(probe, ":")
}

// handleCustomSpanRecord dispatches an EVENT_CUSTOM_SPAN ringbuf record. Returns
// (span, ready, handled, err): handled=true means the record was a custom_span
// event; ready=true means span is the completed result to emit.
func (p *Tracer) handleCustomSpanRecord(record *ringbuf.Record) (request.Span, bool, bool, error) {
	if p.customSpan == nil || record == nil || len(record.RawSample) == 0 {
		return request.Span{}, false, false, nil
	}
	if record.RawSample[0] != ebpfcommon.EventTypeCustomSpan {
		return request.Span{}, false, false, nil
	}

	ev, err := DecodeCustomSpanEvent(record.RawSample)
	if err != nil {
		p.log.Debug("custom_span: decode failed", "error", err)
		return request.Span{}, false, true, nil
	}
	span, ready, err := p.customSpan.builder.Build(ev)
	if err != nil {
		p.log.Debug("custom_span: build failed", "error", err)
		return request.Span{}, false, true, nil
	}
	return span, ready, true, nil
}

// customSpanEvictionLoop prunes pending start frames older than TTL.
func (p *Tracer) customSpanEvictionLoop(ctx context.Context) {
	if p.customSpan == nil {
		return
	}
	interval := p.cfg.EBPF.CustomSpans.TTL / 4
	if interval < 10*time.Second {
		interval = 10 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n := p.customSpan.pairer.EvictExpired(); n > 0 {
				p.log.Debug("custom_span: evicted stale pending starts", "count", n)
			}
		}
	}
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return []*ebpf.Program{p.bpfObjects.ObiSocketHttpFilter}
}

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg { return nil }

func (p *Tracer) SockOps() []ebpfcommon.SockOps { return nil }

func (p *Tracer) Iters() []*ebpfcommon.Iter {
	if len(p.iters) == 0 {
		p.iters = []*ebpfcommon.Iter{
			{
				Program: p.bpfObjects.ObiIterTcp,
			},
		}
	}

	return p.iters
}

func (p *Tracer) runItersForPids() {
	iters := p.Iters()
	if len(iters) == 0 {
		return
	}

	seen := make(map[uint64]struct{})

	for _, pids := range p.pidsFilter.CurrentPIDs(ebpfcommon.PIDTypeKProbes) {
		for pid := range pids {
			info, err := os.Stat(fmt.Sprintf("/proc/%d/ns/net", pid))
			if err != nil {
				p.log.Debug("netns stat failed", "pid", pid, "error", err)
				continue
			}

			inode := info.Sys().(*syscall.Stat_t).Ino
			if _, ok := seen[inode]; ok {
				continue
			}
			seen[inode] = struct{}{}

			for _, it := range iters {
				if err := netns.WithNetNS(int(pid), func() error {
					return it.Run(p.log)
				}); err != nil {
					p.log.Error("error running iterator in netns", "pid", pid, "error", err)
				}
			}
		}
	}
}

func (p *Tracer) Tracing() []*ebpfcommon.Tracing { return nil }

func (p *Tracer) RecordInstrumentedLib(id uint64, closers []io.Closer) {
	p.libsMux.Lock()
	defer p.libsMux.Unlock()

	module := p.instrumentedLibs.AddRef(id)

	if len(closers) > 0 {
		module.Closers = append(module.Closers, closers...)
	}

	p.log.Debug("Recorded instrumented Lib", "ino", id, "module", module)
}

func (p *Tracer) AddInstrumentedLibRef(id uint64) {
	p.RecordInstrumentedLib(id, nil)
}

func (p *Tracer) UnlinkInstrumentedLib(id uint64) {
	p.libsMux.Lock()
	defer p.libsMux.Unlock()

	module, err := p.instrumentedLibs.RemoveRef(id)

	p.log.Debug("Unlinking instrumented lib - before state", "ino", id, "module", module)

	if err != nil {
		p.log.Debug("Error unlinking instrumented lib", "ino", id, "error", err)
	}
}

func (p *Tracer) AlreadyInstrumentedLib(id uint64) bool {
	p.libsMux.Lock()
	defer p.libsMux.Unlock()

	module := p.instrumentedLibs.Find(id)

	p.log.Debug("checking already instrumented Lib", "ino", id, "module", module)
	return module != nil
}

func (p *Tracer) Run(
	ctx context.Context,
	ebpfEventContext *ebpfcommon.EBPFEventContext,
	eventsChan *msg.Queue[[]request.Span],
) {
	p.eventCtx = ebpfEventContext

	// Register custom_span dispatcher onto the shared EBPFEventContext so
	// gotracer can route EVENT_CUSTOM_SPAN records to us when it wins the
	// SharedRingBuffer slot.
	if p.customSpan != nil && ebpfEventContext != nil {
		ebpfEventContext.CustomSpanHandler = p.handleCustomSpanRecord
	}

	// At this point we now have loaded the bpf objects, which means we should insert any
	// pids that are allowed into the bpf map
	if p.bpfObjects.ValidPids != nil {
		p.rebuildValidPids()
	} else {
		p.log.Error("BPF Pids map is not created yet, this is a bug.")
	}

	timeoutTicker := time.NewTicker(2 * time.Second)
	parseContext := ebpfcommon.NewEBPFParseContext(&p.cfg.EBPF, eventsChan, p.pidsFilter)

	go p.watchForMisclassifedEvents(ctx)
	go p.lookForTimeouts(ctx, parseContext, timeoutTicker, eventsChan)
	go p.customSpanEvictionLoop(ctx)
	defer timeoutTicker.Stop()

	p.runItersForPids()

	p.log.Info("Launching p.Tracer")

	cfg := &p.cfg.EBPF
	if p.cfg.JVMRuntimeMetrics.Enabled {
		if p.runtimeMetricsSender() == nil {
			p.log.Warn("JVM runtime metrics enabled without runtime metrics queue")
		} else {
			p.log.Debug("reading JVM runtime metrics from shared ring buffer")
		}
	}

	ebpfcommon.SharedRingbuf(
		ebpfEventContext,
		cfg,
		p.bpfObjects.Events,
		func(record *ringbuf.Record) (request.Span, bool, error) {
			return p.processSharedRingbufRecord(ctx, parseContext, cfg, record)
		},
		p.pidsFilter.Filter,
		p.log,
		p.metrics,
	)(ctx, append(p.closers, &p.bpfObjects), eventsChan)
}

func (p *Tracer) processSharedRingbufRecord(
	ctx context.Context,
	parseContext *ebpfcommon.EBPFParseContext,
	cfg *config.EBPFTracer,
	record *ringbuf.Record,
) (request.Span, bool, error) {
	if handled, err := ebpfcommon.HandleRuntimeMetricsRecord(
		ctx,
		p.eventCtx,
		record,
		p.pidsFilter,
		p.log,
		p.handleJVMRuntimeMetricsRecord,
	); handled {
		return request.Span{}, true, err
	}

	if span, skip, ok, err := ebpfcommon.DispatchCustomSpan(p.eventCtx, record); ok {
		if skip {
			return request.Span{}, true, err
		}
		return span, false, err
	}

	s, ignore, err := ebpfcommon.ReadBPFTraceAsSpan(parseContext, cfg, record, p.pidsFilter)
	if !ignore && err == nil && !s.IsValid() {
		return s, true, nil
	}
	return s, ignore, err
}

func (p *Tracer) handleJVMRuntimeMetricsRecord(
	ctx context.Context,
	record *ringbuf.Record,
) (bool, error) {
	if record == nil || len(record.RawSample) == 0 {
		return false, nil
	}

	eventType := record.RawSample[0]
	switch eventType {
	case ebpfcommon.EventTypeJVMGCHeapSummary:
		if p.eventCtx == nil || p.eventCtx.RuntimeMetrics == nil {
			return true, nil
		}
		event, ignore, err := p.parseJVMGCHeapSummaryRecord(record)
		if err != nil || ignore {
			return true, err
		}
		p.eventCtx.RuntimeMetrics.SendJVMRuntimeMetrics(ctx, []jvmruntime.JVMRuntimeEvent{event})
		return true, nil
	case ebpfcommon.EventTypeJVMMemoryPoolGC:
		if p.eventCtx == nil || p.eventCtx.RuntimeMetrics == nil {
			return true, nil
		}
		events, ignore, err := p.parseJVMMemoryPoolRecord(record)
		if err != nil || ignore || len(events) == 0 {
			return true, err
		}
		p.eventCtx.RuntimeMetrics.SendJVMRuntimeMetrics(ctx, events)
		return true, nil
	default:
		return false, nil
	}
}

func (p *Tracer) runtimeMetricsSender() ebpfcommon.RuntimeMetricSender {
	if p.eventCtx == nil {
		return nil
	}
	return p.eventCtx.RuntimeMetrics
}

func (p *Tracer) parseJVMGCHeapSummaryRecord(record *ringbuf.Record) (jvmruntime.JVMRuntimeEvent, bool, error) {
	raw, err := ebpfcommon.ReinterpretCast[BpfJvmGcHeapSummaryEvent](record.RawSample)
	if err != nil {
		return jvmruntime.JVMRuntimeEvent{}, false, err
	}

	event, err := jvmruntime.ParseJVMGCHeapSummaryEvent(
		raw.Timestamp,
		raw.NsPid,
		raw.PidNsId,
		jvmruntime.RawJVMGCWhenType(raw.GcWhenType),
		raw.Used,
	)
	if err != nil {
		return jvmruntime.JVMRuntimeEvent{}, false, err
	}
	if !ebpfcommon.DecorateJVMRuntimeEvent(p.pidsFilter, &event) {
		return jvmruntime.JVMRuntimeEvent{}, true, nil
	}
	if p.log != nil {
		p.log.Debug("received JVM GC heap summary event",
			"pid", event.PID,
			"service", event.Service.UID.Name,
			"namespace", event.Service.UID.Namespace,
			"phase", event.GCPhase,
			"value_bytes", event.ValueBytes,
		)
	}
	return event, false, nil
}

func (p *Tracer) parseJVMMemoryPoolRecord(record *ringbuf.Record) ([]jvmruntime.JVMRuntimeEvent, bool, error) {
	raw, err := ebpfcommon.ReinterpretCast[BpfJvmMemPoolGcEvent](record.RawSample)
	if err != nil {
		return nil, false, err
	}

	events, err := jvmruntime.ParseJVMMemoryPoolEvent(
		raw.Timestamp,
		raw.NsPid,
		raw.PidNsId,
		jvmruntime.RawJVMGCWhenType(raw.GcWhenType),
		raw.Used,
		raw.Committed,
		raw.MaxSize,
		raw.Pool,
	)
	if err != nil {
		return nil, false, err
	}

	if len(events) == 0 {
		return nil, true, nil
	}

	// All events are fanned out from one raw sample and share PID identity.
	if !ebpfcommon.DecorateJVMRuntimeEvent(p.pidsFilter, &events[0]) {
		return nil, true, nil
	}
	for i := 1; i < len(events); i++ {
		events[i].Service = events[0].Service
	}

	if p.log != nil {
		p.log.Debug("received JVM memory pool event",
			"pid", events[0].PID,
			"service", events[0].Service.UID.Name,
			"namespace", events[0].Service.UID.Namespace,
			"pool", events[0].PoolName,
			"phase", events[0].GCPhase,
			"events", len(events),
		)
	}
	return events, false, nil
}

func kernelTime(ktime uint64) time.Time {
	now := time.Now()
	delta := timing.MonoTimeNow() - time.Duration(int64(ktime))

	return now.Add(-delta)
}

//nolint:cyclop
func (p *Tracer) lookForTimeouts(ctx context.Context, parseCtx *ebpfcommon.EBPFParseContext, ticker *time.Ticker, eventsChan *msg.Queue[[]request.Span]) {
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			if p.bpfObjects.OngoingHttp != nil {
				i := p.bpfObjects.OngoingHttp.Iterate()
				var k BpfPidConnectionInfoT
				var v BpfHttpInfoT
				for i.Next(&k, &v) {
					// Check if we have a lingering request which we've completed, as in it has EndMonotimeNs
					// but it hasn't been posted yet, likely missed by the logic that looks at finishing requests
					// where we track the full response. If we haven't updated the EndMonotimeNs in more than some
					// short interval, we are likely not going to finish this request from eBPF, so let's do it here.
					if v.EndMonotimeNs != 0 && v.Submitted == 0 && t.After(kernelTime(v.EndMonotimeNs).Add(10*time.Second)) {
						// Must use unsafe here, the two bpfHttpInfoTs are the same but generated from different
						// ebpf2go outputs
						s, ignore, err := ebpfcommon.HTTPInfoEventToSpan(parseCtx, (*ebpfcommon.BPFHTTPInfo)(unsafe.Pointer(&v)))
						if !ignore && err == nil {
							eventsChan.SendCtx(ctx, p.pidsFilter.Filter([]request.Span{s}))
						}
						if err := p.bpfObjects.OngoingHttp.Delete(k); err != nil {
							p.log.Debug("Error deleting ongoing request", "error", err)
						}
					} else if v.EndMonotimeNs == 0 && p.cfg.EBPF.HTTPRequestTimeout.Milliseconds() > 0 && t.After(kernelTime(v.StartMonotimeNs).Add(p.cfg.EBPF.HTTPRequestTimeout)) {
						// If we don't have a request finish with endTime by the configured request timeout, terminate the
						// waiting request with a timeout 408
						s, ignore, err := ebpfcommon.HTTPInfoEventToSpan(parseCtx, (*ebpfcommon.BPFHTTPInfo)(unsafe.Pointer(&v)))

						if !ignore && err == nil {
							s.Status = 408 // timeout
							if s.RequestStart == 0 {
								s.RequestStart = s.Start
							}
							s.End = s.Start + p.cfg.EBPF.HTTPRequestTimeout.Nanoseconds()

							eventsChan.SendCtx(ctx, p.pidsFilter.Filter([]request.Span{s}))
						}
						if err := p.bpfObjects.OngoingHttp.Delete(k); err != nil {
							p.log.Debug("Error deleting ongoing request", "error", err)
						}
					}
				}
			}
		}
	}
}

func (p *Tracer) watchForMisclassifedEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-ebpfcommon.MisclassifiedEvents:
			if e.EventType == ebpfcommon.EventTypeKHTTP2 {
				if p.bpfObjects.OngoingHttp2Connections != nil {
					err := p.bpfObjects.OngoingHttp2Connections.Put(
						&BpfPidConnectionInfoT{Conn: bpfConnInfoT(e.TCPInfo.ConnInfo), Pid: e.TCPInfo.Pid.HostPid},
						BpfHttp2ConnInfoDataT{Flags: e.TCPInfo.Ssl, Id: 0}, // no new connection flag (0x3)
					)
					if err != nil {
						p.log.Debug("error writing HTTP2/gRPC connection info", "error", err)
					}
				}
			}
		}
	}
}

// Cilium 0.19.0+ is adding a new private field to all the BpfConnectionInfoT
// implementations, so we can't directly do a type cast
func bpfConnInfoT(src ebpfcommon.BpfConnectionInfoT) (dst BpfConnectionInfoT) {
	dst.D_port = src.D_port
	dst.D_addr = src.D_addr
	dst.S_addr = src.S_addr
	dst.S_port = src.S_port
	return
}

func (p *Tracer) SetEventContext(ctx *ebpfcommon.EBPFEventContext) { p.eventCtx = ctx }

func (p *Tracer) Capabilities() ebpfcommon.TracerCapability { return 0 }

func (p *Tracer) Required() bool {
	return true
}
