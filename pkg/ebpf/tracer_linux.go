// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	common "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func ptlog() *slog.Logger { return slog.With("component", "ebpf.ProcessTracer") }

type instrumenter struct {
	offsets     *goexec.Offsets
	exe         *link.Executable
	closables   []io.Closer
	modules     map[uint64]struct{}
	metrics     imetrics.Reporter
	processName string
}

func loadSpec(eventContext *common.EBPFEventContext, bundle *common.SpecBundle, otelBPFFSPath string, idx int) error {
	if err := ebpfconvenience.LoadSpec(
		bundle.Spec,
		bundle.Objects,
		bundle.Constants,
		eventContext.EBPFMaps,
		&eventContext.MapsLock,
		otelBPFFSPath,
	); err != nil {
		return fmt.Errorf("loading spec %d: %w", idx, err)
	}

	return nil
}

func closeLoadedSpecs(bundles []*common.SpecBundle) {
	for _, bundle := range bundles {
		if c, ok := bundle.Objects.(io.Closer); ok {
			c.Close()
		}
	}
}

func unloadInternalMaps(eventContext *common.EBPFEventContext) {
	eventContext.MapsLock.Lock()
	defer eventContext.MapsLock.Unlock()

	for _, v := range eventContext.EBPFMaps {
		v.Close()
	}

	eventContext.EBPFMaps = make(map[string]*ebpf.Map)
}

func NewProcessTracer(tracerType ProcessTracerType, programs []Tracer, cfg *obi.Config, metrics imetrics.Reporter) *ProcessTracer {
	return &ProcessTracer{
		Programs:        programs,
		Type:            tracerType,
		Instrumentables: map[uint64]*instrumenter{},
		shutdownTimeout: cfg.ShutdownTimeout,
		metrics:         metrics,
		bpffsPath:       cfg.EBPF.BPFFSPath,
	}
}

type tracerInstance struct {
	implType string
	done     atomic.Bool
}

func (pt *ProcessTracer) Run(ctx context.Context, ebpfEventContext *common.EBPFEventContext, out *msg.Queue[[]request.Span]) {
	pt.log = ptlog().With("type", pt.Type)

	pt.log.Debug("starting process tracer")
	// Searches for traceable functions
	trcrs := pt.Programs
	wg := sync.WaitGroup{}
	runningTracers := make([]tracerInstance, 0, len(trcrs))
	for i := range trcrs {
		idx := i
		t := trcrs[idx]
		wg.Add(1)
		runningTracers = append(runningTracers, tracerInstance{
			implType: reflect.TypeOf(t).String(),
		})
		go func() {
			defer wg.Done()
			t.Run(ctx, ebpfEventContext, out)
			runningTracers[idx].done.Store(true)
		}()
	}

	<-ctx.Done()

	tracersEnded := make(chan struct{})
	go func() {
		wg.Wait()
		close(tracersEnded)
	}()
	unloadInternalMaps(ebpfEventContext)

	hasWarned := false
	for {
		select {
		// notifying before OBI times out on finish
		case <-time.After(3 * pt.shutdownTimeout / 4):
			pt.log.Warn("some process tracers did not finish", "tracers", runningTracers)
			hasWarned = true
		case <-tracersEnded:
			if hasWarned {
				pt.log.Info("all process tracers finished")
			}
			return
		}
	}
}

func (pt *ProcessTracer) makeOtelBPFFSPath() (string, error) {
	otelPath := path.Join(pt.bpffsPath, "otel")

	if err := os.MkdirAll(otelPath, 0o1700); err != nil {
		return "", fmt.Errorf("creating bpffs otel path: %w", err)
	}

	return otelPath, nil
}

func (pt *ProcessTracer) setupOtelBPFFSPath(bundles []*common.SpecBundle) string {
	// Set up BPF FS path once for all specs
	otelBPFFSPath, err := pt.makeOtelBPFFSPath()

	if err == nil {
		return otelBPFFSPath
	}

	log := ptlog()

	log.Warn("creating OTEL namespace in bpffs failed (is bpffs mounted?)",
		"bpffs_path", pt.bpffsPath, "err", err)

	log.Warn("OBI will still work, but features depending on pinned maps (e.g., log enricher, profile correlation) will be disabled")

	// disable pinning for ALL specs
	for _, bundle := range bundles {
		for _, v := range bundle.Spec.Maps {
			if v.Pinning == ebpf.PinByName {
				v.Pinning = ebpf.PinNone
				v.MaxEntries = 1
			}
		}
	}

	return ""
}


func (pt *ProcessTracer) setupBPFMapSizes(spec *ebpf.CollectionSpec, cfg *obi.Config) {
	fmt.Println("pino setupBPFMapSizes")

	mapSizes := pt.getRuntimeMapSizes(cfg)

	for name, m := range spec.Maps {
		if newSize, shouldOverride := mapSizes[name]; shouldOverride {
			m.MaxEntries = newSize
			fmt.Println("pino setupBPFMapSizes FOUND IT name: ", name)
		}
	}
}

func (pt *ProcessTracer) loadAndAssign(eventContext *common.EBPFEventContext, p Tracer, cfg *obi.Config) error {
	spec, err := pt.loadSpec(p)
	if err != nil {
		return fmt.Errorf("loading eBPF program specs: %w", err)
	}

	otelBPFFSPath := pt.setupOtelBPFFSPath(bundles)

	for i, bundle := range bundles {
		if err := loadSpec(eventContext, bundle, otelBPFFSPath, i); err != nil {
			closeLoadedSpecs(bundles[:i])
			return err
		}
	// set max entries map using user defined values
	pt.setupBPFMapSizes(spec, cfg)

	collOpts, err := resolveMaps(eventContext, spec)
	if err != nil {
		return err
	}

	return nil
}

func (pt *ProcessTracer) loadTracer(eventContext *common.EBPFEventContext, p Tracer, log *slog.Logger, cfg *obi.Config) error {
	plog := log.With("program", reflect.TypeOf(p))
	plog.Debug("loading eBPF program", "type", pt.Type)

	err := pt.loadAndAssign(eventContext, p, cfg)

	if err != nil && (strings.Contains(err.Error(), "unknown func bpf_probe_write_user") ||
		strings.Contains(err.Error(), "cannot use helper bpf_probe_write_user")) {
		plog.Warn("Failed to enable Go write memory distributed tracing context-propagation" +
			"and/or log enricher on a Linux Kernel without write memory support. " +
			"To avoid seeing this message, please ensure you have correctly mounted /sys/kernel/security " +
			"and ensure OBI has the SYS_ADMIN linux capability. " +
			"For more details set OTEL_EBPF_LOG_LEVEL=DEBUG.")

		common.IntegrityModeOverride = true
		err = pt.loadAndAssign(eventContext, p, cfg)
	}

	if err != nil {
		printVerifierErrorInfo(err)
		return fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	// Setup any tail call jump tables
	p.SetupTailCalls()

	i := instrumenter{} // dummy instrumenter to setup the kprobes, socket filters and tracepoint probes

	// Kprobes to be used for native instrumentation points
	if err := i.kprobes(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	// Tracepoints support
	if err := i.tracepoints(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	// Sock filters support
	if err := i.sockfilters(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	// Sock_msg support
	if err := i.sockmsgs(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	// Sockops support
	if err := i.sockops(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	if err := i.iters(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	if err := i.tracing(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	return nil
}

func (pt *ProcessTracer) loadTracers(eventContext *common.EBPFEventContext, cfg *obi.Config) error {
	eventContext.LoadLock.Lock()
	defer eventContext.LoadLock.Unlock()

	log := ptlog()

	loadedPrograms := make([]Tracer, 0, len(pt.Programs))

	for _, p := range pt.Programs {
		if err := pt.loadTracer(eventContext, p, log, cfg); err != nil {
			log.Warn("couldn't load tracer", "error", err, "required", p.Required())
			if p.Required() {
				return err
			}
		} else {
			loadedPrograms = append(loadedPrograms, p)
		}
	}

	pt.Programs = loadedPrograms

	btf.FlushKernelSpec()

	return nil
}

func (pt *ProcessTracer) Init(eventContext *common.EBPFEventContext, cfg *obi.Config) error {
	return pt.loadTracers(eventContext, cfg)
}

func (pt *ProcessTracer) NewExecutableInstance(ie *Instrumentable) error {
	if i, ok := pt.Instrumentables[ie.FileInfo.Ino]; ok {
		for _, p := range pt.Programs {
			p.ProcessBinary(ie.FileInfo)
			// Uprobes to be used for native module instrumentation points
			if err := i.uprobes(ie.FileInfo.Pid, p); err != nil {
				printVerifierErrorInfo(err)
				return err
			}
		}
	} else {
		pt.log.Warn("Attempted to update non-existent tracer", "path", ie.FileInfo.CmdExePath, "pid", ie.FileInfo.Pid)
	}

	return nil
}

func (pt *ProcessTracer) NewExecutable(exe *link.Executable, ie *Instrumentable) error {
	i := instrumenter{
		exe:         exe,
		offsets:     ie.Offsets, // this is needed for the function offsets, not fields
		modules:     map[uint64]struct{}{},
		metrics:     pt.metrics,
		processName: ie.FileInfo.CmdExePath,
	}

	for _, p := range pt.Programs {
		p.RegisterOffsets(ie.FileInfo, ie.Offsets)

		// Go style Uprobes
		if err := i.goprobes(p); err != nil {
			printVerifierErrorInfo(err)
			return err
		}

		// Uprobes to be used for native module instrumentation points
		if err := i.uprobes(ie.FileInfo.Pid, p); err != nil {
			printVerifierErrorInfo(err)
			return err
		}
	}

	pt.Instrumentables[ie.FileInfo.Ino] = &i

	return nil
}

func (pt *ProcessTracer) UnlinkExecutable(info *exec.FileInfo) {
	if i, ok := pt.Instrumentables[info.Ino]; ok {
		for _, c := range i.closables {
			if err := c.Close(); err != nil {
				pt.log.Debug("Unable to close on unlink", "closable", c)
			}
		}
		for ino := range i.modules {
			for _, p := range pt.Programs {
				p.UnlinkInstrumentedLib(ino)
			}
		}
		delete(pt.Instrumentables, info.Ino)
	} else {
		pt.log.Warn("Unable to find executable to unlink",
			"path", info.CmdExePath,
			"pid", info.Pid,
			"inode", info.Ino)
	}
}

func printVerifierErrorInfo(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		_, _ = fmt.Fprintf(os.Stderr, "Error Log:\n %v\n", strings.Join(ve.Log, "\n"))
	}
}

func RunUtilityTracer(ctx context.Context, eventContext *common.EBPFEventContext, p UtilityTracer) error {
	i := instrumenter{}
	plog := ptlog()
	plog.Debug("loading independent eBPF program")

	bundles, err := p.LoadSpecs()
	if err != nil {
		return fmt.Errorf("loading eBPF program specs: %w", err)
	}

	for idx, bundle := range bundles {
		if err := loadSpec(eventContext, bundle, "", idx); err != nil {
			closeLoadedSpecs(bundles[:idx])
			printVerifierErrorInfo(err)
			return err
		}
	}

	if err := i.kprobes(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	if err := i.tracepoints(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	go p.Run(ctx)

	btf.FlushKernelSpec()

	return nil
}

func (pt *ProcessTracer) getRuntimeMapSizes(cfg *obi.Config) map[string]uint32 {
	return map[string]uint32{
		// override DEFAULT_MAX_CONCURRENT_REQUESTS
		"listening_ports":                   cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"active_unix_socks":                 cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"incoming_trace_map":                cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"nginx_upstream":                    cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"outgoing_trace_map":                cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"go_ongoing_http":                   cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"pq_hostnames":                      cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"go_ongoing_http_client_requests":   cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"java_tasks":                        cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"protocol_cache":                    cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"puma_task_connections":             cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"puma_worker_tasks":                 cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"active_send_args":                  cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"active_send_sock_args":             cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"ssl_to_pid_tid":                    cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"active_accept_args":                cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"active_recv_args":                  cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"active_connect_args":               cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"ongoing_http2_connections":         cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"upstream_init_args":                cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"kafka_state":                       cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"kafka_ongoing_requests":            cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"mysql_state":                       cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"produce_traceparents":              cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"ongoing_produce_topics":            cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"ongoing_produce_messages":          cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"produce_requests":                  cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"fetch_requests":                    cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"ongoing_client_connections":        cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"ongoing_grpc_operate_headers":      cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"ongoing_grpc_transports":           cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"ongoing_sql_queries":               cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"ongoing_mongo_requests":            cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"newproc1":                          cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"ongoing_http_client_requests_data": cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"http2_server_requests_tp":          cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"ongoing_http_server_requests":      cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"header_req_map":                    cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"http2_req_map":                     cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"framer_invocation_map":             cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"span_names":                        cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"ongoing_redis_requests":            cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"redis_writes":                      cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"kafka_requests":                    cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"ongoing_kafka_requests":            cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"ongoing_grpc_request_status":       cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"ongoing_grpc_client_requests":      cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"ongoing_grpc_server_requests":      cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"cached_grpc_client_connections":    cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"ongoing_streams":                   cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"ongoing_grpc_header_writes":        cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"transport_new_client_invocations":  cfg.EBPF.MapSizes.MaxConcurrentRequests,
		"grpc_framer_invocation_map":        cfg.EBPF.MapSizes.MaxConcurrentRequests,
		// override DEFAULT_MAX_CONCURRENT_SHARED_REQUESTS
		"ssl_to_conn":                cfg.EBPF.MapSizes.MaxConcurrentSharedRequests,
		"server_traces":              cfg.EBPF.MapSizes.MaxConcurrentSharedRequests,
		"server_traces_aux":          cfg.EBPF.MapSizes.MaxConcurrentSharedRequests,
		"clone_map":                  cfg.EBPF.MapSizes.MaxConcurrentSharedRequests,
		"fd_to_connection":           cfg.EBPF.MapSizes.MaxConcurrentSharedRequests,
		"active_ssl_connections":     cfg.EBPF.MapSizes.MaxConcurrentSharedRequests,
		"accepted_connections":       cfg.EBPF.MapSizes.MaxConcurrentSharedRequests,
		"fd_map":                     cfg.EBPF.MapSizes.MaxConcurrentSharedRequests,
		"cp_support_connect_info":    cfg.EBPF.MapSizes.MaxConcurrentSharedRequests,
		"ongoing_http":               cfg.EBPF.MapSizes.MaxConcurrentSharedRequests,
		"trace_map":                  cfg.EBPF.MapSizes.MaxConcurrentSharedRequests,
		"ongoing_tcp_req":            cfg.EBPF.MapSizes.MaxConcurrentSharedRequests,
		"ongoing_http2_grpc":         cfg.EBPF.MapSizes.MaxConcurrentSharedRequests,
		"pid_tid_to_conn":            cfg.EBPF.MapSizes.MaxConcurrentSharedRequests,
		"ongoing_goroutines":         cfg.EBPF.MapSizes.MaxConcurrentSharedRequests,
		"ongoing_server_connections": cfg.EBPF.MapSizes.MaxConcurrentSharedRequests,
		"go_trace_map":               cfg.EBPF.MapSizes.MaxConcurrentSharedRequests,
		// override DEFAULT_MAX_CONCURRENT_CUSTOM_SPANS
		"active_spans": cfg.EBPF.MapSizes.MaxConcurrentCustomSpans,
	}
}
