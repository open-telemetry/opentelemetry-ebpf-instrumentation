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
	key                   ExecutableKey
	references            uint64
	offsets               *goexec.Offsets
	exe                   *link.Executable
	closables             []io.Closer
	processScopedGoProbes []processScopedGoProbeRegistration
	modules               []instrumentedModule
	metrics               imetrics.Reporter
	processName           string
	attachUprobe          func(
		*link.Executable,
		*common.ProbeDesc,
	) ([]io.Closer, error)
}

type instrumentedModule struct {
	tracer Tracer
	inode  uint64
}

type processRegistrationRollback interface {
	RollbackProcessRegistration(*exec.FileInfo)
}

func loadSpec(eventContext *common.EBPFEventContext, bundle *common.SpecBundle, otelBPFFSPath string, idx int, cache *btf.Cache) error {
	if err := ebpfconvenience.LoadSpec(
		bundle.Spec,
		bundle.Objects,
		bundle.Constants,
		eventContext.EBPFMaps,
		&eventContext.MapsLock,
		otelBPFFSPath,
		cache,
	); err != nil {
		return fmt.Errorf("loading spec %d: %w", idx, err)
	}
	eventContext.NotifyOutgoingTraceHandoffMapsLoaded()

	return nil
}

func closeLoadedSpecs(bundles []*common.SpecBundle) {
	for _, bundle := range bundles {
		if c, ok := bundle.Objects.(io.Closer); ok {
			_ = c.Close()
		}
	}
}

func unloadInternalMaps(eventContext *common.EBPFEventContext) {
	eventContext.MapsLock.Lock()
	defer eventContext.MapsLock.Unlock()

	for _, bpfMap := range eventContext.EBPFMaps {
		if bpfMap != nil {
			_ = bpfMap.Close()
		}
	}

	eventContext.EBPFMaps = make(map[string]*ebpf.Map)
}

func NewProcessTracer(tracerType ProcessTracerType, programs []Tracer, cfg *obi.Config, metrics imetrics.Reporter) *ProcessTracer {
	return &ProcessTracer{
		Programs:                  programs,
		Type:                      tracerType,
		Instrumentables:           map[ExecutableKey]*instrumenter{},
		instrumentableGenerations: map[ExecutableKey]uint64{},
		shutdownTimeout:           cfg.ShutdownTimeout,
		metrics:                   metrics,
		bpffsPath:                 cfg.EBPF.BPFFSPath,
	}
}

type tracerInstance struct {
	implType string
	done     atomic.Bool
}

func (pt *ProcessTracer) Run(
	ctx context.Context,
	ebpfEventContext *common.EBPFEventContext,
	out *msg.Queue[[]request.Span],
) {
	pt.log = ptlog().With("type", pt.Type)

	pt.log.Debug("starting process tracer")
	releaseHandoffReaper := ebpfEventContext.StartOutgoingTraceHandoffReaper()
	defer releaseHandoffReaper()

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
		pt.waitForResourceTeardown()
		close(tracersEnded)
	}()

	hasWarned := false
	for {
		select {
		// notifying before OBI times out on finish
		case <-time.After(3 * pt.shutdownTimeout / 4):
			pt.log.Warn("some process tracers did not finish", "tracers", runningTracers)
			hasWarned = true
		case <-tracersEnded:
			if pt.resourceTeardownReady() {
				pt.closeInstrumentables()
			} else {
				ebpfEventContext.RetainResources()
				pt.log.Error("retaining eBPF resources after unsafe tracer shutdown")
			}
			if hasWarned {
				pt.log.Info("all process tracers finished")
			}
			return
		}
	}
}

func ShutdownSharedMaps(eventContext *common.EBPFEventContext) {
	if eventContext == nil {
		return
	}
	eventContext.StopOutgoingTraceHandoffReaper()
	if eventContext.ResourcesRetained() {
		return
	}
	unloadInternalMaps(eventContext)
}

func (pt *ProcessTracer) resourceTeardownReady() bool {
	for _, program := range pt.Programs {
		if readiness, ok := program.(ResourceTeardownReadiness); ok &&
			!readiness.ResourceTeardownReady() {
			return false
		}
	}
	return true
}

func (pt *ProcessTracer) waitForResourceTeardown() {
	for _, program := range pt.Programs {
		if waiter, ok := program.(ResourceTeardownWaiter); ok {
			waiter.WaitForResourceTeardown()
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

func setupBPFMapSizes(spec *ebpf.CollectionSpec, cfg *obi.Config) {
	ebpfconvenience.SetupMapSizes(spec, cfg.EBPF.MapsConfig.GlobalScaleFactor)
}

func (pt *ProcessTracer) loadAndAssign(
	eventContext *common.EBPFEventContext,
	p Tracer,
	cfg *obi.Config,
	cache *btf.Cache,
) error {
	p.SetEventContext(eventContext)

	bundles, err := p.LoadSpecs()
	if err != nil {
		return fmt.Errorf("loading eBPF program specs: %w", err)
	}

	otelBPFFSPath := pt.setupOtelBPFFSPath(bundles)

	for i, bundle := range bundles {
		// set max entries map using user defined values
		setupBPFMapSizes(bundle.Spec, cfg)

		if err := loadSpec(eventContext, bundle, otelBPFFSPath, i, cache); err != nil {
			closeLoadedSpecs(bundles[:i])
			return err
		}
	}

	return nil
}

func (pt *ProcessTracer) loadTracer(
	eventContext *common.EBPFEventContext,
	p Tracer,
	log *slog.Logger,
	cfg *obi.Config,
	cache *btf.Cache,
) error {
	plog := log.With("program", reflect.TypeOf(p))
	plog.Debug("loading eBPF program", "type", pt.Type)

	err := pt.loadAndAssign(eventContext, p, cfg, cache)

	if err != nil && (strings.Contains(err.Error(), "unknown func bpf_probe_write_user") ||
		strings.Contains(err.Error(), "cannot use helper bpf_probe_write_user")) {
		plog.Warn("Failed to enable Go write memory distributed tracing context-propagation " +
			"and/or log enricher on a Linux Kernel without write memory support. " +
			"To avoid seeing this message, please ensure you have correctly mounted /sys/kernel/security " +
			"and ensure OBI has the SYS_ADMIN linux capability. " +
			"For more details set OTEL_EBPF_LOG_LEVEL=DEBUG.")

		common.IntegrityModeOverride = true
		err = pt.loadAndAssign(eventContext, p, cfg, cache)
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
	i.sockops(p)

	if err := i.iters(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	if err := i.tracing(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	p.AddCloser(i.closables...)

	return nil
}

func (pt *ProcessTracer) loadTracers(eventContext *common.EBPFEventContext, cfg *obi.Config) error {
	eventContext.LoadLock.Lock()
	defer eventContext.LoadLock.Unlock()

	log := ptlog()

	loadedPrograms := make([]Tracer, 0, len(pt.Programs))

	cache := btf.NewCache()

	for _, p := range pt.Programs {
		if err := pt.loadTracer(eventContext, p, log, cfg, cache); err != nil {
			log.Warn("couldn't load tracer", "error", err, "required", p.Required())
			if p.Required() {
				return err
			}
		} else {
			loadedPrograms = append(loadedPrograms, p)
			eventContext.Capabilities |= p.Capabilities()
		}
	}

	pt.Programs = loadedPrograms

	return nil
}

func (pt *ProcessTracer) Init(eventContext *common.EBPFEventContext, cfg *obi.Config) error {
	return pt.loadTracers(eventContext, cfg)
}

func (pt *ProcessTracer) NewExecutableInstance(
	ie *Instrumentable,
) (_ *ExecutableInstanceUpdate, retErr error) {
	if ie == nil || ie.FileInfo == nil {
		return &ExecutableInstanceUpdate{}, nil
	}

	key := ExecutableKey{Dev: ie.FileInfo.Dev(), Ino: ie.FileInfo.Ino()}
	pt.instrumentablesMu.Lock()
	locked := true
	defer func() {
		if locked {
			pt.instrumentablesMu.Unlock()
		}
	}()

	if i, ok := pt.Instrumentables[key]; ok {
		ie.ExecutableGeneration = pt.instrumentableGenerations[key]
		closablesBefore := len(i.closables)
		modulesBefore := len(i.modules)
		published := false
		defer func() {
			if !published {
				retErr = errors.Join(
					retErr,
					rollbackInstrumenterUpdate(i, closablesBefore, modulesBefore),
				)
			}
		}()
		maps, err := processMaps(ie.FileInfo.Pid())
		if err != nil {
			return nil, err
		}
		for _, p := range pt.Programs {
			// Uprobes to be used for native module instrumentation points
			if err := i.uprobes(ie.FileInfo.Pid(), p, maps); err != nil {
				printVerifierErrorInfo(err)
				return nil, err
			}
			if err := i.usdtProbes(ie.FileInfo.Pid(), ie.FileInfo.Ns(), p, maps); err != nil {
				printVerifierErrorInfo(err)
				return nil, err
			}
		}

		update := pt.newExecutableInstanceUpdateLocked(
			ie.FileInfo,
			i,
			closablesBefore,
			modulesBefore,
		)
		published = true
		locked = false
		return update, nil
	} else {
		pt.log.Warn("Attempted to update non-existent tracer", "path", ie.FileInfo.CmdExePath(), "pid", ie.FileInfo.Pid())
	}

	return &ExecutableInstanceUpdate{}, nil
}

func (pt *ProcessTracer) newExecutableInstanceUpdateLocked(
	fileInfo *exec.FileInfo,
	i *instrumenter,
	closablesBefore int,
	modulesBefore int,
) *ExecutableInstanceUpdate {
	return &ExecutableInstanceUpdate{finalize: func(commit bool) {
		defer pt.instrumentablesMu.Unlock()
		if commit {
			for _, p := range pt.Programs {
				p.ProcessBinary(fileInfo)
			}
			return
		}
		if err := rollbackInstrumenterUpdate(i, closablesBefore, modulesBefore); err != nil {
			log := pt.log
			if log == nil {
				log = ptlog().With("type", pt.Type)
			}
			log.Debug("rolling back executable instance update failed", "error", err)
		}
	}}
}

func rollbackInstrumenterUpdate(
	i *instrumenter,
	closablesBefore int,
	modulesBefore int,
) error {
	if i == nil {
		return nil
	}
	if closablesBefore < 0 || closablesBefore > len(i.closables) ||
		modulesBefore < 0 || modulesBefore > len(i.modules) {
		return errors.New("invalid executable instance update snapshot")
	}

	var cleanupErr error
	for closerIndex := len(i.closables) - 1; closerIndex >= closablesBefore; closerIndex-- {
		if closer := i.closables[closerIndex]; closer != nil {
			cleanupErr = errors.Join(cleanupErr, closer.Close())
		}
	}
	for moduleIndex := len(i.modules) - 1; moduleIndex >= modulesBefore; moduleIndex-- {
		module := i.modules[moduleIndex]
		module.tracer.UnlinkInstrumentedLib(module.inode)
	}
	i.closables = i.closables[:closablesBefore]
	i.modules = i.modules[:modulesBefore]
	return cleanupErr
}

func (pt *ProcessTracer) NewExecutable(
	exe *link.Executable,
	ie *Instrumentable,
) (err error) {
	if ie == nil || ie.FileInfo == nil {
		return errors.New("missing executable file information")
	}

	pt.instrumentablesMu.Lock()
	defer pt.instrumentablesMu.Unlock()
	if pt.reuseGoInstrumenterLocked(ie) {
		return nil
	}

	i := instrumenter{
		key:         ExecutableKey{Dev: ie.FileInfo.Dev(), Ino: ie.FileInfo.Ino()},
		exe:         exe,
		offsets:     ie.Offsets, // this is needed for the function offsets, not fields
		metrics:     pt.metrics,
		processName: ie.FileInfo.ExecutableName(),
	}
	published := false
	registeredPrograms := make([]Tracer, 0, len(pt.Programs))
	defer func() {
		if !published {
			for index := len(registeredPrograms) - 1; index >= 0; index-- {
				if rollback, ok := registeredPrograms[index].(processRegistrationRollback); ok {
					rollback.RollbackProcessRegistration(ie.FileInfo)
				}
			}
			err = errors.Join(err, pt.closeInstrumenter(&i))
		}
	}()

	maps, err := processMaps(ie.FileInfo.Pid())
	if err != nil {
		return err
	}

	for _, p := range pt.Programs {
		p.RegisterOffsets(ie.FileInfo, ie.Offsets)
		registeredPrograms = append(registeredPrograms, p)

		// Go style Uprobes
		if err := i.goprobes(ie.FileInfo, p); err != nil {
			printVerifierErrorInfo(err)
			return err
		}

		// Uprobes to be used for native module instrumentation points
		if err := i.uprobes(ie.FileInfo.Pid(), p, maps); err != nil {
			printVerifierErrorInfo(err)
			return err
		}

		if err := i.usdtProbes(ie.FileInfo.Pid(), ie.FileInfo.Ns(), p, maps); err != nil {
			printVerifierErrorInfo(err)
			return err
		}
	}
	pt.commitInstrumenterLocked(&i, ie)
	published = true

	return nil
}

func (pt *ProcessTracer) commitInstrumenter(i *instrumenter, ie *Instrumentable) {
	pt.instrumentablesMu.Lock()
	defer pt.instrumentablesMu.Unlock()
	pt.commitInstrumenterLocked(i, ie)
}

func (pt *ProcessTracer) commitInstrumenterLocked(i *instrumenter, ie *Instrumentable) {
	if previous := pt.Instrumentables[i.key]; previous != nil {
		if previous == i {
			ie.ExecutableGeneration = pt.recordExecutableGeneration(i.key)
			return
		}
		pt.removeInstrumenterReference(i.key, previous)
	}
	if pt.Instrumentables == nil {
		pt.Instrumentables = map[ExecutableKey]*instrumenter{}
	}
	pt.Instrumentables[i.key] = i
	i.references++
	ie.ExecutableGeneration = pt.recordExecutableGeneration(i.key)
	i.registerProcessScopedGoProbes(i.key)
}

func (pt *ProcessTracer) reuseGoInstrumenterLocked(ie *Instrumentable) bool {
	if pt.Type != Go {
		return false
	}

	key := ExecutableKey{Dev: ie.FileInfo.Dev(), Ino: ie.FileInfo.Ino()}
	i := pt.Instrumentables[key]
	if i == nil {
		return false
	}

	// The exact executable is already instrumented. Rotate only its event
	// generation; sharing by inode alone is unsafe across devices because the
	// executable and its Go ABI metadata may be unrelated.
	ie.ExecutableGeneration = pt.recordExecutableGeneration(key)
	return true
}

func (pt *ProcessTracer) recordExecutableGeneration(key ExecutableKey) uint64 {
	pt.nextExecutableGeneration++
	if pt.nextExecutableGeneration == 0 {
		pt.nextExecutableGeneration++
	}
	if pt.instrumentableGenerations == nil {
		pt.instrumentableGenerations = map[ExecutableKey]uint64{}
	}
	pt.instrumentableGenerations[key] = pt.nextExecutableGeneration

	return pt.nextExecutableGeneration
}

func (pt *ProcessTracer) UnlinkExecutable(info *exec.FileInfo, generation uint64) bool {
	if info == nil {
		return true
	}

	key := ExecutableKey{Dev: info.Dev(), Ino: info.Ino()}
	log := pt.log
	if log == nil {
		log = ptlog().With("type", pt.Type)
	}

	pt.instrumentablesMu.Lock()
	defer pt.instrumentablesMu.Unlock()
	i, ok := pt.Instrumentables[key]
	currentGeneration := pt.instrumentableGenerations[key]
	if !ok {
		log.Debug("Ignoring unlink for an absent executable",
			"path", info.CmdExePath(),
			"pid", info.Pid(),
			"inode", info.Ino(),
			"generation", generation)
		return true
	}
	if currentGeneration != generation {
		log.Debug("Ignoring stale executable unlink",
			"path", info.CmdExePath(),
			"pid", info.Pid(),
			"inode", info.Ino(),
			"generation", generation,
			"current_generation", currentGeneration)
		return true
	}
	for _, program := range pt.Programs {
		if readiness, ok := program.(ExecutableUnlinkReadiness); ok &&
			!readiness.ExecutableUnlinkReady(info) {
			log.Debug("retaining executable resources until process cleanup completes",
				"path", info.CmdExePath(),
				"pid", info.Pid(),
				"inode", info.Ino())
			return false
		}
	}
	pt.removeInstrumenterReference(key, i)
	return true
}

func (pt *ProcessTracer) removeInstrumenterReference(key ExecutableKey, i *instrumenter) {
	for _, p := range pt.Programs {
		if processScopedTracer, ok := p.(processScopedGoProbeTracer); ok {
			processScopedTracer.UnregisterProcessScopedGoProbes(key)
		}
	}
	delete(pt.Instrumentables, key)
	delete(pt.instrumentableGenerations, key)

	if i.references > 0 {
		i.references--
	}
	if i.references != 0 {
		return
	}
	log := pt.log
	if log == nil {
		log = ptlog().With("type", pt.Type)
	}
	if err := pt.closeInstrumenter(i); err != nil {
		log.Debug("closing executable resources failed", "error", err)
	}
}

func (pt *ProcessTracer) closeInstrumentables() {
	pt.instrumentablesMu.Lock()
	instrumenters := make([]*instrumenter, 0, len(pt.Instrumentables))
	seen := make(map[*instrumenter]struct{}, len(pt.Instrumentables))
	for key, instrumenter := range pt.Instrumentables {
		for _, program := range pt.Programs {
			if processScopedTracer, ok := program.(processScopedGoProbeTracer); ok {
				processScopedTracer.UnregisterProcessScopedGoProbes(key)
			}
		}
		if _, ok := seen[instrumenter]; !ok {
			seen[instrumenter] = struct{}{}
			instrumenter.references = 0
			instrumenters = append(instrumenters, instrumenter)
		}
		delete(pt.Instrumentables, key)
		delete(pt.instrumentableGenerations, key)
	}
	pt.instrumentablesMu.Unlock()

	log := pt.log
	if log == nil {
		log = ptlog().With("type", pt.Type)
	}
	for _, instrumenter := range instrumenters {
		if err := pt.closeInstrumenter(instrumenter); err != nil {
			log.Debug("closing executable resources failed", "error", err)
		}
	}
}

func (pt *ProcessTracer) closeInstrumenter(i *instrumenter) error {
	if i == nil {
		return nil
	}

	var cleanupErr error
	for closerIndex := len(i.closables) - 1; closerIndex >= 0; closerIndex-- {
		if closer := i.closables[closerIndex]; closer != nil {
			cleanupErr = errors.Join(cleanupErr, closer.Close())
		}
	}
	for moduleIndex := len(i.modules) - 1; moduleIndex >= 0; moduleIndex-- {
		module := i.modules[moduleIndex]
		module.tracer.UnlinkInstrumentedLib(module.inode)
	}
	return cleanupErr
}

func printVerifierErrorInfo(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		_, _ = fmt.Fprintf(os.Stderr, "Error Log:\n %v\n", strings.Join(ve.Log, "\n"))
	}
}

func RunUtilityTracer(ctx context.Context, eventContext *common.EBPFEventContext, p UtilityTracer, cfg *obi.Config) error {
	i := instrumenter{}
	plog := ptlog()
	plog.Debug("loading independent eBPF program")

	bundles, err := p.LoadSpecs()
	if err != nil {
		return fmt.Errorf("loading eBPF program specs: %w", err)
	}

	for idx, bundle := range bundles {
		// Utility tracers don't pin maps (empty pin path), so no pinned
		// map conflicts are possible — the empty path is intentional.
		setupBPFMapSizes(bundle.Spec, cfg)
		if err := loadSpec(eventContext, bundle, "", idx, nil); err != nil {
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

	p.AddCloser(i.closables...)
	go p.Run(ctx)

	return nil
}
