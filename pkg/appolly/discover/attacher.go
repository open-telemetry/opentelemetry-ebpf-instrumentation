// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/helpers/maps"
	javaagent "go.opentelemetry.io/obi/pkg/internal/java"
	"go.opentelemetry.io/obi/pkg/internal/nodejs"
	"go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

const attacherCleanupRetryInterval = 100 * time.Millisecond

// Swappable in tests so attacher tests don't depend on memlock permissions.
var removeMemlock = rlimit.RemoveMemlock

// traceAttacher creates the available trace.Tracer implementations (Go HTTP tracer, GRPC tracer, Generic tracer...)
// for each received Instrumentable process and forwards an ebpf.ProcessTracer instance ready to run and start
// instrumenting the executable
type traceAttacher struct {
	log     *slog.Logger
	Cfg     *obi.Config
	Metrics imetrics.Reporter
	runCtx  context.Context

	// processInstances keeps track of the instances of each process. This will help making sure
	// that we don't remove the BPF resources of an executable until all their instances are removed
	// are stopped
	processInstances maps.MultiCounter[ebpf.ExecutableKey]
	activePIDs       map[app.PID]*exec.FileInfo
	activePIDTracers map[*exec.FileInfo]*ebpf.ProcessTracer

	// keeps a copy of all the tracers for a given executable path
	existingTracers      map[ebpf.ExecutableKey]executableTracer
	nodeInjector         *nodejs.NodeInjector
	javaInjector         *javaagent.JavaInjector
	reusableTracer       *ebpf.ProcessTracer
	reusableGoTracer     *ebpf.ProcessTracer
	commonTracers        []ebpf.Tracer
	commonTracersLoaded  bool
	pendingUnlinks       map[ebpf.ExecutableKey]pendingExecutableUnlink
	pendingAdmissions    map[pendingProcessAdmissionKey]pendingProcessAdmission
	pendingIdentityCheck func(*exec.FileInfo, *os.File) bool
	initialIdentityCheck func(*exec.FileInfo, *os.File) bool
	probeUpdate          func(*ebpf.ProcessTracer, *ebpf.Instrumentable) (func(), bool)
	unlinkExecutableFn   func(*ebpf.ProcessTracer, *exec.FileInfo, uint64) bool
	processTracerFactory func(
		ebpf.ProcessTracerType,
		[]ebpf.Tracer,
		*obi.Config,
		imetrics.Reporter,
	) *ebpf.ProcessTracer
	currentProcessRoots map[*exec.FileInfo]*os.File
	activeEvents        map[pendingProcessAdmissionKey]struct{}
	activeExecutables   map[pendingProcessAdmissionKey]activeExecutable

	// Usually, only ebpf.Tracer implementations will send spans data to the read decorator.
	// But on each new process, we will send a "process alive" span type to the read decorator, whose
	// unique purpose is to notify other parts of the system that this process is active, even
	// if no spans are detected. This would allow, for example, to start instrumenting this process
	// from the Process metrics pipeline even before it starts to do/receive requests.
	SpanSignalsShortcut *msg.Queue[[]request.Span]
	RuntimeMetrics      *msg.Queue[[]runtimemetrics.RuntimeMetricSnapshot]

	// InputInstrumentables is the input channel for the traceAttacher, where it receives information
	// about the instrumentables that traversed the whole process discovery pipeline, so they need to
	// be instrumented.
	InputInstrumentables *msg.Queue[[]Event[ebpf.Instrumentable]]

	// OutputTracerEvents communicates the process discovery pipeline with the instrumentation pipeline.
	// This queue will forward any newly discovered process to the instrumentation pipeline.
	OutputTracerEvents *msg.Queue[Event[*ebpf.Instrumentable]]

	// EbpfEventContext allows to set the common PID filter that's used to filter out events we don't need
	EbpfEventContext *ebpfcommon.EBPFEventContext

	// Extracts HTTP routes from executables
	routeHarvester *harvest.RouteHarvester

	// Is able to find process lifetime duration
	processAgeFunc func(app.PID) time.Duration

	DynamicPIDSelector *DynamicPIDSelector
}

type executableTracer struct {
	tracer     *ebpf.ProcessTracer
	generation uint64
}

func executableKey(fileInfo *exec.FileInfo) ebpf.ExecutableKey {
	return ebpf.ExecutableKey{Dev: fileInfo.Dev(), Ino: fileInfo.Ino()}
}

type activeExecutable struct {
	key        ebpf.ExecutableKey
	tracer     *ebpf.ProcessTracer
	generation uint64
}

type pendingExecutableUnlink struct {
	tracer     *ebpf.ProcessTracer
	fileInfo   *exec.FileInfo
	generation uint64
}

type pendingProcessAdmissionKey struct {
	pid       app.PID
	ns        uint32
	startTime uint64
	dev       uint64
	ino       uint64
	fileInfo  *exec.FileInfo
	kind      pendingAdmissionKind
}

type pendingAdmissionKind uint8

const (
	pendingGroupAdmission pendingAdmissionKind = iota
	pendingMemberAdmission
)

type pendingProcessAdmission struct {
	tracer             *ebpf.ProcessTracer
	instrumentable     *ebpf.Instrumentable
	eventOwner         *exec.FileInfo
	updateTracerProbes bool
	accountCreation    bool
	processRoots       map[*exec.FileInfo]*os.File
}

func traceAttacherProvider(ta *traceAttacher) swarm.InstanceFunc {
	return ta.attacherLoop
}

func (ta *traceAttacher) attacherLoop(_ context.Context) (swarm.RunFunc, error) {
	ta.log = slog.With("component", "discover.traceAttacher")
	ta.existingTracers = map[ebpf.ExecutableKey]executableTracer{}
	ta.nodeInjector = nodejs.NewNodeInjector(ta.Cfg)
	javaInjector, err := javaagent.NewJavaInjector(ta.Cfg)
	if err != nil {
		ta.log.Warn("unable to inject OBI java agent, Java TLS telemetry generation will not work", "error", err)
	} else {
		ta.javaInjector = javaInjector
	}
	ta.processInstances = maps.MultiCounter[ebpf.ExecutableKey]{}
	ta.activePIDs = map[app.PID]*exec.FileInfo{}
	ta.activePIDTracers = map[*exec.FileInfo]*ebpf.ProcessTracer{}
	ta.activeEvents = map[pendingProcessAdmissionKey]struct{}{}
	ta.activeExecutables = map[pendingProcessAdmissionKey]activeExecutable{}
	if ta.pendingIdentityCheck == nil {
		ta.pendingIdentityCheck = livePendingProcessIdentityMatches
	}
	if ta.initialIdentityCheck == nil {
		ta.initialIdentityCheck = livePendingProcessIdentityMatches
	}
	ta.EbpfEventContext.CommonPIDsFilter = ebpfcommon.NewPIDsFilter(&ta.Cfg.Discovery, slog.With("component", "ebpfCommon.CommonPIDsFilter"), ta.Metrics)
	if ta.RuntimeMetrics != nil {
		ta.EbpfEventContext.RuntimeMetrics = runtimemetrics.NewQueueSender(ta.RuntimeMetrics)
	}
	ta.routeHarvester = harvest.NewRouteHarvester(&ta.Cfg.Discovery.RouteHarvestConfig, ta.Cfg.Discovery.DisabledRouteHarvesters, ta.Cfg.Discovery.RouteHarvesterTimeout)
	ta.processAgeFunc = ProcessAgeFunc()

	if err := ta.init(); err != nil {
		ta.log.Error("cant start process tracer. Stopping it", "error", err)
		return nil, err
	}

	in := ta.InputInstrumentables.Subscribe(msg.SubscriberName("traceAttacher"))
	return func(ctx context.Context) {
		ta.runCtx = ctx
		defer func() {
			ta.runCtx = nil
		}()
		defer ta.OutputTracerEvents.Close()
		ta.forEachInstrumentableInput(ctx, in, func(instrumentables []Event[ebpf.Instrumentable]) {
			for _, instr := range instrumentables {
				ta.log.Debug("Instrumentable", "created", instr.Type, "type", instr.Obj.Type,
					"exec", instr.Obj.FileInfo.CmdExePath(), "pid", instr.Obj.FileInfo.Pid())
				if instr.Type != EventDeleted &&
					!processStartTimeMatches(instr.Obj.FileInfo.Pid(), instr.Obj.FileInfo.StartTime()) {
					ta.log.Debug("ignoring instrumentable for an older process incarnation",
						"pid", instr.Obj.FileInfo.Pid(),
						"startTime", instr.Obj.FileInfo.StartTime())
					if instr.Type == EventCreated {
						closeInstrumentableProcessRoots(&instr.Obj)
					}
					continue
				}
				switch instr.Type {
				case EventCreated:
					if ta.processCreationActive(&instr.Obj) {
						closeInstrumentableProcessRoots(&instr.Obj)
						continue
					}

					if ok := ta.getTracerWithProcessRoots(&instr.Obj); ok {
						ta.completeProcessCreation(&instr.Obj)
					}

					closeInstrumentableProcessRoots(&instr.Obj)
				case EventDeleted:
					ta.notifyProcessDeletion(&instr.Obj)
				}
			}
		})
	}, nil
}

func (ta *traceAttacher) getTracerWithProcessRoots(ie *ebpf.Instrumentable) bool {
	previousRoots := ta.currentProcessRoots
	ta.currentProcessRoots = claimInstrumentableProcessRoots(ie)
	defer func() {
		closeAdmissionProcessRoots(ta.currentProcessRoots)
		ta.currentProcessRoots = previousRoots
	}()
	if !ta.initialInstrumentableIdentityMatches(ie) ||
		!ta.injectProcessAgents(ie) ||
		!ta.initialInstrumentableIdentityMatches(ie) {
		return false
	}
	return ta.getTracer(ie)
}

func (ta *traceAttacher) initialInstrumentableIdentityMatches(
	ie *ebpf.Instrumentable,
) bool {
	if ie == nil || ie.FileInfo == nil {
		return false
	}
	identityMatches := ta.initialIdentityCheck
	if identityMatches == nil {
		identityMatches = livePendingProcessIdentityMatches
	}
	for _, fileInfo := range instrumentableFileInfosExcept(ie, nil) {
		if ta.activePIDs[fileInfo.Pid()] == fileInfo {
			continue
		}
		if !identityMatches(fileInfo, ta.currentProcessRoots[fileInfo]) {
			return false
		}
	}
	return true
}

func (ta *traceAttacher) sideEffectIdentityMatches(
	ie *ebpf.Instrumentable,
) bool {
	if ta.currentProcessRoots != nil {
		return ta.initialInstrumentableIdentityMatches(ie)
	}
	if ie == nil || ie.FileInfo == nil {
		return false
	}
	for _, fileInfo := range instrumentableFileInfosExcept(ie, nil) {
		if !processStartTimeMatches(fileInfo.Pid(), fileInfo.StartTime()) {
			return false
		}
	}
	return true
}

func (ta *traceAttacher) ownedProcessIdentityMatches(
	fileInfo *exec.FileInfo,
) bool {
	if fileInfo == nil {
		return false
	}
	identityMatches := ta.initialIdentityCheck
	if identityMatches == nil {
		identityMatches = livePendingProcessIdentityMatches
	}
	return identityMatches(fileInfo, ta.currentProcessRoots[fileInfo])
}

func (ta *traceAttacher) injectProcessAgents(ie *ebpf.Instrumentable) bool {
	if ie == nil || ie.FileInfo == nil {
		return false
	}
	needsNodeInjection := ta.nodeInjector != nil && ta.nodeInjector.Enabled() &&
		ie.Type == svc.InstrumentableNodejs
	needsJavaInjection := ta.javaInjector != nil && ie.Type == svc.InstrumentableJava
	if !needsNodeInjection && !needsJavaInjection {
		return true
	}

	fileInfo := triggeringFileInfo(ie)
	if fileInfo == nil {
		return false
	}
	processRoot := ta.currentProcessRoots[fileInfo]
	if !livePendingProcessIdentityMatches(fileInfo, processRoot) {
		return false
	}
	processHandle, err := openIdentityStableProcessHandle(int(fileInfo.Pid()))
	if err != nil {
		ta.log.Warn("unable to acquire identity-stable process handle; skipping agent injection",
			"pid", fileInfo.Pid(), "error", err)
		return true
	}
	defer func() { _ = processHandle.Close() }()
	if err := processHandle.Signal(0); err != nil ||
		!livePendingProcessIdentityMatches(fileInfo, processRoot) {
		return false
	}

	if needsNodeInjection {
		injectionTarget := instrumentableForEventOwner(ie, fileInfo)
		ta.nodeInjector.NewExecutable(injectionTarget, processHandle.Signal)
		if err := processHandle.Signal(0); err != nil ||
			!livePendingProcessIdentityMatches(fileInfo, processRoot) {
			return false
		}
	}
	if needsJavaInjection {
		filesystemRoot, err := filesystemRootPathThroughProcessRoot(processRoot)
		if err != nil {
			return false
		}
		injectionTarget := instrumentableForEventOwner(ie, fileInfo)
		if err := ta.javaInjector.NewExecutable(injectionTarget, processHandle.Signal, filesystemRoot); err != nil {
			ta.log.Warn("unable to attach java agent to process, Java TLS telemetry generation will not work", "pid", fileInfo.Pid(), "error", err)
		}
		if err := processHandle.Signal(0); err != nil ||
			!livePendingProcessIdentityMatches(fileInfo, processRoot) {
			return false
		}
	}
	return true
}

func claimInstrumentableProcessRoots(
	ie *ebpf.Instrumentable,
) map[*exec.FileInfo]*os.File {
	roots := map[*exec.FileInfo]*os.File{}
	for _, fileInfo := range instrumentableFileInfosExcept(ie, nil) {
		if root := fileInfo.DuplicateProcessRoot(); root != nil {
			roots[fileInfo] = root
		}
	}
	return roots
}

func closeInstrumentableProcessRoots(ie *ebpf.Instrumentable) {
	if ie == nil {
		return
	}
	seen := map[*exec.FileInfo]struct{}{}
	closeRoot := func(fileInfo *exec.FileInfo) {
		if fileInfo == nil {
			return
		}
		if _, ok := seen[fileInfo]; ok {
			return
		}
		seen[fileInfo] = struct{}{}
		if fileInfo.ELF() != nil {
			_ = fileInfo.ELF().Close()
		}
		_ = fileInfo.CloseProcessRoot()
	}
	closeRoot(ie.FileInfo)
	for _, fileInfo := range ie.ChildFileInfos {
		closeRoot(fileInfo)
	}
}

func (ta *traceAttacher) processCreationActive(ie *ebpf.Instrumentable) bool {
	return ta.processCreationOwnerActive(triggeringFileInfo(ie))
}

func (ta *traceAttacher) processCreationOwnerActive(owner *exec.FileInfo) bool {
	if owner == nil {
		return false
	}
	_, active := ta.activeEvents[processAdmissionKey(owner)]
	return active
}

func (ta *traceAttacher) completeProcessCreation(ie *ebpf.Instrumentable) bool {
	return ta.completeProcessCreationForOwner(ie, triggeringFileInfo(ie))
}

func (ta *traceAttacher) completeProcessCreationForOwner(
	ie *ebpf.Instrumentable,
	owner *exec.FileInfo,
) bool {
	if ie == nil || ie.FileInfo == nil || owner == nil ||
		ta.processCreationOwnerActive(owner) {
		return false
	}
	if ta.activeEvents == nil {
		ta.activeEvents = map[pendingProcessAdmissionKey]struct{}{}
	}
	if ta.processInstances == nil {
		ta.processInstances = maps.MultiCounter[ebpf.ExecutableKey]{}
	}
	creationKey := processAdmissionKey(owner)
	executable := activeExecutable{
		key:        executableKey(owner),
		tracer:     ie.Tracer,
		generation: ie.ExecutableGeneration,
	}
	ta.activeEvents[creationKey] = struct{}{}
	if ta.activeExecutables == nil {
		ta.activeExecutables = map[pendingProcessAdmissionKey]activeExecutable{}
	}
	ta.activeExecutables[creationKey] = executable
	ta.processInstances.Inc(executable.key)
	if ta.OutputTracerEvents != nil {
		eventInstrumentable := instrumentableForEventOwner(ie, owner)
		ta.OutputTracerEvents.Send(Event[*ebpf.Instrumentable]{
			Type: EventCreated,
			Obj:  eventInstrumentable,
		})
	}
	return true
}

func instrumentableForEventOwner(
	ie *ebpf.Instrumentable,
	owner *exec.FileInfo,
) *ebpf.Instrumentable {
	if ie == nil || owner == nil {
		return nil
	}
	eventInstrumentable := cloneInstrumentableForAdmissionRetry(ie)
	eventInstrumentable.FileInfo = owner
	eventInstrumentable.ChildPids = nil
	eventInstrumentable.ChildFileInfos = nil
	return eventInstrumentable
}

func (ta *traceAttacher) forEachInstrumentableInput(
	ctx context.Context,
	input <-chan []Event[ebpf.Instrumentable],
	action func([]Event[ebpf.Instrumentable]),
) {
	retryTicker := time.NewTicker(attacherCleanupRetryInterval)
	defer retryTicker.Stop()

	ta.log.Debug("starting node")
	for {
		select {
		case <-ctx.Done():
			ta.log.Debug("context done, stopping node")
			ta.cancelAllProcessAdmissionRetries()
			closeQueuedInstrumentableProcessRoots(input)
			return
		case instrumentables, ok := <-input:
			if !ok {
				ta.log.Debug("input channel closed, stopping node")
				ta.cancelAllProcessAdmissionRetries()
				return
			}
			action(instrumentables)
		case <-retryTicker.C:
			ta.retryPendingProcessAdmissions()
			ta.retryPendingExecutableUnlinks()
		}
	}
}

func closeQueuedInstrumentableProcessRoots(
	input <-chan []Event[ebpf.Instrumentable],
) {
	for instrumentables := range input {
		for i := range instrumentables {
			instrumentable := &instrumentables[i]
			if instrumentable.Type == EventCreated {
				closeInstrumentableProcessRoots(&instrumentable.Obj)
			}
		}
	}
}

//nolint:cyclop
func (ta *traceAttacher) getTracer(ie *ebpf.Instrumentable) bool {
	if !ta.sideEffectIdentityMatches(ie) {
		return false
	}
	eventOwner := triggeringFileInfo(ie)
	sideEffectTarget := instrumentableForEventOwner(ie, eventOwner)
	key := executableKey(eventOwner)
	if existing, ok := ta.existingTracers[key]; ok {
		tracer := existing.tracer
		ie.Tracer = tracer
		ie.ExecutableGeneration = existing.generation
		sideEffectTarget.Tracer = tracer
		sideEffectTarget.ExecutableGeneration = existing.generation
		ta.log.Debug("new process for already instrumented executable",
			"pid", ie.FileInfo.Pid(),
			"child", ie.ChildPids,
			"cmd", ie.FileInfo.CmdExePath())
		eventOwner.SetSDKLanguage(ie.Type)
		// Must be called after we've set the SDKLanguage
		ta.harvestRoutes(sideEffectTarget, true)

		updateTracerProbes := ta.pendingTracerProbeUpdate(tracer, ie, true)
		if tracer.Type == ebpf.Generic && updateTracerProbes {
			// We need to do this because generic tracers have shared libraries. For example,
			// a python executable can run an SSL and non-SSL application, so it's not enough
			// to look at the executable, we must ensure this process doesn't have different
			// libraries attached
			if !ta.ownedProcessIdentityMatches(eventOwner) ||
				!ta.updateTracerProbes(
					tracer,
					sideEffectTarget,
					func() bool { return ta.ownedProcessIdentityMatches(eventOwner) },
				) {
				ta.queueProcessAdmissionRetryForced(tracer, ie, true)
				return false
			}
			ie.ExecutableGeneration = sideEffectTarget.ExecutableGeneration
			updateTracerProbes = false
		}
		// allowing the tracer to forward traces from the new PID and its children processes
		if !ta.monitorPIDs(tracer, ie) {
			ta.queueProcessAdmissionRetry(tracer, ie, updateTracerProbes)
			return false
		}
		ta.cancelInstrumentableAdmissionRetries(ie)
		ta.existingTracers[key] = executableTracer{
			tracer:     tracer,
			generation: ie.ExecutableGeneration,
		}
		if ta.Metrics != nil {
			ta.Metrics.InstrumentProcess(eventOwner.ExecutableName())
		}
		ta.log.Debug(".done", "success", ok)
		return ok
	}

	snap := ie.FileInfo.ServiceAttrs()
	ta.log.Info(
		"instrumenting process",
		"cmd", ie.FileInfo.CmdExePath(),
		"pid", ie.FileInfo.Pid(),
		"ino", ie.FileInfo.Ino(),
		"type", ie.Type,
		"service", snap.UID.Name,
		"logenricher", snap.LogEnricherEnabled,
	)

	// builds a tracer for that executable
	var programs []ebpf.Tracer
	tracerType := ebpf.Generic
	switch ie.Type {
	case svc.InstrumentableGolang:
		// gets all the possible supported tracers for a go program, and filters out
		// those whose symbols are not present in the ELF functions list
		if ta.Cfg.Discovery.SkipGoSpecificTracers || ie.InstrumentationError != nil || ie.Offsets == nil {
			if !ta.Cfg.Discovery.SkipGoSpecificTracers {
				if ie.InstrumentationError != nil {
					ta.log.Warn("Unsupported Go program detected, using generic instrumentation", "error", ie.InstrumentationError)
				} else if ie.Offsets == nil {
					ta.log.Warn("Go program with null offsets detected, using generic instrumentation")
				}
			}
			if ta.reusableTracer != nil {
				// We need to do more than monitor PIDs. It's possible that this new
				// instance of the executable has different DLLs loaded, e.g. libssl.so.
				return ta.reuseTracer(ta.reusableTracer, ie)
			} else {
				programs = ta.withCommonTracersGroup(newGenericTracersGroup(ta.EbpfEventContext.CommonPIDsFilter, ta.Cfg, ta.Metrics))
			}
		} else {
			if ta.reusableGoTracer != nil {
				return ta.reuseTracer(ta.reusableGoTracer, ie)
			}
			tracerType = ebpf.Go
			programs = ta.withCommonTracersGroup(newGoTracersGroup(
				ta.EbpfEventContext.CommonPIDsFilter,
				ta.Cfg,
				ta.Metrics,
			))
		}
	case svc.InstrumentableNodejs, svc.InstrumentableJava, svc.InstrumentableJavaNative, svc.InstrumentableRuby, svc.InstrumentablePython, svc.InstrumentableDotnet, svc.InstrumentableGeneric, svc.InstrumentableRust, svc.InstrumentablePHP, svc.InstrumentableCPP:
		if ta.reusableTracer != nil {
			return ta.reuseTracer(ta.reusableTracer, ie)
		}
		programs = ta.withCommonTracersGroup(newGenericTracersGroup(ta.EbpfEventContext.CommonPIDsFilter, ta.Cfg, ta.Metrics))
	default:
		ta.log.Warn("unexpected instrumentable type. This is basically a bug", "type", ie.Type)
	}
	if len(programs) == 0 {
		ta.log.Warn("no instrumentable functions found. Ignoring", "pid", ie.FileInfo.Pid(), "cmd", ie.FileInfo.CmdExePath())
		ta.Metrics.InstrumentationError(ie.FileInfo.ExecutableName(), imetrics.InstrumentationErrorNoInstrumentableFunctionsFound)
		return false
	}

	eventOwner.SetSDKLanguage(ie.Type)
	// Must be called after we've set the SDKLanguage
	ta.harvestRoutes(sideEffectTarget, false)

	// Instead of the executable file in the disk, we pass the /proc/<pid>/exec
	// to allow loading it from different container/pods in containerized environments
	exe, ok := ta.loadExecutable(sideEffectTarget)
	if !ok {
		ta.Metrics.InstrumentationError(ie.FileInfo.ExecutableName(), imetrics.InstrumentationErrorInspectionFailed)
		return false
	}

	processTracerFactory := ta.processTracerFactory
	if processTracerFactory == nil {
		processTracerFactory = ebpf.NewProcessTracer
	}
	tracer := processTracerFactory(tracerType, programs, ta.Cfg, ta.Metrics)

	if err := tracer.Init(ta.EbpfEventContext, ta.Cfg); err != nil {
		ta.log.Error("couldn't trace process. Stopping process tracer", "error", err)
		ta.Metrics.InstrumentationError(ie.FileInfo.ExecutableName(), imetrics.InstrumentationErrorInspectionFailed)
		return false
	}
	ie.Tracer = tracer
	defer ta.handoffInitializedTracer(tracer, ie)
	ta.dropUnloadedTracers(tracer.Programs)
	if !ta.ownedProcessIdentityMatches(eventOwner) {
		return false
	}

	if err := tracer.NewExecutable(exe, sideEffectTarget); err != nil {
		ta.Metrics.InstrumentationError(ie.FileInfo.ExecutableName(), imetrics.InstrumentationErrorAttachingUprobe)
		return false
	}
	ie.ExecutableGeneration = sideEffectTarget.ExecutableGeneration

	ta.log.Debug("new executable for discovered process",
		"pid", ie.FileInfo.Pid(),
		"child", ie.ChildPids,
		"cmd", ie.FileInfo.CmdExePath(),
		"type", ie.Type)
	// allowing the tracer to forward traces from the discovered PID and its children processes
	if !ta.monitorPIDs(tracer, ie) {
		ta.unlinkRejectedExecutable(tracer, eventOwner, ie.ExecutableGeneration)
		ta.queueProcessAdmissionRetry(tracer, ie, false)
		return false
	}
	ta.cancelInstrumentableAdmissionRetries(ie)
	ta.existingTracers[key] = executableTracer{
		tracer:     tracer,
		generation: ie.ExecutableGeneration,
	}
	if ta.Metrics != nil {
		ta.Metrics.InstrumentProcess(eventOwner.ExecutableName())
	}
	ta.log.Debug(".done")
	return true
}

func (ta *traceAttacher) pendingTracerProbeUpdate(
	tracer *ebpf.ProcessTracer,
	ie *ebpf.Instrumentable,
	defaultValue bool,
) bool {
	pending, exists := ta.pendingAdmissions[processAdmissionKey(triggeringFileInfo(ie))]
	if !exists || pending.tracer != tracer {
		return defaultValue
	}
	return pending.updateTracerProbes
}

func (ta *traceAttacher) handoffInitializedTracer(
	tracer *ebpf.ProcessTracer,
	ie *ebpf.Instrumentable,
) {
	if tracer == nil || ie == nil {
		return
	}
	if tracer.Type == ebpf.Generic {
		ta.reusableTracer = tracer
	} else {
		ta.reusableGoTracer = tracer
	}
	ie.Tracer = tracer
	if ta.OutputTracerEvents != nil {
		ta.OutputTracerEvents.Send(Event[*ebpf.Instrumentable]{
			Type: EventTracerInitialized,
			Obj:  ie,
		})
	}
}

// dropUnloadedTracers keeps only the common tracers that survived ProcessTracer.Init in
// loadedPrograms, so PID notifications never reach a tracer without loaded BPF objects
func (ta *traceAttacher) dropUnloadedTracers(loadedPrograms []ebpf.Tracer) {
	if ta.commonTracersLoaded {
		return
	}
	ta.commonTracers = slices.DeleteFunc(ta.commonTracers, func(ct ebpf.Tracer) bool {
		return !slices.Contains(loadedPrograms, ct)
	})
	ta.commonTracersLoaded = true
}

func (ta *traceAttacher) withCommonTracersGroup(tracers []ebpf.Tracer) []ebpf.Tracer {
	if ta.commonTracersLoaded {
		return tracers
	}

	ta.commonTracers = newCommonTracersGroup(ta.Cfg, ta.Metrics, ta.EbpfEventContext.CommonPIDsFilter)

	return append(tracers, ta.commonTracers...)
}

func (ta *traceAttacher) harvestRoutesProcessor(ie *ebpf.Instrumentable, reused bool) {
	routes, err := ta.routeHarvester.HarvestRoutes(ie.FileInfo)
	if err != nil {
		ta.log.Info("encountered error harvesting routes", "error", err, "pid", ie.FileInfo.Pid(), "cmd", ie.FileInfo.CmdExePath())
	} else if routes != nil && len(routes.Routes) > 0 {
		ta.log.Debug("found routes in executable", "pid", ie.FileInfo.Pid(), "routes", routes, "reused", reused)
		m := harvest.RouteMatcherFromResult(*routes)
		ie.FileInfo.SetHarvestedRoutes(m)
	}
}

func (ta *traceAttacher) harvestRoutes(ie *ebpf.Instrumentable, reused bool) {
	if delay, delayTime := ta.routeHarvester.HarvestRoutesDelay(ie.FileInfo); delay {
		procAge := ta.processAgeFunc(ie.FileInfo.Pid())
		if procAge < delayTime {
			time.AfterFunc(delayTime-procAge, func() {
				// sanity check that the program is still up and running and it's the same command
				if exePath, ready := ExecutableReady(ie.FileInfo.Pid()); ready &&
					exePath == ie.FileInfo.CmdExePath() &&
					processStartTimeMatches(ie.FileInfo.Pid(), ie.FileInfo.StartTime()) {
					ta.harvestRoutesProcessor(ie, reused)
				}
			})

			return
		}
	}

	ta.harvestRoutesProcessor(ie, reused)
}

func (ta *traceAttacher) loadExecutable(ie *ebpf.Instrumentable) (*link.Executable, bool) {
	if !ta.sideEffectIdentityMatches(ie) {
		ta.log.Debug("process was replaced before opening executable",
			"pid", ie.FileInfo.Pid(), "cmd", ie.FileInfo.CmdExePath())
		return nil, false
	}
	executablePath := ie.FileInfo.ProExeLinkPath()
	if root := ta.currentProcessRoots[ie.FileInfo]; root != nil {
		var err error
		executablePath, err = executablePathThroughProcessRoot(root)
		if err != nil {
			return nil, false
		}
	}
	// Instead of the executable file in the disk, we pass the /proc/<pid>/exec
	// to allow loading it from different container/pods in containerized environments
	exe, err := link.OpenExecutable(executablePath)
	if err != nil {
		ta.log.Debug("can't open executable. Ignoring",
			"error", err, "pid", ie.FileInfo.Pid(), "cmd", ie.FileInfo.CmdExePath())
		return nil, false
	}
	if !ta.sideEffectIdentityMatches(ie) {
		ta.log.Debug("process was replaced while opening executable",
			"pid", ie.FileInfo.Pid(), "cmd", ie.FileInfo.CmdExePath())
		return nil, false
	}

	return exe, true
}

func (ta *traceAttacher) reuseTracer(tracer *ebpf.ProcessTracer, ie *ebpf.Instrumentable) bool {
	eventOwner := triggeringFileInfo(ie)
	sideEffectTarget := instrumentableForEventOwner(ie, eventOwner)
	exe, ok := ta.loadExecutable(sideEffectTarget)
	if !ok {
		return false
	}

	if err := tracer.NewExecutable(exe, sideEffectTarget); err != nil {
		ta.log.Debug("Failed to attach uprobes for new executable", "pid", ie.FileInfo.Pid(), "error", err)
		ie.Tracer = nil
		return false
	}
	ie.Tracer = tracer
	ie.ExecutableGeneration = sideEffectTarget.ExecutableGeneration
	if !ta.ownedProcessIdentityMatches(eventOwner) {
		ta.unlinkRejectedExecutable(tracer, eventOwner, ie.ExecutableGeneration)
		ie.Tracer = nil
		return false
	}

	ta.log.Debug("reusing Generic tracer for",
		"pid", ie.FileInfo.Pid(),
		"child", ie.ChildPids,
		"cmd", ie.FileInfo.CmdExePath(),
		"language", ie.Type)

	if !ta.monitorPIDs(tracer, ie) {
		ta.unlinkRejectedExecutable(tracer, eventOwner, ie.ExecutableGeneration)
		ta.queueProcessAdmissionRetry(tracer, ie, false)
		ie.Tracer = nil
		return false
	}
	ta.cancelInstrumentableAdmissionRetries(ie)
	ta.existingTracers[executableKey(eventOwner)] = executableTracer{
		tracer:     tracer,
		generation: ie.ExecutableGeneration,
	}
	if ta.Metrics != nil {
		ta.Metrics.InstrumentProcess(eventOwner.ExecutableName())
	}

	return true
}

func (ta *traceAttacher) updateTracerProbes(
	tracer *ebpf.ProcessTracer,
	ie *ebpf.Instrumentable,
	identityMatches func() bool,
) bool {
	if ta.probeUpdate != nil {
		rollback, updated := ta.probeUpdate(tracer, ie)
		if !updated {
			return false
		}
		if identityMatches == nil || !identityMatches() {
			if rollback != nil {
				rollback()
			}
			return false
		}
		return true
	}
	update, err := tracer.NewExecutableInstance(ie)
	if err != nil {
		ta.log.Debug("Failed to attach uprobes", "pid", ie.FileInfo.Pid(), "error", err)
		return false
	}
	if identityMatches == nil || !identityMatches() {
		update.Rollback()
		return false
	}
	update.Commit()

	ta.log.Debug("reusing Generic tracer for",
		"pid", ie.FileInfo.Pid(),
		"child", ie.ChildPids,
		"cmd", ie.FileInfo.CmdExePath(),
		"language", ie.Type)
	return true
}

func (ta *traceAttacher) monitorPIDs(
	tracer *ebpf.ProcessTracer,
	ie *ebpf.Instrumentable,
) bool {
	result := ta.monitorPIDsWithIdentity(tracer, ie, func(fileInfo *exec.FileInfo) bool {
		if ta.initialIdentityCheck != nil {
			return ta.initialIdentityCheck(fileInfo, ta.currentProcessRoots[fileInfo])
		}
		return fileInfo != nil &&
			processStartTimeMatches(fileInfo.Pid(), fileInfo.StartTime())
	}, triggeringFileInfo(ie))
	if result.admitted {
		ta.queueRejectedMemberAdmissions(tracer, result.rejected)
	}
	return result.admitted
}

type pidMonitoringResult struct {
	admitted bool
	rejected []*exec.FileInfo
}

func (ta *traceAttacher) monitorPIDsWithIdentity(
	tracer *ebpf.ProcessTracer,
	ie *ebpf.Instrumentable,
	identityMatches func(*exec.FileInfo) bool,
	eventOwner *exec.FileInfo,
) pidMonitoringResult {
	if tracer == nil || ie == nil || ie.FileInfo == nil ||
		identityMatches == nil {
		return pidMonitoringResult{}
	}
	if eventOwner == nil {
		eventOwner = ie.FileInfo
	}
	ie.CopyToServiceAttributes()

	if ta.activePIDs == nil {
		ta.activePIDs = map[app.PID]*exec.FileInfo{}
	}
	if ta.activePIDTracers == nil {
		ta.activePIDTracers = map[*exec.FileInfo]*ebpf.ProcessTracer{}
	}

	admitted := make([]*exec.FileInfo, 0, len(ie.ChildPids)+1)
	newAdmissions := make([]*exec.FileInfo, 0, len(ie.ChildPids)+1)
	rejectedAdmissions := make([]*exec.FileInfo, 0, len(ie.ChildPids)+1)
	admit := func(fi *exec.FileInfo) bool {
		if fi == nil {
			return false
		}
		if ta.activePIDs[fi.Pid()] == fi {
			return true
		}
		if !identityMatches(fi) {
			return false
		}
		if !tracer.AllowPID(fi.Pid(), fi.Ns(), fi) {
			rejectedAdmissions = append(rejectedAdmissions, fi)
			return false
		}
		if !identityMatches(fi) {
			rejectedAdmissions = append(rejectedAdmissions, fi)
			return false
		}
		admitted = append(admitted, fi)
		newAdmissions = append(newAdmissions, fi)
		return true
	}

	primaryAdmitted := admit(ie.FileInfo)
	if !primaryAdmitted {
		ta.rollbackPIDAdmissions(tracer, rejectedAdmissions)
		return pidMonitoringResult{rejected: rejectedAdmissions}
	}

	eventOwnerAdmitted := eventOwner == ie.FileInfo
	for _, pid := range ie.ChildPids {
		if fi := ie.FileInfoForPID(pid); fi != nil {
			if !admit(fi) {
				continue
			}
			if fi == eventOwner {
				eventOwnerAdmitted = true
			}
		}
	}

	if !eventOwnerAdmitted {
		ta.rollbackPIDAdmissions(tracer, append(newAdmissions, rejectedAdmissions...))
		return pidMonitoringResult{rejected: rejectedAdmissions}
	}
	ta.rollbackPIDAdmissions(tracer, rejectedAdmissions)

	for _, fi := range admitted {
		ta.activePIDs[fi.Pid()] = fi
		ta.activePIDTracers[fi] = tracer
		if ta.DynamicPIDSelector != nil {
			ta.DynamicPIDSelector.RegisterFileInfo(fi.Pid(), fi)
		}
	}

	for _, ct := range ta.commonTracers {
		for _, fi := range admitted {
			ct.AllowPID(fi.Pid(), fi.Ns(), fi)
		}
	}

	if ta.SpanSignalsShortcut != nil && len(admitted) > 0 {
		spans := make([]request.Span, 0, len(admitted))
		// the forwarded signal must include
		// - Service, which includes several metadata about the process
		// - PID namespace, to allow further kubernetes decoration
		for _, fi := range admitted {
			spans = append(spans, request.Span{
				Type:    request.EventTypeProcessAlive,
				Service: fi.ServiceAttrs(),
				Pid:     request.PidInfo{Namespace: fi.Ns()},
			})
		}
		ctx := ta.runCtx
		if ctx == nil {
			ctx = context.Background()
		}
		ta.SpanSignalsShortcut.SendCtx(ctx, spans)
	}
	return pidMonitoringResult{
		admitted: eventOwnerAdmitted,
		rejected: rejectedAdmissions,
	}
}

func (ta *traceAttacher) rollbackPIDAdmissions(
	tracer *ebpf.ProcessTracer,
	fileInfos []*exec.FileInfo,
) {
	for _, fi := range fileInfos {
		tracer.BlockPIDForProcess(fi.Pid(), fi.Ns(), fi)
	}
}

func (ta *traceAttacher) unregisterDynamicFileInfo(ie *ebpf.Instrumentable) {
	if ta.DynamicPIDSelector == nil {
		return
	}
	ta.DynamicPIDSelector.UnregisterFileInfo(ie.FileInfo.Pid(), ie.FileInfo)
	for _, pid := range ie.ChildPids {
		if fi := ie.FileInfoForPID(pid); fi != nil {
			ta.DynamicPIDSelector.UnregisterFileInfo(pid, fi)
		}
	}
}

func (ta *traceAttacher) notifyProcessDeletion(ie *ebpf.Instrumentable) {
	if ie == nil || ie.FileInfo == nil {
		return
	}
	fileInfo := ie.FileInfo
	ta.removeProcessFromAdmissionRetries(fileInfo)
	creationKey := processAdmissionKey(fileInfo)
	_, ownsCreation := ta.activeEvents[creationKey]
	creation := ta.activeExecutables[creationKey]
	if ownsCreation {
		delete(ta.activeEvents, creationKey)
		delete(ta.activeExecutables, creationKey)
	}
	active := ta.activePIDs[fileInfo.Pid()]
	currentPID := active == fileInfo
	if !currentPID && !ownsCreation {
		delete(ta.activePIDTracers, fileInfo)
		if active == nil {
			ta.log.Debug("ignoring deletion without an active process admission",
				"pid", fileInfo.Pid(),
				"startTime", fileInfo.StartTime())
			return
		}
		ta.log.Debug("ignoring deletion for an older process incarnation",
			"pid", fileInfo.Pid(),
			"deletedStartTime", fileInfo.StartTime(),
			"currentStartTime", active.StartTime())
		return
	}

	pidTracer := ta.activePIDTracers[fileInfo]
	if pidTracer == nil && ownsCreation {
		pidTracer = creation.tracer
	}
	if pidTracer == nil {
		pidTracer = ta.existingTracers[executableKey(fileInfo)].tracer
	}
	if currentPID {
		delete(ta.activePIDs, fileInfo.Pid())
		delete(ta.activePIDTracers, fileInfo)
		ta.unregisterDynamicFileInfo(ie)
		if pidTracer != nil {
			pidTracer.BlockPIDForProcess(
				fileInfo.Pid(),
				fileInfo.Ns(),
				fileInfo,
			)
		}
		for _, ct := range ta.commonTracers {
			ebpf.BlockPIDForProcess(
				ct,
				fileInfo.Pid(),
				fileInfo.Ns(),
				fileInfo,
			)
		}
	} else {
		delete(ta.activePIDTracers, fileInfo)
	}

	if !ownsCreation {
		return
	}
	ta.log.Info(
		"process ended for already instrumented executable",
		"cmd", fileInfo.CmdExePath(),
		"pid", fileInfo.Pid(),
		"ino", fileInfo.Ino(),
		"type", ie.Type,
		"service", fileInfo.ServiceAttrs().UID.Name,
	)
	if ta.Metrics != nil {
		ta.Metrics.UninstrumentProcess(fileInfo.ExecutableName())
	}

	key := creation.key
	tracer := creation.tracer
	generation := creation.generation
	if tracer == nil {
		key = executableKey(fileInfo)
		if existing, ok := ta.existingTracers[key]; ok {
			tracer = existing.tracer
			generation = existing.generation
		}
	}
	ie.ExecutableGeneration = generation

	// Creation accounting belongs to the exact event identity, independently
	// from whichever process incarnation currently owns this numeric PID.
	remainingInstances := ta.processInstances.Dec(key)
	if tracer == nil {
		ta.log.Warn("unable to finish deleted process accounting without its tracer",
			"pid", fileInfo.Pid(),
			"ino", fileInfo.Ino())
		return
	}
	if remainingInstances == 0 {
		if ta.unlinkExecutable(tracer, fileInfo, generation) {
			ta.deleteExecutableStateIfMatch(key, tracer, generation)
			ie.Tracer = tracer
			if ta.OutputTracerEvents != nil {
				ta.OutputTracerEvents.Send(Event[*ebpf.Instrumentable]{Type: EventDeleted, Obj: ie})
			}
		} else {
			ta.queueExecutableUnlinkRetry(tracer, fileInfo, generation)
			if ta.OutputTracerEvents != nil {
				ta.OutputTracerEvents.Send(Event[*ebpf.Instrumentable]{
					Type: EventInstanceDeleted,
					Obj:  ie,
				})
			}
		}
	} else if ta.OutputTracerEvents != nil {
		ta.OutputTracerEvents.Send(Event[*ebpf.Instrumentable]{Type: EventInstanceDeleted, Obj: ie})
	}
}

func (ta *traceAttacher) unlinkRejectedExecutable(
	tracer *ebpf.ProcessTracer,
	fileInfo *exec.FileInfo,
	generation uint64,
) {
	if tracer == nil || fileInfo == nil || ta.unlinkExecutable(tracer, fileInfo, generation) {
		return
	}
	if ta.existingTracers == nil {
		ta.existingTracers = map[ebpf.ExecutableKey]executableTracer{}
	}
	key := executableKey(fileInfo)
	ta.existingTracers[key] = executableTracer{tracer: tracer, generation: generation}
	ta.queueExecutableUnlinkRetry(tracer, fileInfo, generation)
}

func (ta *traceAttacher) queueExecutableUnlinkRetry(
	tracer *ebpf.ProcessTracer,
	fileInfo *exec.FileInfo,
	generation uint64,
) {
	if tracer == nil || fileInfo == nil {
		return
	}
	if ta.pendingUnlinks == nil {
		ta.pendingUnlinks = map[ebpf.ExecutableKey]pendingExecutableUnlink{}
	}
	ta.pendingUnlinks[executableKey(fileInfo)] = pendingExecutableUnlink{
		tracer:     tracer,
		fileInfo:   fileInfo,
		generation: generation,
	}
}

func (ta *traceAttacher) retryPendingExecutableUnlinks() {
	for key, pending := range ta.pendingUnlinks {
		if _, active := ta.processInstances[key]; active {
			continue
		}
		current, ok := ta.existingTracers[key]
		if !ok || current.tracer != pending.tracer ||
			current.generation != pending.generation {
			delete(ta.pendingUnlinks, key)
			continue
		}
		if !ta.unlinkExecutable(pending.tracer, pending.fileInfo, pending.generation) {
			continue
		}
		ta.deleteExecutableStateIfMatch(
			key,
			pending.tracer,
			pending.generation,
		)
	}
}

func (ta *traceAttacher) unlinkExecutable(
	tracer *ebpf.ProcessTracer,
	fileInfo *exec.FileInfo,
	generation uint64,
) bool {
	if ta.unlinkExecutableFn != nil {
		return ta.unlinkExecutableFn(tracer, fileInfo, generation)
	}
	return tracer.UnlinkExecutable(fileInfo, generation)
}

func (ta *traceAttacher) deleteExecutableStateIfMatch(
	key ebpf.ExecutableKey,
	tracer *ebpf.ProcessTracer,
	generation uint64,
) {
	if current, ok := ta.existingTracers[key]; ok &&
		current.tracer == tracer && current.generation == generation {
		delete(ta.existingTracers, key)
	}
	if pending, ok := ta.pendingUnlinks[key]; ok &&
		pending.tracer == tracer && pending.generation == generation {
		delete(ta.pendingUnlinks, key)
	}
}

func (ta *traceAttacher) queueProcessAdmissionRetry(
	tracer *ebpf.ProcessTracer,
	ie *ebpf.Instrumentable,
	updateTracerProbes bool,
) {
	ta.queueProcessAdmissionRetryWithRequirement(
		tracer,
		ie,
		updateTracerProbes,
		true,
	)
}

func (ta *traceAttacher) queueProcessAdmissionRetryForced(
	tracer *ebpf.ProcessTracer,
	ie *ebpf.Instrumentable,
	updateTracerProbes bool,
) {
	ta.queueProcessAdmissionRetryWithRequirement(
		tracer,
		ie,
		updateTracerProbes,
		false,
	)
}

func (ta *traceAttacher) queueProcessAdmissionRetryWithRequirement(
	tracer *ebpf.ProcessTracer,
	ie *ebpf.Instrumentable,
	updateTracerProbes bool,
	requireCleanupMarker bool,
) {
	if tracer == nil || ie == nil || ie.FileInfo == nil {
		return
	}
	if requireCleanupMarker && pendingAdmissionFileInfo(tracer, ie) == nil {
		return
	}
	if ta.pendingAdmissions == nil {
		ta.pendingAdmissions = map[pendingProcessAdmissionKey]pendingProcessAdmission{}
	}
	eventOwner := triggeringFileInfo(ie)
	key := processAdmissionKey(eventOwner)
	instrumentable := cloneInstrumentableForAdmissionRetry(ie)
	pending := pendingProcessAdmission{
		tracer:             tracer,
		instrumentable:     instrumentable,
		eventOwner:         eventOwner,
		updateTracerProbes: updateTracerProbes,
		accountCreation:    true,
		processRoots:       ta.takeAdmissionProcessRoots(instrumentable),
	}
	if previous, exists := ta.pendingAdmissions[key]; exists {
		if previous.tracer == tracer {
			pending.instrumentable = mergeInstrumentableAdmissionRetries(
				previous.instrumentable,
				instrumentable,
				tracer,
			)
			pending.updateTracerProbes = previous.updateTracerProbes
			pending.eventOwner = previous.eventOwner
			pending.processRoots = mergeAdmissionProcessRoots(
				previous.processRoots,
				pending.processRoots,
			)
			pruneAdmissionProcessRoots(&pending)
		} else {
			pending.processRoots = mergeAdmissionProcessRoots(
				previous.processRoots,
				pending.processRoots,
			)
			previous.processRoots = nil
			cancelPendingProcessAdmission(previous)
		}
	}
	ta.pendingAdmissions[key] = pending
}

func (ta *traceAttacher) queueRejectedMemberAdmissions(
	tracer *ebpf.ProcessTracer,
	rejected []*exec.FileInfo,
) {
	ta.queueMemberAdmissionsWithRoots(tracer, rejected, nil, true)
}

func (ta *traceAttacher) queueMemberAdmissionsWithRoots(
	tracer *ebpf.ProcessTracer,
	fileInfos []*exec.FileInfo,
	ownedRoots map[*exec.FileInfo]*os.File,
	requireCleanupMarker bool,
) map[*exec.FileInfo]struct{} {
	retained := map[*exec.FileInfo]struct{}{}
	for _, fileInfo := range fileInfos {
		if fileInfo == nil || ta.activePIDs[fileInfo.Pid()] == fileInfo {
			continue
		}
		if requireCleanupMarker && !tracer.PIDAdmissionRetryPending(
			fileInfo.Pid(), fileInfo.Ns(), fileInfo,
		) {
			continue
		}
		if ta.pendingAdmissions == nil {
			ta.pendingAdmissions = map[pendingProcessAdmissionKey]pendingProcessAdmission{}
		}
		key := processAdmissionKeyFor(fileInfo, pendingMemberAdmission)
		pending := pendingProcessAdmission{
			tracer:          tracer,
			instrumentable:  &ebpf.Instrumentable{FileInfo: fileInfo},
			processRoots:    map[*exec.FileInfo]*os.File{},
			accountCreation: false,
		}
		if root := ownedRoots[fileInfo]; root != nil {
			pending.processRoots[fileInfo] = root
			delete(ownedRoots, fileInfo)
		} else if root := ta.takeAdmissionProcessRoot(fileInfo); root != nil {
			pending.processRoots[fileInfo] = root
		}
		if previous, exists := ta.pendingAdmissions[key]; exists {
			if previous.tracer == tracer {
				pending.processRoots = mergeAdmissionProcessRoots(
					previous.processRoots,
					pending.processRoots,
				)
			} else {
				pending.processRoots = mergeAdmissionProcessRoots(
					previous.processRoots,
					pending.processRoots,
				)
				previous.processRoots = nil
				cancelPendingProcessAdmission(previous)
			}
		}
		ta.pendingAdmissions[key] = pending
		retained[fileInfo] = struct{}{}
	}
	return retained
}

func triggeringFileInfo(ie *ebpf.Instrumentable) *exec.FileInfo {
	if ie != nil && len(ie.ChildPids) > 0 {
		if fileInfo := ie.FileInfoForPID(ie.ChildPids[0]); fileInfo != nil {
			return fileInfo
		}
	}
	if ie == nil {
		return nil
	}
	return ie.FileInfo
}

func (ta *traceAttacher) takeAdmissionProcessRoots(
	ie *ebpf.Instrumentable,
) map[*exec.FileInfo]*os.File {
	roots := map[*exec.FileInfo]*os.File{}
	take := func(fileInfo *exec.FileInfo) {
		if fileInfo == nil {
			return
		}
		if root := ta.takeAdmissionProcessRoot(fileInfo); root != nil {
			roots[fileInfo] = root
		}
	}
	take(ie.FileInfo)
	for _, pid := range ie.ChildPids {
		take(ie.FileInfoForPID(pid))
	}
	return roots
}

func (ta *traceAttacher) takeAdmissionProcessRoot(fileInfo *exec.FileInfo) *os.File {
	if fileInfo == nil {
		return nil
	}
	if ta.activePIDs[fileInfo.Pid()] == fileInfo {
		return nil
	}
	if root := ta.currentProcessRoots[fileInfo]; root != nil {
		duplicate := duplicateAdmissionProcessRoot(root)
		_ = fileInfo.CloseProcessRoot()
		return duplicate
	}
	if root := fileInfo.DuplicateProcessRoot(); root != nil {
		_ = fileInfo.CloseProcessRoot()
		return root
	}
	for _, pending := range ta.pendingAdmissions {
		if root := pending.processRoots[fileInfo]; root != nil {
			return duplicateAdmissionProcessRoot(root)
		}
	}
	return nil
}

func duplicateAdmissionProcessRoot(root *os.File) *os.File {
	if root == nil {
		return nil
	}
	fd, err := unix.Dup(int(root.Fd()))
	if err != nil {
		return nil
	}
	unix.CloseOnExec(fd)
	duplicate := os.NewFile(uintptr(fd), root.Name())
	if duplicate == nil {
		_ = unix.Close(fd)
	}
	return duplicate
}

func mergeAdmissionProcessRoots(
	previous map[*exec.FileInfo]*os.File,
	current map[*exec.FileInfo]*os.File,
) map[*exec.FileInfo]*os.File {
	for fileInfo, root := range previous {
		if _, exists := current[fileInfo]; !exists {
			current[fileInfo] = root
		} else if root != nil {
			_ = root.Close()
		}
	}
	return current
}

func pruneAdmissionProcessRoots(pending *pendingProcessAdmission) {
	if pending == nil || pending.instrumentable == nil {
		return
	}
	retained := map[*exec.FileInfo]struct{}{
		pending.instrumentable.FileInfo: {},
	}
	for _, pid := range pending.instrumentable.ChildPids {
		if fileInfo := pending.instrumentable.FileInfoForPID(pid); fileInfo != nil {
			retained[fileInfo] = struct{}{}
		}
	}
	for fileInfo, root := range pending.processRoots {
		if _, keep := retained[fileInfo]; keep {
			continue
		}
		if root != nil {
			_ = root.Close()
		}
		delete(pending.processRoots, fileInfo)
	}
}

func cloneInstrumentableForAdmissionRetry(
	ie *ebpf.Instrumentable,
) *ebpf.Instrumentable {
	clone := *ie
	clone.ChildPids = append([]app.PID(nil), ie.ChildPids...)
	clone.ChildFileInfos = make(map[app.PID]*exec.FileInfo, len(ie.ChildFileInfos))
	for pid, fileInfo := range ie.ChildFileInfos {
		clone.ChildFileInfos[pid] = fileInfo
	}
	return &clone
}

func mergeInstrumentableAdmissionRetries(
	previous *ebpf.Instrumentable,
	current *ebpf.Instrumentable,
	tracer *ebpf.ProcessTracer,
) *ebpf.Instrumentable {
	if previous == nil {
		return current
	}
	merged := cloneInstrumentableForAdmissionRetry(current)
	seen := make(map[app.PID]struct{}, len(merged.ChildPids))
	for _, pid := range merged.ChildPids {
		seen[pid] = struct{}{}
	}
	for _, pid := range previous.ChildPids {
		if _, exists := seen[pid]; exists {
			previousFileInfo := previous.FileInfoForPID(pid)
			currentFileInfo := current.FileInfoForPID(pid)
			if previousFileInfo != nil && currentFileInfo != nil &&
				processAdmissionKey(previousFileInfo) != processAdmissionKey(currentFileInfo) {
				tracer.CancelPIDAdmissionRetry(
					pid,
					previousFileInfo.Ns(),
					previousFileInfo,
				)
			}
		} else {
			merged.ChildPids = append(merged.ChildPids, pid)
			seen[pid] = struct{}{}
			merged.ChildFileInfos[pid] = previous.FileInfoForPID(pid)
		}
	}
	return merged
}

func pendingAdmissionFileInfo(
	tracer *ebpf.ProcessTracer,
	ie *ebpf.Instrumentable,
) *exec.FileInfo {
	if tracer.PIDAdmissionRetryPending(
		ie.FileInfo.Pid(), ie.FileInfo.Ns(), ie.FileInfo,
	) {
		return ie.FileInfo
	}
	for _, pid := range ie.ChildPids {
		fileInfo := ie.FileInfoForPID(pid)
		if fileInfo != nil && tracer.PIDAdmissionRetryPending(pid, fileInfo.Ns(), fileInfo) {
			return fileInfo
		}
	}
	return nil
}

func processAdmissionKey(fileInfo *exec.FileInfo) pendingProcessAdmissionKey {
	return processAdmissionKeyFor(fileInfo, pendingGroupAdmission)
}

func processAdmissionKeyFor(
	fileInfo *exec.FileInfo,
	kind pendingAdmissionKind,
) pendingProcessAdmissionKey {
	if fileInfo == nil {
		return pendingProcessAdmissionKey{kind: kind}
	}
	return pendingProcessAdmissionKey{
		pid:       fileInfo.Pid(),
		ns:        fileInfo.Ns(),
		startTime: fileInfo.StartTime(),
		dev:       fileInfo.Dev(),
		ino:       fileInfo.Ino(),
		fileInfo:  fileInfo,
		kind:      kind,
	}
}

func (ta *traceAttacher) removeProcessFromAdmissionRetries(fileInfo *exec.FileInfo) {
	if fileInfo == nil {
		return
	}
	keys := make([]pendingProcessAdmissionKey, 0, len(ta.pendingAdmissions))
	for key := range ta.pendingAdmissions {
		keys = append(keys, key)
	}
	for _, key := range keys {
		pending, exists := ta.pendingAdmissions[key]
		if !exists {
			continue
		}
		ie := pending.instrumentable
		if ie == nil {
			cancelPendingProcessAdmission(pending)
			delete(ta.pendingAdmissions, key)
			continue
		}
		if pending.eventOwner == fileInfo {
			delete(ta.pendingAdmissions, key)
			remaining := instrumentableFileInfosExcept(ie, fileInfo)
			retained := ta.queueMemberAdmissionsWithRoots(
				pending.tracer,
				remaining,
				pending.processRoots,
				false,
			)
			cancelPendingProcessAdmissionExcept(pending, retained)
			continue
		}
		if !rebaseInstrumentableAfterRemoval(ie, fileInfo, pending.eventOwner) {
			continue
		}
		pending.tracer.CancelPIDAdmissionRetry(
			fileInfo.Pid(), fileInfo.Ns(), fileInfo,
		)
		if root := pending.processRoots[fileInfo]; root != nil {
			_ = root.Close()
		}
		delete(pending.processRoots, fileInfo)
		if ie.FileInfo == nil {
			cancelPendingProcessAdmission(pending)
			delete(ta.pendingAdmissions, key)
			continue
		}
		ta.pendingAdmissions[key] = pending
	}
}

func instrumentableFileInfosExcept(
	ie *ebpf.Instrumentable,
	excluded *exec.FileInfo,
) []*exec.FileInfo {
	if ie == nil {
		return nil
	}
	fileInfos := make([]*exec.FileInfo, 0, len(ie.ChildPids)+1)
	seen := map[*exec.FileInfo]struct{}{}
	appendFileInfo := func(fileInfo *exec.FileInfo) {
		if fileInfo == nil || fileInfo == excluded {
			return
		}
		if _, exists := seen[fileInfo]; exists {
			return
		}
		seen[fileInfo] = struct{}{}
		fileInfos = append(fileInfos, fileInfo)
	}
	appendFileInfo(ie.FileInfo)
	for _, pid := range ie.ChildPids {
		appendFileInfo(ie.FileInfoForPID(pid))
	}
	return fileInfos
}

func rebaseInstrumentableAfterRemoval(
	ie *ebpf.Instrumentable,
	removed *exec.FileInfo,
	preferredPrimary *exec.FileInfo,
) bool {
	if ie == nil || removed == nil {
		return false
	}
	allFileInfos := instrumentableFileInfosExcept(ie, nil)
	found := false
	remaining := make([]*exec.FileInfo, 0, len(allFileInfos))
	for _, fileInfo := range allFileInfos {
		if fileInfo == removed {
			found = true
			continue
		}
		remaining = append(remaining, fileInfo)
	}
	if !found {
		return false
	}
	if len(remaining) == 0 {
		ie.FileInfo = nil
		ie.ChildPids = nil
		ie.ChildFileInfos = nil
		return true
	}

	primary := ie.FileInfo
	if primary == removed {
		primary = nil
		for _, candidate := range remaining {
			if candidate == preferredPrimary {
				primary = candidate
				break
			}
		}
		if primary == nil {
			primary = remaining[0]
		}
	}
	ie.FileInfo = primary
	ie.ChildPids = ie.ChildPids[:0]
	ie.ChildFileInfos = make(map[app.PID]*exec.FileInfo, len(remaining)-1)
	for _, fileInfo := range remaining {
		if fileInfo == primary {
			continue
		}
		ie.ChildPids = append(ie.ChildPids, fileInfo.Pid())
		ie.ChildFileInfos[fileInfo.Pid()] = fileInfo
	}
	return true
}

func (ta *traceAttacher) cancelInstrumentableAdmissionRetries(
	ie *ebpf.Instrumentable,
) {
	if ie == nil || ie.FileInfo == nil {
		return
	}
	keys := []pendingProcessAdmissionKey{
		processAdmissionKey(triggeringFileInfo(ie)),
	}
	if ta.activePIDs[ie.FileInfo.Pid()] == ie.FileInfo {
		keys = append(keys, processAdmissionKeyFor(ie.FileInfo, pendingMemberAdmission))
	}
	for _, pid := range ie.ChildPids {
		if fileInfo := ie.FileInfoForPID(pid); fileInfo != nil &&
			ta.activePIDs[pid] == fileInfo {
			keys = append(keys, processAdmissionKeyFor(fileInfo, pendingMemberAdmission))
		}
	}
	for _, key := range keys {
		if pending, exists := ta.pendingAdmissions[key]; exists {
			cancelPendingProcessAdmission(pending)
			delete(ta.pendingAdmissions, key)
		}
	}
}

func (ta *traceAttacher) cancelAllProcessAdmissionRetries() {
	for key, pending := range ta.pendingAdmissions {
		cancelPendingProcessAdmission(pending)
		delete(ta.pendingAdmissions, key)
	}
}

func cancelPendingProcessAdmission(pending pendingProcessAdmission) {
	cancelPendingProcessAdmissionExcept(pending, nil)
}

func cancelPendingProcessAdmissionExcept(
	pending pendingProcessAdmission,
	retained map[*exec.FileInfo]struct{},
) {
	defer closeAdmissionProcessRoots(pending.processRoots)
	if pending.tracer == nil || pending.instrumentable == nil {
		return
	}
	ie := pending.instrumentable
	if _, keep := retained[ie.FileInfo]; ie.FileInfo != nil && !keep {
		pending.tracer.CancelPIDAdmissionRetry(
			ie.FileInfo.Pid(), ie.FileInfo.Ns(), ie.FileInfo,
		)
	}
	for _, pid := range ie.ChildPids {
		if fileInfo := ie.FileInfoForPID(pid); fileInfo != nil {
			if _, keep := retained[fileInfo]; keep {
				continue
			}
			pending.tracer.CancelPIDAdmissionRetry(pid, fileInfo.Ns(), fileInfo)
		}
	}
}

func closeAdmissionProcessRoots(roots map[*exec.FileInfo]*os.File) {
	for _, root := range roots {
		if root != nil {
			_ = root.Close()
		}
	}
}

// installAdmissionReplayProcessRoots gives each replayed tracer call a fresh
// descriptor while keeping the attacher-owned descriptor as the stable
// identity authority. A tracer may claim the fresh descriptor with
// FileInfo.TakeProcessRoot; otherwise cleanup closes it after the call.
func installAdmissionReplayProcessRoots(
	ie *ebpf.Instrumentable,
	roots map[*exec.FileInfo]*os.File,
) func() {
	installed := map[*exec.FileInfo]*os.File{}
	for _, fileInfo := range instrumentableFileInfosExcept(ie, nil) {
		root := duplicateAdmissionProcessRoot(roots[fileInfo])
		if root == nil {
			continue
		}
		if !fileInfo.InstallProcessRoot(root) {
			_ = root.Close()
			continue
		}
		installed[fileInfo] = root
	}
	return func() {
		for fileInfo, root := range installed {
			if unclaimed := fileInfo.TakeProcessRootIf(root); unclaimed != nil {
				_ = unclaimed.Close()
			}
		}
	}
}

func (ta *traceAttacher) retryPendingProcessAdmissions() {
	keys := make([]pendingProcessAdmissionKey, 0, len(ta.pendingAdmissions))
	for key := range ta.pendingAdmissions {
		keys = append(keys, key)
	}
	for _, key := range keys {
		pending, exists := ta.pendingAdmissions[key]
		if !exists {
			continue
		}
		if pending.tracer == nil || pending.instrumentable == nil ||
			pending.instrumentable.FileInfo == nil {
			cancelPendingProcessAdmission(pending)
			delete(ta.pendingAdmissions, key)
			continue
		}
		identityMatches := func(fileInfo *exec.FileInfo) bool {
			if ta.pendingIdentityCheck != nil {
				return ta.pendingIdentityCheck(fileInfo, pending.processRoots[fileInfo])
			}
			return fileInfo != nil &&
				processStartTimeMatches(fileInfo.Pid(), fileInfo.StartTime())
		}
		pendingIdentityMatches := func(fileInfo *exec.FileInfo) bool {
			return fileInfo != nil &&
				(ta.activePIDs[fileInfo.Pid()] == fileInfo || identityMatches(fileInfo))
		}
		if !pendingIdentityMatches(pending.instrumentable.FileInfo) {
			ta.removeProcessFromAdmissionRetries(pending.instrumentable.FileInfo)
			continue
		}
		for _, pid := range append([]app.PID(nil), pending.instrumentable.ChildPids...) {
			fileInfo := pending.instrumentable.FileInfoForPID(pid)
			if fileInfo != nil && !pendingIdentityMatches(fileInfo) {
				ta.removeProcessFromAdmissionRetries(fileInfo)
			}
		}
		pending, exists = ta.pendingAdmissions[key]
		if !exists {
			continue
		}
		eventOwner := pending.eventOwner
		if eventOwner == nil {
			eventOwner = pending.instrumentable.FileInfo
		}
		ie := pending.instrumentable
		completeCreation := pending.accountCreation && pending.eventOwner != nil &&
			!ta.processCreationOwnerActive(pending.eventOwner)
		if completeCreation && pending.updateTracerProbes {
			probeTarget := instrumentableForEventOwner(ie, eventOwner)
			previousRoots := ta.currentProcessRoots
			ta.currentProcessRoots = pending.processRoots
			identityBefore := identityMatches(eventOwner)
			probesUpdated := identityBefore && ta.updateTracerProbes(
				pending.tracer,
				probeTarget,
				func() bool { return identityMatches(eventOwner) },
			)
			ta.currentProcessRoots = previousRoots
			if !probesUpdated {
				if !identityBefore || !identityMatches(eventOwner) {
					ta.removeProcessFromAdmissionRetries(eventOwner)
				}
				continue
			}
			ie.ExecutableGeneration = probeTarget.ExecutableGeneration
			pending.updateTracerProbes = false
			ta.pendingAdmissions[key] = pending
		}
		closeReplayProcessRoots := installAdmissionReplayProcessRoots(
			pending.instrumentable,
			pending.processRoots,
		)
		result := ta.monitorPIDsWithIdentity(
			pending.tracer,
			pending.instrumentable,
			identityMatches,
			eventOwner,
		)
		closeReplayProcessRoots()
		if !result.admitted {
			if !pendingIdentityMatches(pending.instrumentable.FileInfo) {
				ta.removeProcessFromAdmissionRetries(pending.instrumentable.FileInfo)
				continue
			}
			if pendingAdmissionFileInfo(pending.tracer, pending.instrumentable) == nil {
				cancelPendingProcessAdmission(pending)
				delete(ta.pendingAdmissions, key)
			}
			continue
		}

		ie.Tracer = pending.tracer
		if pending.accountCreation {
			if ta.existingTracers == nil {
				ta.existingTracers = map[ebpf.ExecutableKey]executableTracer{}
			}
			ta.existingTracers[executableKey(eventOwner)] = executableTracer{
				tracer:     pending.tracer,
				generation: ie.ExecutableGeneration,
			}
		}
		retained := ta.queueMemberAdmissionsWithRoots(
			pending.tracer,
			result.rejected,
			pending.processRoots,
			true,
		)
		if !pending.accountCreation &&
			ta.pendingCreationOwnsFileInfo(key, pending.tracer, ie.FileInfo) {
			retained[ie.FileInfo] = struct{}{}
		}
		cancelPendingProcessAdmissionExcept(pending, retained)
		delete(ta.pendingAdmissions, key)
		if pending.accountCreation {
			ta.cancelInstrumentableAdmissionRetries(ie)
		}
		if completeCreation {
			if ta.Metrics != nil {
				ta.Metrics.InstrumentProcess(eventOwner.ExecutableName())
			}
			ta.completeProcessCreationForOwner(ie, pending.eventOwner)
		}
	}
}

func (ta *traceAttacher) pendingCreationOwnsFileInfo(
	excludedKey pendingProcessAdmissionKey,
	tracer *ebpf.ProcessTracer,
	fileInfo *exec.FileInfo,
) bool {
	for key, pending := range ta.pendingAdmissions {
		if key == excludedKey || !pending.accountCreation {
			continue
		}
		if pending.tracer == tracer && pending.eventOwner == fileInfo {
			return true
		}
	}
	return false
}

func (ta *traceAttacher) init() error {
	if err := removeMemlock(); err != nil {
		return fmt.Errorf("removing memory lock: %w", err)
	}
	return nil
}
