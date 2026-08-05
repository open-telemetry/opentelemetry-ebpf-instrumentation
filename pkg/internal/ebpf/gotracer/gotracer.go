// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gotracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	ebpfsampling "go.opentelemetry.io/obi/pkg/internal/ebpf/sampling"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 Bpf ../../../../bpf/gotracer/gotracer.c -- -I../../../../bpf

type runtimeMetricTargetKey struct {
	pid app.PID
	ns  uint32
}

// goExecutableKey mirrors go_executable_key_t in bpf/gotracer/go_offsets.h.
// Canonical major/minor components avoid the different dev_t encodings used
// by kernel memory and userspace stat results.
type goExecutableKey struct {
	DevMajor uint32
	DevMinor uint32
	Ino      uint64
}

func goExecutableKeyFor(fileInfo *exec.FileInfo) (goExecutableKey, bool) {
	if fileInfo == nil {
		return goExecutableKey{}, false
	}
	return goExecutableKey{
		DevMajor: unix.Major(fileInfo.Dev()),
		DevMinor: unix.Minor(fileInfo.Dev()),
		Ino:      fileInfo.Ino(),
	}, true
}

type goSpanOptionFunctionKey struct {
	HostPID    uint64
	Generation uint64
	Function   uint64
}

type goProcessKey struct {
	PID        uint64
	Generation uint64
}

type goProcessGenerationValue struct {
	Generation uint64
	StartTime  uint64
}

type goSpanOptionFunction struct {
	entry      uint64
	optionType uint8
}

const (
	goSpanOptionKind                  uint8  = 1
	goSpanOptionNewRoot               uint8  = 2
	goAutoSDKFirstRequiredTailCall           = 15
	goAutoSDKLastRequiredTailCall            = 18
	goHTTP2ValidateTailCall                  = 19
	goHTTPContinuationTailCall               = 20
	goHTTP2FinishClientTailCall              = 21
	goHTTP2ParseServerHeadersTailCall        = 22
	goTailCallCount                          = goHTTP2ParseServerHeadersTailCall + 1
	goAutoSDKMaxInflightCalls         uint32 = 30_000
	goAutoSDKInflightPoisonShift             = 32
)

type goSpanOptionMap interface {
	Put(key, value any) error
	Delete(key any) error
}

type goAutoSDKTypeInfoMap interface {
	Put(key, value any) error
	Delete(key any) error
}

type goProcessGenerationMap interface {
	Put(key, value any) error
	Delete(key any) error
}

type goAutoSDKFlagMap interface {
	Lookup(key, valueOut any) error
	Put(key, value any) error
	Delete(key any) error
}

type goAutoSDKReadinessMap interface {
	Lookup(key, valueOut any) error
}

type goAutoSDKOuterCallMap interface {
	Lookup(key, valueOut any) error
	NextKey(key, nextKeyOut any) error
	Delete(key any) error
}

type goAutoSDKInflightMap interface {
	Lookup(key, valueOut any) error
	Update(key, value any, flags ebpf.MapUpdateFlags) error
	Delete(key any) error
}

type goAutoSDKProcessAccess interface {
	Open(*os.File, *exec.FileInfo) (goAutoSDKProcessSession, error)
}

var errGoAutoSDKProcessMemoryGone = errors.New(
	"exact process memory is no longer available",
)

type goAutoSDKProcessSession interface {
	io.Closer
	Read(addr uint64) (byte, error)
	Write(addr uint64, value byte) error
	StartTime() (uint64, error)
}

type goAutoSDKEventReader interface {
	io.Closer
	Read() (ringbuf.Record, error)
}

type goAutoSDKFlagValue struct {
	FlagPtr   uint64
	StartTime uint64
	Epoch     uint32
	Activated uint8
	Pad       [3]uint8
}

type goAutoSDKReadinessValue struct {
	StartTime          uint64
	Epoch              uint32
	ConfigEpoch        uint32
	Ready              uint8
	AutoSDKGlobalReady uint8
	Pad                [6]uint8
}

type goAddrKey struct {
	PID  uint64
	Addr uint64
}

type goAutoSDKOuterCallValue struct {
	StartTime       uint64
	Generation      uint64
	FlagPtr         uint64
	Epoch           uint32
	State           uint8
	DirectEntryKind uint8
	DirectDepth     uint8
	RejectedReturns uint8
}

type goAutoSDKInflightKey struct {
	PID        uint64
	Generation uint64
	StartTime  uint64
	Epoch      uint32
	Pad        uint32
}

type goAutoSDKInflightValue struct {
	State uint64
}

func (v goAutoSDKInflightValue) activeCalls() uint32 {
	return uint32(v.State)
}

func (v goAutoSDKInflightValue) poisonGeneration() uint32 {
	return uint32(v.State >> goAutoSDKInflightPoisonShift)
}

type goAutoSDKFlagState struct {
	key             goProcessKey
	flagPtr         uint64
	startTime       uint64
	epoch           uint32
	original        byte
	globalProtocol  bool
	restoreRequired bool
	discardRequired bool
	incarnation     *goAutoSDKProcessIncarnation
	fileInfo        *exec.FileInfo
}

type goAutoSDKAdmissionState struct {
	startTime            uint64
	executable           goExecutableKey
	samplerReady         bool
	generationReady      bool
	optionFunctionsReady bool
	typeInfoReady        bool
	globalReady          bool
	globalPatchReady     bool
	authorityActive      bool
	fileInfo             *exec.FileInfo
}

type goProcessAdmissionState struct {
	startTime       uint64
	generationReady bool
	fileInfo        *exec.FileInfo
	processRoot     *goAutoSDKProcessRoot
}

// goProcessAdmissionRetryKey records attacher replay debt separately from the
// internal restoration queue. Background cleanup may settle the restoration
// queue, but only a successful replay or explicit cancellation settles this
// exact process-incarnation admission.
type goProcessAdmissionRetryKey struct {
	process   runtimeMetricTargetKey
	startTime uint64
	fileInfo  *exec.FileInfo
}

type goAutoSDKRestoreRetryKey struct {
	process   runtimeMetricTargetKey
	startTime uint64
	fileInfo  *exec.FileInfo
}

type samplerLifecycleManager interface {
	InstallGlobal() bool
	AllowPIDForProcess(
		app.PID,
		uint32,
		uint64,
		*services.CanonicalSampler,
		bool,
	) bool
	FallbackSafeForProcessIncarnation(app.PID, uint32, uint64) bool
	EnableAutoSDK(app.PID, uint32) bool
	EnableAutoSDKWithSetup(
		app.PID,
		uint32,
		func(hostPID uint32, startTime uint64, epoch uint32) bool,
	) bool
	EnableAutoSDKWithSetupMode(
		app.PID,
		uint32,
		bool,
		func(hostPID uint32, startTime uint64, epoch uint32) bool,
	) bool
	QuiesceAutoSDKForProcess(app.PID, uint32, uint64) bool
	BlockPIDForProcess(app.PID, uint32, uint64) bool
}

type goProcessGenerationState struct {
	hostPID    uint32
	generation uint64
	fileInfo   *exec.FileInfo
	retired    bool
}

type goHTTP2ServerOffsetAvailability struct {
	xNet     bool
	vendored bool
}

type goProcessHostPIDResolver func(app.PID, uint32) (uint32, error)

const missingGoOffset = ^uint64(0)

// Mirrors go_runtime_metric_valid_t in bpf/gotracer/maps/runtime.h. Scalar
// bits also mirror the raw snapshot masks in pkg/runtimemetrics/reader.go.
const (
	goRuntimeMetricGCCyclesMask                  uint64 = 1 << 0
	goRuntimeMetricMemoryLimitMask               uint64 = 1 << 1
	goRuntimeMetricProcessorLimitMask            uint64 = 1 << 2
	goRuntimeMetricGOGCMask                      uint64 = 1 << 3
	goRuntimeMetricCPUTimeMask                   uint64 = 1 << 4
	goRuntimeMetricMemoryUsedMask                uint64 = 1 << 5
	goRuntimeMetricMemoryAllocsMask              uint64 = 1 << 6
	goRuntimeMetricGCPauseHistogramMask          uint64 = 1 << 7
	goRuntimeMetricScheduleDurationHistogramMask uint64 = 1 << 8
	goRuntimeMetricGoroutineCountMask            uint64 = 1 << 9
	goRuntimeMetricMemoryGCGoalMask              uint64 = 1 << 10
)

type goRuntimeGCGoalSource uint32

const (
	goRuntimeGCGoalSourceNone goRuntimeGCGoalSource = iota
	goRuntimeGCGoalSourceHeapGoalField
	goRuntimeGCGoalSourcePaceScavengerArgument
)

const goRuntimeMetricBaseMask = goRuntimeMetricGCCyclesMask | goRuntimeMetricGOGCMask

const goRuntimeMetricHeapSnapshotMask = goRuntimeMetricMemoryUsedMask |
	goRuntimeMetricMemoryAllocsMask

const goRuntimeMetricHistogramMask = goRuntimeMetricGCPauseHistogramMask |
	goRuntimeMetricScheduleDurationHistogramMask

const (
	goRuntimeHistogramMaxBuckets uint64 = 160
	goRuntimeHistogramBucketSize uint64 = 8
)

var goChannelOffsetFields = [...]goexec.GoOffset{
	goexec.HchanQcountPos,
	goexec.HchanDataqsizPos,
	goexec.HchanSendxPos,
	goexec.HchanRecvxPos,
}

var goRuntimeMetricOffsetFields = [...]goexec.GoOffset{
	goexec.RuntimeMemstatsNumGCPos,
	goexec.RuntimeGCControllerMemoryLimitPos,
	goexec.RuntimeGCControllerGCPercentPos,
	goexec.RuntimeWorkCPUStatsPos,
	goexec.RuntimeCPUStatsGCAssistTimePos,
	goexec.RuntimeCPUStatsGCDedicatedTimePos,
	goexec.RuntimeCPUStatsGCIdleTimePos,
	goexec.RuntimeCPUStatsGCPauseTimePos,
	goexec.RuntimeCPUStatsScavengeAssistTimePos,
	goexec.RuntimeCPUStatsScavengeBgTimePos,
	goexec.RuntimeCPUStatsIdleTimePos,
	goexec.RuntimeCPUStatsUserTimePos,
	goexec.RuntimeMemstatsHeapStatsPos,
	goexec.RuntimeMemstatsStacksSysPos,
	goexec.RuntimeMemstatsMspanSysPos,
	goexec.RuntimeMemstatsMcacheSysPos,
	goexec.RuntimeMemstatsBuckhashSysPos,
	goexec.RuntimeMemstatsGCMiscSysPos,
	goexec.RuntimeMemstatsOtherSysPos,
	goexec.RuntimeConsistentHeapStatsStatsPos,
	goexec.RuntimeHeapStatsDeltaCommittedPos,
	goexec.RuntimeHeapStatsDeltaInStacksPos,
	goexec.RuntimeHeapStatsDeltaLargeAllocPos,
	goexec.RuntimeHeapStatsDeltaLargeAllocCountPos,
	goexec.RuntimeHeapStatsDeltaSmallAllocCountPos,
	goexec.RuntimeHeapStatsDeltaSmallFreeCountPos,
	goexec.RuntimeSchedNgSysPos,
	goexec.RuntimeSchedGFreeStackPos,
	goexec.RuntimeSchedGFreeNoStackPos,
	goexec.RuntimePFreeGPos,
	goexec.RuntimeGListSizePos,
	goexec.RuntimeGCControllerHeapGoalPos,
	goexec.RuntimeSchedTimeToRunPos,
	goexec.RuntimeSchedSTWTotalTimeGCPos,
	goexec.RuntimeTimeHistogramUnderflowPos,
	goexec.RuntimeTimeHistogramOverflowPos,
}

var goRuntimeCPUTimeOffsetFields = [...]goexec.GoOffset{
	goexec.RuntimeWorkCPUStatsPos,
	goexec.RuntimeCPUStatsGCAssistTimePos,
	goexec.RuntimeCPUStatsGCDedicatedTimePos,
	goexec.RuntimeCPUStatsGCIdleTimePos,
	goexec.RuntimeCPUStatsGCPauseTimePos,
	goexec.RuntimeCPUStatsScavengeAssistTimePos,
	goexec.RuntimeCPUStatsScavengeBgTimePos,
	goexec.RuntimeCPUStatsIdleTimePos,
	goexec.RuntimeCPUStatsUserTimePos,
}

var goRuntimeMemoryOffsetFields = [...]goexec.GoOffset{
	goexec.RuntimeMemstatsHeapStatsPos,
	goexec.RuntimeMemstatsStacksSysPos,
	goexec.RuntimeMemstatsMspanSysPos,
	goexec.RuntimeMemstatsMcacheSysPos,
	goexec.RuntimeMemstatsBuckhashSysPos,
	goexec.RuntimeMemstatsGCMiscSysPos,
	goexec.RuntimeMemstatsOtherSysPos,
	goexec.RuntimeConsistentHeapStatsStatsPos,
	goexec.RuntimeHeapStatsDeltaCommittedPos,
	goexec.RuntimeHeapStatsDeltaInStacksPos,
	goexec.RuntimeHeapStatsDeltaLargeAllocPos,
	goexec.RuntimeHeapStatsDeltaLargeAllocCountPos,
	goexec.RuntimeHeapStatsDeltaSmallAllocCountPos,
	goexec.RuntimeHeapStatsDeltaSmallFreeCountPos,
}

var goRuntimeGoroutineCountCommonOffsetFields = [...]goexec.GoOffset{
	goexec.RuntimeSchedGFreeStackPos,
	goexec.RuntimeSchedGFreeNoStackPos,
	goexec.RuntimePFreeGPos,
	goexec.RuntimeGListSizePos,
}

var goRuntimeMetricOffsetGroups = [...]struct {
	mask   uint64
	fields []goexec.GoOffset
}{
	{goRuntimeMetricGCCyclesMask, []goexec.GoOffset{goexec.RuntimeMemstatsNumGCPos}},
	{goRuntimeMetricMemoryLimitMask, []goexec.GoOffset{goexec.RuntimeGCControllerMemoryLimitPos}},
	{goRuntimeMetricGOGCMask, []goexec.GoOffset{goexec.RuntimeGCControllerGCPercentPos}},
	{goRuntimeMetricCPUTimeMask, goRuntimeCPUTimeOffsetFields[:]},
	{goRuntimeMetricMemoryUsedMask | goRuntimeMetricMemoryAllocsMask, goRuntimeMemoryOffsetFields[:]},
	{goRuntimeMetricGCPauseHistogramMask, []goexec.GoOffset{
		goexec.RuntimeSchedSTWTotalTimeGCPos,
		goexec.RuntimeTimeHistogramUnderflowPos,
		goexec.RuntimeTimeHistogramOverflowPos,
	}},
	{goRuntimeMetricScheduleDurationHistogramMask, []goexec.GoOffset{
		goexec.RuntimeSchedTimeToRunPos,
		goexec.RuntimeTimeHistogramUnderflowPos,
		goexec.RuntimeTimeHistogramOverflowPos,
	}},
}

type Tracer struct {
	processMu                           sync.Mutex
	log                                 *slog.Logger
	pidsFilter                          ebpfcommon.ServiceFilter
	cfg                                 *config.EBPFTracer
	shutdownTimeout                     time.Duration
	metrics                             imetrics.Reporter
	bpfObjects                          BpfObjects
	resourcesMu                         sync.Mutex
	resources                           *goTracerResources
	disabledRouteHarvesting             bool
	supportsBPFLoop                     bool
	runtimeMetricTargetKeys             map[runtimeMetricTargetKey]BpfPidInfo
	goChannelOffsetsByExecutable        map[goExecutableKey]bool
	goHTTP2ServerOffsetsByExecutable    map[goExecutableKey]goHTTP2ServerOffsetAvailability
	goAutoSDKEligibleByExecutable       map[goExecutableKey]bool
	goAutoSDKReadyByExecutable          map[goExecutableKey]bool
	goAutoSDKGlobalEligibleByExecutable map[goExecutableKey]bool
	goAutoSDKGlobalReadyByExecutable    map[goExecutableKey]bool
	goAutoSDKTypesByExecutable          map[goExecutableKey]goexec.GoAutoSDKTypeInfo
	goAutoSDKProbesByExecutable         map[goExecutableKey][]string
	goAutoSDKGlobalProbesByExecutable   map[goExecutableKey][]string
	goSpanOptionFuncsByExecutable       map[goExecutableKey][]goSpanOptionFunction
	goSpanOptionKeysByProcess           map[runtimeMetricTargetKey][]goSpanOptionFunctionKey
	goSpanOptionFunctions               goSpanOptionMap
	goAutoSDKTypeInfos                  goAutoSDKTypeInfoMap
	goProcessGenerations                goProcessGenerationMap
	goAutoSDKFlags                      goAutoSDKFlagMap
	goAutoSDKReadiness                  goAutoSDKReadinessMap
	goAutoSDKOuterCalls                 goAutoSDKOuterCallMap
	goAutoSDKInflight                   goAutoSDKInflightMap
	goProcessGenerationByPID            map[runtimeMetricTargetKey]goProcessGenerationState
	goProcessOwnerByHostPID             map[uint32]runtimeMetricTargetKey
	goProcessAdmissions                 map[runtimeMetricTargetKey]goProcessAdmissionState
	goProcessAdmissionRetries           map[goProcessAdmissionRetryKey]struct{}
	newGoProcessGeneration              func() (uint64, error)
	resolveGoProcessHostPID             goProcessHostPIDResolver
	goAutoSDKProcessAccess              goAutoSDKProcessAccess
	newGoAutoSDKEventReader             func(*ebpf.Map) (goAutoSDKEventReader, error)
	goAutoSDKEventReader                goAutoSDKEventReader
	goAutoSDKEventWG                    sync.WaitGroup
	goAutoSDKRestoreRetryWG             sync.WaitGroup
	goAutoSDKRestoreRetrying            bool
	goAutoSDKRestoreRetries             map[goAutoSDKRestoreRetryKey]bool
	goAutoSDKDiscoveryReady             bool
	goAutoSDKRunStarted                 bool
	goAutoSDKAdmissions                 map[runtimeMetricTargetKey]goAutoSDKAdmissionState
	goAutoSDKFlagStates                 map[runtimeMetricTargetKey]goAutoSDKFlagState
	goAutoSDKQuiescing                  map[runtimeMetricTargetKey]bool
	goAutoSDKDirectEntryClosers         []io.Closer
	goAutoSDKDirectEntryAttaching       int
	goAutoSDKDirectEntryClosing         int
	goAutoSDKDirectEntryBarrierClosed   bool
	goAutoSDKGlobalEntryClosers         []io.Closer
	goAutoSDKGlobalEntryAttaching       int
	goAutoSDKGlobalEntryClosing         int
	goAutoSDKGlobalEntryBarrierClosed   bool
	goAutoSDKShuttingDown               bool
	goAutoSDKShutdownMu                 sync.Mutex
	goAutoSDKShutdownComplete           bool
	goAutoSDKEventDone                  chan struct{}
	goAutoSDKRestoreRetryDone           chan struct{}
	goAutoSDKDrainPause                 func()
	goAutoSDKRestoreRetryPause          func()
	goRuntimeMetricMaskByExecutable     map[goExecutableKey]uint64
	goRuntimeGCGoalSourceByExecutable   map[goExecutableKey]goRuntimeGCGoalSource
	goAutoSDKTypeInfoKeys               map[runtimeMetricTargetKey]goProcessKey
	goAutoSDKPreAdmissionReady          bool
	goAutoSDKTailCallsReady             bool
	currentBinaryExecutable             goExecutableKey
	samplerConfig                       services.CanonicalSampler
	samplerManager                      samplerLifecycleManager
}

func New(
	pidFilter ebpfcommon.ServiceFilter,
	cfg *obi.Config,
	metrics imetrics.Reporter,
) *Tracer {
	log := slog.With("component", "go.Tracer")
	samplerConfig, err := cfg.Traces.SamplerConfig.Canonical()
	if err != nil {
		log.Error("invalid sampler configuration", "error", err)
	}

	disabledRouteHarvesting := false

	for _, lang := range cfg.Discovery.DisabledRouteHarvesters {
		if lang == services.RouteHarvesterLanguageGo {
			disabledRouteHarvesting = true
			break
		}
	}

	return &Tracer{
		log:                                 log,
		pidsFilter:                          pidFilter,
		cfg:                                 &cfg.EBPF,
		shutdownTimeout:                     cfg.ShutdownTimeout,
		metrics:                             metrics,
		disabledRouteHarvesting:             disabledRouteHarvesting,
		supportsBPFLoop:                     ebpfcommon.SupportsEBPFLoops(log, cfg.EBPF.OverrideBPFLoopEnabled),
		runtimeMetricTargetKeys:             map[runtimeMetricTargetKey]BpfPidInfo{},
		goChannelOffsetsByExecutable:        map[goExecutableKey]bool{},
		goHTTP2ServerOffsetsByExecutable:    map[goExecutableKey]goHTTP2ServerOffsetAvailability{},
		goAutoSDKEligibleByExecutable:       map[goExecutableKey]bool{},
		goAutoSDKReadyByExecutable:          map[goExecutableKey]bool{},
		goAutoSDKGlobalEligibleByExecutable: map[goExecutableKey]bool{},
		goAutoSDKGlobalReadyByExecutable:    map[goExecutableKey]bool{},
		goAutoSDKTypesByExecutable:          map[goExecutableKey]goexec.GoAutoSDKTypeInfo{},
		goAutoSDKProbesByExecutable:         map[goExecutableKey][]string{},
		goAutoSDKGlobalProbesByExecutable:   map[goExecutableKey][]string{},
		goSpanOptionFuncsByExecutable:       map[goExecutableKey][]goSpanOptionFunction{},
		goSpanOptionKeysByProcess:           map[runtimeMetricTargetKey][]goSpanOptionFunctionKey{},
		goProcessGenerationByPID:            map[runtimeMetricTargetKey]goProcessGenerationState{},
		goProcessOwnerByHostPID:             map[uint32]runtimeMetricTargetKey{},
		goProcessAdmissions:                 map[runtimeMetricTargetKey]goProcessAdmissionState{},
		goProcessAdmissionRetries:           map[goProcessAdmissionRetryKey]struct{}{},
		newGoProcessGeneration:              randomGoProcessGeneration,
		resolveGoProcessHostPID:             resolveGoProcessHostPID,
		goAutoSDKProcessAccess:              newGoAutoSDKProcessAccess(),
		goAutoSDKRestoreRetries:             map[goAutoSDKRestoreRetryKey]bool{},
		goAutoSDKAdmissions:                 map[runtimeMetricTargetKey]goAutoSDKAdmissionState{},
		goAutoSDKFlagStates:                 map[runtimeMetricTargetKey]goAutoSDKFlagState{},
		goAutoSDKQuiescing:                  map[runtimeMetricTargetKey]bool{},
		goRuntimeMetricMaskByExecutable:     map[goExecutableKey]uint64{},
		goRuntimeGCGoalSourceByExecutable:   map[goExecutableKey]goRuntimeGCGoalSource{},
		goAutoSDKTypeInfoKeys:               map[runtimeMetricTargetKey]goProcessKey{},
		samplerConfig:                       samplerConfig,
	}
}

func (p *Tracer) AllowPID(pid app.PID, ns uint32, fi *exec.FileInfo) {
	p.AllowPIDForProcess(pid, ns, fi)
}

func (p *Tracer) AllowPIDForProcess(pid app.PID, ns uint32, fi *exec.FileInfo) bool {
	p.processMu.Lock()
	defer p.processMu.Unlock()

	if p.goAutoSDKShuttingDown || p.goAutoSDKShutdownComplete {
		p.pidsFilter.BlockPID(pid, ns)
		return false
	}

	process := runtimeMetricTargetKey{pid: pid, ns: ns}
	if !p.prepareGoProcessAdmissionLocked(process, fi) {
		p.markGoProcessAdmissionRetryLocked(process, fi)
		p.blockIndeterminateProcess(pid, ns)
		return false
	}
	if p.goAutoSDKQuiescing == nil {
		p.goAutoSDKQuiescing = map[runtimeMetricTargetKey]bool{}
	}
	p.goAutoSDKQuiescing[process] = true
	if !p.restoreGoAutoSDKFlag(process) {
		p.queueGoAutoSDKRestoreRetryLocked(
			process,
			p.goAutoSDKRestorationStartTime(process, fi.StartTime()),
			true,
		)
		p.markGoProcessAdmissionRetryLocked(process, fi)
		p.blockIndeterminateProcess(pid, ns)
		return false
	}
	processRoot := p.retainedGoProcessRootLocked(process, fi)
	if p.goProcessAdmissions == nil {
		p.goProcessAdmissions = map[runtimeMetricTargetKey]goProcessAdmissionState{}
	}
	p.goProcessAdmissions[process] = goProcessAdmissionState{
		startTime:   fi.StartTime(),
		fileInfo:    fi,
		processRoot: processRoot,
	}

	samplerReady := false
	autoSDKQuiesced := false
	if p.samplerManager != nil {
		attrs := fi.ServiceAttrs()
		samplerReady = p.samplerManager.AllowPIDForProcess(
			pid, ns, fi.StartTime(), attrs.SamplerConfig, false,
		)
		autoSDKQuiesced = p.samplerManager.QuiesceAutoSDKForProcess(
			pid, ns, fi.StartTime(),
		)
		if !autoSDKQuiesced ||
			!p.samplerManager.FallbackSafeForProcessIncarnation(pid, ns, fi.StartTime()) {
			samplerReady = false
			autoSDKQuiesced = p.restoreSamplerFallback(pid, ns, fi.StartTime())
			if !autoSDKQuiesced {
				p.queueGoAutoSDKRestoreRetryLocked(process, fi.StartTime(), true)
				p.markGoProcessAdmissionRetryLocked(process, fi)
				p.blockIndeterminateProcess(pid, ns)
				return false
			}
		}
	}

	generationReady := p.registerGoProcessGeneration(pid, ns, fi)
	optionFunctionsReady := p.registerGoSpanOptionFunctions(pid, ns, fi)
	typeInfoReady := p.registerGoAutoSDKTypeInfo(pid, ns, fi)
	executable, _ := goExecutableKeyFor(fi)
	autoSDKDirectReady := p.goAutoSDKReadyByExecutable[executable]
	autoSDKGlobalReady := p.goAutoSDKGlobalReadyByExecutable[executable]
	autoSDKPotential := p.samplerManager != nil &&
		samplerReady && autoSDKQuiesced &&
		generationReady && optionFunctionsReady && typeInfoReady &&
		(autoSDKDirectReady || autoSDKGlobalReady)
	processRoot = p.prepareGoProcessRootLocked(
		process,
		fi,
		autoSDKPotential && autoSDKGlobalReady,
	)
	globalPatchReady := autoSDKPotential && autoSDKGlobalReady &&
		processRoot != nil && processRoot.file != nil
	p.goProcessAdmissions[process] = goProcessAdmissionState{
		startTime:       fi.StartTime(),
		generationReady: generationReady,
		fileInfo:        fi,
		processRoot:     processRoot,
	}
	if p.samplerManager != nil {
		if autoSDKPotential {
			if p.goAutoSDKAdmissions == nil {
				p.goAutoSDKAdmissions = map[runtimeMetricTargetKey]goAutoSDKAdmissionState{}
			}
			p.goAutoSDKAdmissions[process] = goAutoSDKAdmissionState{
				startTime:            fi.StartTime(),
				executable:           executable,
				samplerReady:         true,
				generationReady:      true,
				optionFunctionsReady: true,
				typeInfoReady:        true,
				globalReady:          autoSDKGlobalReady,
				globalPatchReady:     globalPatchReady,
				fileInfo:             fi,
			}
		} else if admission, ok := p.goAutoSDKAdmissions[process]; ok &&
			admission.fileInfo == fi {
			delete(p.goAutoSDKAdmissions, process)
		}
	}
	p.pidsFilter.AllowPID(pid, ns, fi, ebpfcommon.PIDTypeGo)
	if p.samplerManager != nil && p.goAutoSDKRunStarted {
		if admission, ok := p.goAutoSDKAdmissions[process]; ok {
			if admission.globalPatchReady {
				p.ensureGoAutoSDKEventReader()
			}
			if !p.reconcileGoAutoSDKAdmission(process, admission) {
				p.markGoProcessAdmissionRetryLocked(process, fi)
				return false
			}
		}
	}
	p.registerRuntimeMetricTarget(pid, ns, fi)
	if !p.hasGoAutoSDKRestoreRetryLocked(process) {
		delete(p.goAutoSDKQuiescing, process)
	}
	p.clearGoProcessAdmissionRetryLocked(process, fi)
	return true
}

func goProcessAdmissionRetryKeyFor(
	process runtimeMetricTargetKey,
	fileInfo *exec.FileInfo,
) (goProcessAdmissionRetryKey, bool) {
	if fileInfo == nil || fileInfo.StartTime() == 0 {
		return goProcessAdmissionRetryKey{}, false
	}
	return goProcessAdmissionRetryKey{
		process:   process,
		startTime: fileInfo.StartTime(),
		fileInfo:  fileInfo,
	}, true
}

func (p *Tracer) markGoProcessAdmissionRetryLocked(
	process runtimeMetricTargetKey,
	fileInfo *exec.FileInfo,
) {
	retry, ok := goProcessAdmissionRetryKeyFor(process, fileInfo)
	if !ok {
		return
	}
	if p.goProcessAdmissionRetries == nil {
		p.goProcessAdmissionRetries = map[goProcessAdmissionRetryKey]struct{}{}
	}
	p.goProcessAdmissionRetries[retry] = struct{}{}
}

func (p *Tracer) clearGoProcessAdmissionRetryLocked(
	process runtimeMetricTargetKey,
	fileInfo *exec.FileInfo,
) {
	retry, ok := goProcessAdmissionRetryKeyFor(process, fileInfo)
	if ok {
		delete(p.goProcessAdmissionRetries, retry)
	}
}

func (p *Tracer) PIDAdmissionRetryPending(
	pid app.PID,
	ns uint32,
	fileInfo *exec.FileInfo,
) bool {
	if p == nil {
		return false
	}
	retry, ok := goProcessAdmissionRetryKeyFor(
		runtimeMetricTargetKey{pid: pid, ns: ns},
		fileInfo,
	)
	if !ok {
		return false
	}
	p.processMu.Lock()
	defer p.processMu.Unlock()
	_, pending := p.goProcessAdmissionRetries[retry]
	return pending
}

func (p *Tracer) CancelPIDAdmissionRetry(
	pid app.PID,
	ns uint32,
	fileInfo *exec.FileInfo,
) {
	if p == nil {
		return
	}
	retry, ok := goProcessAdmissionRetryKeyFor(
		runtimeMetricTargetKey{pid: pid, ns: ns},
		fileInfo,
	)
	if !ok {
		return
	}
	p.processMu.Lock()
	defer p.processMu.Unlock()
	// Cancellation revokes only attacher replay intent. Any queued restoration
	// remains responsible for making fallback and BPF cleanup safe.
	delete(p.goProcessAdmissionRetries, retry)
}

func (p *Tracer) restoreSamplerFallback(pid app.PID, ns uint32, startTime uint64) bool {
	return p.samplerManager.BlockPIDForProcess(pid, ns, startTime) &&
		p.samplerManager.FallbackSafeForProcessIncarnation(pid, ns, startTime)
}

func (p *Tracer) blockIndeterminateProcess(pid app.PID, ns uint32) {
	p.pidsFilter.BlockPID(pid, ns)
	p.deleteRuntimeMetricTarget(pid, ns)
}

func (p *Tracer) BlockPID(pid app.PID, ns uint32) {
	p.BlockPIDForProcess(pid, ns, nil)
}

func (p *Tracer) BlockPIDForProcess(
	pid app.PID,
	ns uint32,
	fileInfo *exec.FileInfo,
) {
	p.processMu.Lock()
	defer p.processMu.Unlock()

	process := runtimeMetricTargetKey{pid: pid, ns: ns}
	if fileInfo != nil && !p.goProcessFileInfoMatches(process, fileInfo) {
		return
	}
	startTime := p.goProcessStartTime(process)
	if fileInfo != nil {
		startTime = fileInfo.StartTime()
	}
	processFileInfo := p.goProcessFileInfo(process)
	if p.goAutoSDKQuiescing == nil {
		p.goAutoSDKQuiescing = map[runtimeMetricTargetKey]bool{}
	}
	p.goAutoSDKQuiescing[process] = true
	if !p.restoreGoAutoSDKFlagForIncarnation(process, startTime) {
		p.queueGoAutoSDKRestoreRetryLocked(process, startTime, true)
		p.pidsFilter.BlockPID(pid, ns)
		p.deleteRuntimeMetricTarget(pid, ns)
		return
	}
	p.disableRestoredGoAutoSDKAdmissionLocked(
		process,
		startTime,
		processFileInfo,
	)
	p.pidsFilter.BlockPID(pid, ns)
	p.deleteRuntimeMetricTarget(pid, ns)
	if !p.finishBlockedGoProcess(process, startTime) {
		p.queueGoAutoSDKRestoreRetryLocked(process, startTime, true)
		return
	}
	if !p.hasGoAutoSDKRestoreRetryLocked(process) {
		delete(p.goAutoSDKQuiescing, process)
	}
}

func (p *Tracer) goProcessFileInfoMatches(
	process runtimeMetricTargetKey,
	fileInfo *exec.FileInfo,
) bool {
	return fileInfo != nil && p.goProcessFileInfo(process) == fileInfo
}

func (p *Tracer) goProcessFileInfo(
	process runtimeMetricTargetKey,
) *exec.FileInfo {
	if admission, ok := p.goProcessAdmissions[process]; ok {
		return admission.fileInfo
	}
	if generation, ok := p.goProcessGenerationByPID[process]; ok {
		return generation.fileInfo
	}
	if state, ok := p.goAutoSDKFlagStates[process]; ok {
		return state.fileInfo
	}
	return nil
}

func (p *Tracer) ExecutableUnlinkReady(fileInfo *exec.FileInfo) bool {
	if p == nil || fileInfo == nil {
		return true
	}

	p.processMu.Lock()
	defer p.processMu.Unlock()
	for retry := range p.goProcessAdmissionRetries {
		if sameGoExecutable(retry.fileInfo, fileInfo) {
			return false
		}
	}
	for retry := range p.goAutoSDKRestoreRetries {
		if sameGoExecutable(retry.fileInfo, fileInfo) {
			return false
		}
	}
	for _, generation := range p.goProcessGenerationByPID {
		if sameGoExecutable(generation.fileInfo, fileInfo) {
			return false
		}
	}
	return true
}

func sameGoExecutable(left, right *exec.FileInfo) bool {
	leftKey, leftOK := goExecutableKeyFor(left)
	rightKey, rightOK := goExecutableKeyFor(right)
	return leftOK && rightOK && leftKey == rightKey
}

func (p *Tracer) finishBlockedGoProcess(
	process runtimeMetricTargetKey,
	startTime uint64,
) bool {
	autoSDKCleanupSafe := true
	if p.samplerManager != nil {
		autoSDKCleanupSafe = p.samplerManager.BlockPIDForProcess(
			process.pid,
			process.ns,
			startTime,
		) && p.samplerManager.FallbackSafeForProcessIncarnation(
			process.pid,
			process.ns,
			startTime,
		)
	}
	if !autoSDKCleanupSafe {
		return false
	}

	admission, admitted := p.goProcessAdmissions[process]
	admissionMatches := admitted && (startTime == 0 || admission.startTime == startTime)
	generation, generationTracked := p.goProcessGenerationByPID[process]
	generationMatches := generationTracked && generation.fileInfo != nil &&
		(startTime == 0 || generation.fileInfo.StartTime() == startTime)
	generationFileInfo := generation.fileInfo
	if admissionMatches && admission.generationReady && generationMatches &&
		admission.fileInfo != generation.fileInfo {
		return false
	}
	if startTime != 0 && !admissionMatches && !generationMatches {
		return true
	}
	if admissionMatches && admission.generationReady && !generationMatches {
		return false
	}

	p.deleteGoSpanOptionFunctions(process.pid, process.ns)
	p.deleteGoAutoSDKTypeInfo(process.pid, process.ns)
	if generationMatches || (admissionMatches && !admission.generationReady) {
		p.retireGoProcessGeneration(process.pid, process.ns)
	}

	generation, generationTracked = p.goProcessGenerationByPID[process]
	generationCleanupPending := generationTracked && generation.fileInfo != nil &&
		(startTime == 0 || generation.fileInfo.StartTime() == startTime ||
			(admissionMatches && !admission.generationReady))
	_, optionFunctionsTracked := p.goSpanOptionKeysByProcess[process]
	_, typeInfoTracked := p.goAutoSDKTypeInfoKeys[process]
	if generationCleanupPending || optionFunctionsTracked || typeInfoTracked {
		return false
	}
	cleanupFileInfo := generationFileInfo
	if admissionMatches {
		cleanupFileInfo = admission.fileInfo
	}
	if autoSDKAdmission, ok := p.goAutoSDKAdmissions[process]; ok &&
		autoSDKAdmission.fileInfo == cleanupFileInfo {
		delete(p.goAutoSDKAdmissions, process)
	}
	if admissionMatches {
		p.closeGoAutoSDKProcessRoot(admission.processRoot)
		delete(p.goProcessAdmissions, process)
	}
	return true
}

func (p *Tracer) supportsContextPropagation() bool {
	return !ebpfcommon.IntegrityModeOverride && ebpfcommon.SupportsContextPropagationWithProbe(p.log)
}

func (p *Tracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	if !p.supportsContextPropagation() {
		p.log.Info("Kernel in lockdown mode or missing CAP_SYS_ADMIN.")
	}

	if p.cfg.TrackRequestHeaders ||
		p.cfg.ContextPropagation.IsEnabled() {
		p.log.Info("Enabling trace information parsing", "bpf_loop_enabled", ebpfcommon.SupportsEBPFLoops(p.log, p.cfg.OverrideBPFLoopEnabled))
	}

	spec, err := LoadBpf()
	if err != nil {
		return nil, err
	}

	ebpfcommon.FixupSpec(spec, p.cfg.OverrideBPFLoopEnabled)

	return []*ebpfcommon.SpecBundle{{
		Spec:      spec,
		Objects:   &p.bpfObjects,
		Constants: p.constants(),
	}}, nil
}

func (p *Tracer) constants() map[string]any {
	blackBoxCP := uint32(0)
	if p.cfg.DisableBlackBoxCP {
		blackBoxCP = uint32(1)
	}

	m := map[string]any{
		"g_bpf_debug":               p.cfg.BpfDebug,
		"g_bpf_header_propagation":  p.supportsContextPropagation(),
		"wakeup_data_bytes":         uint32(p.cfg.WakeupLen) * uint32(unsafe.Sizeof(ebpfcommon.HTTPRequestTrace{})),
		"disable_black_box_cp":      blackBoxCP,
		"attr_type_invalid":         uint64(attribute.INVALID),
		"attr_type_bool":            uint64(attribute.BOOL),
		"attr_type_int64":           uint64(attribute.INT64),
		"attr_type_float64":         uint64(attribute.FLOAT64),
		"attr_type_string":          uint64(attribute.STRING),
		"attr_type_boolslice":       uint64(attribute.BOOLSLICE),
		"attr_type_int64slice":      uint64(attribute.INT64SLICE),
		"attr_type_float64slice":    uint64(attribute.FLOAT64SLICE),
		"attr_type_stringslice":     uint64(attribute.STRINGSLICE),
		"g_bpf_traceparent_enabled": true,
		"g_bpf_loop_enabled":        p.supportsBPFLoop,
	}

	if p.cfg.TrackRequestHeaders ||
		p.cfg.ContextPropagation.IsEnabled() {
		m["capture_header_buffer"] = int32(1)
	} else {
		m["capture_header_buffer"] = int32(0)
	}

	if p.cfg.HighRequestVolume {
		m["high_request_volume"] = uint32(1)
	} else {
		m["high_request_volume"] = uint32(0)
	}

	m["http_max_captured_bytes"] = p.cfg.BufferSizes.HTTP
	m["tcp_max_captured_bytes"] = p.cfg.BufferSizes.TCP
	m["mysql_max_captured_bytes"] = p.cfg.BufferSizes.MySQL
	m["kafka_max_captured_bytes"] = p.cfg.BufferSizes.Kafka
	m["postgres_max_captured_bytes"] = p.cfg.BufferSizes.Postgres
	m["max_transaction_time"] = uint64(p.cfg.MaxTransactionTime.Nanoseconds())

	return m
}

func (p *Tracer) SetupTailCalls() {
	p.goSpanOptionFunctions = p.bpfObjects.GoSpanOptionFunctions
	p.goAutoSDKTypeInfos = p.bpfObjects.GoAutoSdkTypeInfos
	p.goProcessGenerations = p.bpfObjects.GoProcessGenerations
	p.goAutoSDKFlags = p.bpfObjects.GoAutoSdkFlags
	p.goAutoSDKReadiness = p.bpfObjects.GoAutoSdkReady
	p.goAutoSDKOuterCalls = p.bpfObjects.GoAutoSdkOuterCalls
	p.goAutoSDKInflight = p.bpfObjects.GoAutoSdkInflight
	p.samplerManager = ebpfsampling.NewManager(
		p.log,
		p.bpfObjects.GlobalSamplerConfig,
		p.bpfObjects.SamplerOverrides,
		p.bpfObjects.SamplerReadyPids,
		p.bpfObjects.GoAutoSdkReady,
		p.samplerConfig,
	)
	p.samplerManager.InstallGlobal()

	p.goAutoSDKPreAdmissionReady = p.provisionGoAutoSDKInflight(
		goAutoSDKPendingState(),
	)
	tailCallsReady := installGoTailCalls(p.tailCallPrograms(), func(i uint32, prog *ebpf.Program) error {
		p.log.Debug("loading program into tail call jump table", "index", i, "program", prog.String())
		var err error
		if p.bpfObjects.JumpTable == nil {
			err = errors.New("tail call jump table is unavailable")
		} else {
			err = p.bpfObjects.JumpTable.Update(i, uint32(prog.FD()), ebpf.UpdateAny)
		}
		if err != nil {
			p.log.Error("error loading info tail call jump table", "error", err)
		}
		return err
	})
	p.goAutoSDKTailCallsReady = tailCallsReady
}

func (p *Tracer) tailCallPrograms() []*ebpf.Program {
	// Order must match the k_tail_* enum in bpf/generictracer/k_tracer_tailcall.h.
	return []*ebpf.Program{
		// HTTP/1
		p.bpfObjects.ObiProtocolHttp,           // 0  k_tail_protocol_http
		p.bpfObjects.ObiContinueProtocolHttp,   // 1  k_tail_continue_protocol_http
		p.bpfObjects.ObiContinue2ProtocolHttp,  // 2  k_tail_continue2_protocol_http
		p.bpfObjects.ObiContinueProtocolHttpTp, // 3  k_tail_continue_protocol_http_tp
		// TCP
		p.bpfObjects.ObiProtocolTcp, // 4  k_tail_protocol_tcp
		// Generic
		p.bpfObjects.ObiHandleBufWithArgs, // 5  k_tail_handle_buf_with_args
		p.bpfObjects.ObiContinueNetfdRead, // 6  k_tail_continue_netfd_read
		// HTTP/2 + gRPC
		p.bpfObjects.ObiProtocolHttp2,                           // 7
		p.bpfObjects.ObiProtocolHttp2GrpcFrames,                 // 8
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrame,       // 9
		p.bpfObjects.ObiProtocolHttp2GrpcHandleEndFrame,         // 10
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrameServer, // 11
		nil, // 12 (reserved)
		// Large buffer multi-batch emission
		p.bpfObjects.ObiLargeBufEmitContinue,                          // 13  k_tail_large_buf_emit_continue
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrameServerCommit, // 14
		// Go SDK span start attributes
		p.bpfObjects.ObiUprobeGoSpanStartAttributes,      // 15  k_tail_go_span_start_attributes
		p.bpfObjects.ObiUprobeGoSpanStartApplyAttributes, // 16  k_tail_go_span_start_apply_attributes
		p.bpfObjects.ObiUprobeGoSpanStartRoute,           // 17  k_tail_go_span_start_route
		p.bpfObjects.ObiUprobeGoSpanSetAttributes,        // 18  k_tail_go_span_set_attributes
		// HTTP/2 server traceparent validation
		p.bpfObjects.ObiProtocolHttp2GrpcValidateServerTraceparent, // 19
		// Ongoing HTTP/1 request continuation
		p.bpfObjects.ObiHandleHttpContinuation, // 20
		// HTTP/2 client terminal resolution
		p.bpfObjects.ObiProtocolHttp2GrpcFinishClient, // 21
		// HTTP/2 server HPACK parser continuation
		p.bpfObjects.ObiProtocolHttp2GrpcParseServerHeaders, // 22
	}
}

func installGoTailCalls(
	programs []*ebpf.Program,
	update func(uint32, *ebpf.Program) error,
) bool {
	autoSDKReady := len(programs) > goAutoSDKLastRequiredTailCall
	for i, prog := range programs {
		if prog == nil {
			if i >= goAutoSDKFirstRequiredTailCall && i <= goAutoSDKLastRequiredTailCall {
				autoSDKReady = false
			}
			continue
		}
		if err := update(uint32(i), prog); err != nil &&
			i >= goAutoSDKFirstRequiredTailCall &&
			i <= goAutoSDKLastRequiredTailCall {
			autoSDKReady = false
		}
	}
	return autoSDKReady
}

func (p *Tracer) goAutoSDKActivationReady(
	executable goExecutableKey,
	optionFunctionsReady bool,
	typeInfoReady bool,
	samplerReady bool,
	generationReady bool,
	globalProtocolReady bool,
) bool {
	return p.goAutoSDKTailCallsReady &&
		optionFunctionsReady &&
		typeInfoReady &&
		(p.goAutoSDKReadyByExecutable[executable] || globalProtocolReady) &&
		samplerReady &&
		generationReady
}

var bufReaderOffsetFields = [...]goexec.GoOffset{
	goexec.BufReaderBufPos,
	goexec.BufReaderRPos,
	goexec.BufReaderWPos,
}

func registerBufReaderOffsets(offTable *BpfOffTableT, offsets *goexec.Offsets) {
	for _, field := range bufReaderOffsetFields {
		if val, ok := offsets.Field[field].(uint64); ok {
			offTable.Table[field] = val
		}
	}
}

func registerGoHTTP2ServerOffset(
	offTable *BpfOffTableT,
	offsets *goexec.Offsets,
	field goexec.GoOffset,
) bool {
	if offTable == nil || offsets == nil {
		return false
	}
	val, ok := offsets.Field[field].(uint64)
	if !ok || val == 0 {
		return false
	}
	offTable.Table[field] = val
	return true
}

func registerGoHTTP2ServerOffsets(
	offTable *BpfOffTableT,
	offsets *goexec.Offsets,
) goHTTP2ServerOffsetAvailability {
	reqTLS := registerGoHTTP2ServerOffset(offTable, offsets, goexec.ReqTLSPos)
	xNet := registerGoHTTP2ServerOffset(
		offTable, offsets, goexec.ScMaxClientStreamIDPos,
	)
	vendored := registerGoHTTP2ServerOffset(
		offTable, offsets, goexec.ScMaxClientStreamIDVendoredPos,
	)
	return goHTTP2ServerOffsetAvailability{
		xNet:     reqTLS && xNet,
		vendored: reqTLS && vendored,
	}
}

func (p *Tracer) RegisterOffsets(fileInfo *exec.FileInfo, offsets *goexec.Offsets) {
	p.processMu.Lock()
	defer p.processMu.Unlock()

	p.recordGoChannelOffsetAvailability(fileInfo, offsets)
	p.recordGoAutoSDKEligibility(fileInfo, false, false)

	offTable := BpfOffTableT{}
	initMissingGoChannelOffsets(&offTable)
	initMissingGRPCWriterOffsets(&offTable)
	// Set the field offsets and the logLevel for the Go BPF program in a map
	for _, field := range []goexec.GoOffset{
		goexec.ConnFdPos,
		goexec.FdLaddrPos,
		goexec.FdRaddrPos,
		goexec.TCPAddrPortPtrPos,
		goexec.TCPAddrIPPtrPos,
		// http
		goexec.URLPtrPos,
		goexec.PathPtrPos,
		goexec.HostPtrPos,
		goexec.SchemePtrPos,
		goexec.MethodPtrPos,
		goexec.StatusCodePtrPos,
		goexec.ResponseLengthPtrPos,
		goexec.ContentLengthPtrPos,
		goexec.ReqHeaderPtrPos,
		goexec.IoWriterBufPtrPos,
		goexec.IoWriterNPos,
		goexec.IoWriterWrPos,
		goexec.CcNextStreamIDPos,
		goexec.CcNextStreamIDVendoredPos,
		goexec.CcFramerPos,
		goexec.CcFramerVendoredPos,
		goexec.FramerWPos,
		goexec.PcConnPos,
		goexec.PcTLSPos,
		goexec.NetConnPos,
		goexec.CcTconnPos,
		goexec.CcTconnVendoredPos,
		goexec.ScConnPos,
		goexec.CRwcPos,
		goexec.CTlsPos,
		goexec.TextReaderRPos,
		// grpc
		goexec.GrpcStreamStPtrPos,
		goexec.GrpcStreamMethodPtrPos,
		goexec.GrpcStatusSPos,
		goexec.GrpcStatusCodePtrPos,
		goexec.MetaHeadersFrameFieldsPtrPos,
		goexec.ValueContextValPtrPos,
		goexec.GrpcStConnPos,
		goexec.GrpcTConnPos,
		goexec.GrpcTSchemePos,
		goexec.GrpcTransportStreamIDPos,
		goexec.GrpcTransportBufWriterBufPos,
		goexec.GrpcTransportBufWriterOffsetPos,
		goexec.GrpcTransportBufWriterConnPos,
		// redis
		goexec.RedisConnBwPos,
		// kafka go
		goexec.KafkaGoWriterTopicPos,
		goexec.KafkaGoProtocolConnPos,
		goexec.KafkaGoReaderTopicPos,
		// kafka sarama
		goexec.SaramaBrokerCorrIDPos,
		goexec.SaramaResponseCorrIDPos,
		goexec.SaramaBrokerConnPos,
		goexec.SaramaBufconnConnPos,
		// grpc versioning
		goexec.GrpcOneSixZero,
		goexec.GrpcOneSixNine,
		goexec.GrpcOneSevenSeven,
		// HTTP2 versioning
		goexec.HTTP2ZeroFortyFive,
		// grpc
		goexec.GrpcServerStreamStream,
		goexec.GrpcServerStreamStPtr,
		goexec.GrpcClientStreamStream,
		// go manual spans
		goexec.GoTracerDelegatePos,
		goexec.SpanContextTraceIDPos,
		goexec.SpanContextSpanIDPos,
		goexec.SpanContextTraceFlagsPos,
		// go runtime channels
		goexec.HchanQcountPos,
		goexec.HchanDataqsizPos,
		goexec.HchanSendxPos,
		goexec.HchanRecvxPos,
		// go jsonrpc
		goexec.GoJsonrpcRequestHeaderServiceMethodPos,
		// go mongodb
		goexec.MongoConnNamePos,
		goexec.MongoOpNamePos,
		goexec.MongoOpDBPos,
		goexec.MongoOneThirteenOne,
		// database/sql stdlib
		goexec.DriverConnCiPos,
		// lib/pq driver
		goexec.PqConnCfgPos,
		goexec.PqConfigHostPos,
		goexec.PqOneElevenZero,
		// mysql driver
		goexec.MySQLConnCfgPos,
		goexec.MySQLConfigAddrPos,
		// pgx driver
		goexec.PgxConnConfigPos,
		goexec.PgxConfigHostPos,
		goexec.MuxTemplatePos,
		goexec.GinFullpathPos,
	} {
		if val, ok := offsets.Field[field].(uint64); ok {
			offTable.Table[field] = val
		}
	}
	registerBufReaderOffsets(&offTable, offsets)
	p.recordGoHTTP2ServerOffsetAvailability(
		fileInfo,
		registerGoHTTP2ServerOffsets(&offTable, offsets),
	)
	for _, field := range goRuntimeMetricOffsetFields {
		if val, ok := offsets.Field[field].(uint64); ok {
			offTable.Table[field] = val
		}
	}

	for _, iType := range []struct {
		symbol string
		field  goexec.GoOffset
	}{
		{
			symbol: "*errors.errorString",
			field:  goexec.GoErrorStringOffset,
		},
		{
			symbol: "*github.com/go-sql-driver/mysql.mysqlConn",
			field:  goexec.MySQLConnTypeOffset,
		},
		{
			symbol: "*github.com/lib/pq.conn",
			field:  goexec.PqConnTypeOffset,
		},
	} {
		if offset, ok := offsets.ITypes[iType.symbol]; ok {
			offTable.Table[iType.field] = offset
		}
	}

	executable, _ := goExecutableKeyFor(fileInfo)
	if err := p.bpfObjects.GoOffsetsMap.Put(executable, offTable); err != nil {
		p.log.Error("setting Go offsets map failed", "pid", fileInfo.Pid(),
			"dev_major", executable.DevMajor, "dev_minor", executable.DevMinor, "ino", executable.Ino, "error", err)
		delete(p.goChannelOffsetsByExecutable, executable)
		delete(p.goHTTP2ServerOffsetsByExecutable, executable)
		delete(p.goAutoSDKEligibleByExecutable, executable)
		delete(p.goAutoSDKReadyByExecutable, executable)
		delete(p.goAutoSDKGlobalEligibleByExecutable, executable)
		delete(p.goAutoSDKGlobalReadyByExecutable, executable)
		delete(p.goAutoSDKTypesByExecutable, executable)
		delete(p.goAutoSDKProbesByExecutable, executable)
		delete(p.goAutoSDKGlobalProbesByExecutable, executable)
		delete(p.goSpanOptionFuncsByExecutable, executable)
		delete(p.goRuntimeMetricMaskByExecutable, executable)
		delete(p.goRuntimeGCGoalSourceByExecutable, executable)
		p.deleteRuntimeMetricTarget(fileInfo.Pid(), fileInfo.Ns())
		return
	}
	if p.goAutoSDKTypesByExecutable == nil {
		p.goAutoSDKTypesByExecutable = map[goExecutableKey]goexec.GoAutoSDKTypeInfo{}
	}
	p.goAutoSDKTypesByExecutable[executable] = offsets.AutoSDKTypes
	autoSDKProbes, autoSDKFunctionsAvailable := goAutoSDKAttachmentSymbols(offsets)
	if p.goAutoSDKProbesByExecutable == nil {
		p.goAutoSDKProbesByExecutable = map[goExecutableKey][]string{}
	}
	p.goAutoSDKProbesByExecutable[executable] = autoSDKProbes
	autoSDKGlobalProbes, autoSDKGlobalFunctionsAvailable := goAutoSDKGlobalAttachmentSymbols(offsets)
	if p.goAutoSDKGlobalProbesByExecutable == nil {
		p.goAutoSDKGlobalProbesByExecutable = map[goExecutableKey][]string{}
	}
	p.goAutoSDKGlobalProbesByExecutable[executable] = autoSDKGlobalProbes
	spanOptionFunctions := make(
		[]goSpanOptionFunction,
		0,
		len(offsets.SpanKindFunctions)+len(offsets.NewRootFunctions),
	)
	for _, function := range offsets.SpanKindFunctions {
		if function.Entry != 0 {
			spanOptionFunctions = append(spanOptionFunctions, goSpanOptionFunction{
				entry:      function.Entry,
				optionType: goSpanOptionKind,
			})
		}
	}
	for _, function := range offsets.NewRootFunctions {
		if function.Entry != 0 {
			spanOptionFunctions = append(spanOptionFunctions, goSpanOptionFunction{
				entry:      function.Entry,
				optionType: goSpanOptionNewRoot,
			})
		}
	}
	p.goSpanOptionFuncsByExecutable[executable] = spanOptionFunctions

	p.recordGoAutoSDKEligibility(
		fileInfo,
		autoSDKFunctionsAvailable,
		autoSDKGlobalFunctionsAvailable,
	)
	p.recordGoRuntimeMetricAvailability(fileInfo, offsets)
	if hasBaseGoRuntimeMetrics(p.goRuntimeMetricMaskByExecutable[executable]) {
		p.registerRuntimeMetricTarget(fileInfo.Pid(), fileInfo.Ns(), fileInfo)
	} else {
		p.deleteRuntimeMetricTarget(fileInfo.Pid(), fileInfo.Ns())
	}
}

func (p *Tracer) RollbackProcessRegistration(fileInfo *exec.FileInfo) {
	if p == nil || fileInfo == nil {
		return
	}

	p.processMu.Lock()
	defer p.processMu.Unlock()
	p.deleteRuntimeMetricTarget(fileInfo.Pid(), fileInfo.Ns())
}

func (p *Tracer) recordGoAutoSDKEligibility(
	fileInfo *exec.FileInfo,
	directFunctionsAvailable bool,
	globalFunctionsAvailable bool,
) {
	if p == nil || fileInfo == nil {
		return
	}
	if p.goAutoSDKEligibleByExecutable == nil {
		p.goAutoSDKEligibleByExecutable = map[goExecutableKey]bool{}
	}
	if p.goAutoSDKReadyByExecutable == nil {
		p.goAutoSDKReadyByExecutable = map[goExecutableKey]bool{}
	}
	if p.goAutoSDKGlobalEligibleByExecutable == nil {
		p.goAutoSDKGlobalEligibleByExecutable = map[goExecutableKey]bool{}
	}
	if p.goAutoSDKGlobalReadyByExecutable == nil {
		p.goAutoSDKGlobalReadyByExecutable = map[goExecutableKey]bool{}
	}

	contextPropagation := p.supportsContextPropagation()
	directEligible := directFunctionsAvailable && contextPropagation
	globalEligible := globalFunctionsAvailable && contextPropagation
	executable, _ := goExecutableKeyFor(fileInfo)
	p.goAutoSDKEligibleByExecutable[executable] = directEligible
	p.goAutoSDKReadyByExecutable[executable] = false
	p.goAutoSDKGlobalEligibleByExecutable[executable] = globalEligible
	p.goAutoSDKGlobalReadyByExecutable[executable] = false
	if !directEligible && !globalEligible && p.log != nil {
		p.log.Debug("Go Auto SDK activation is unavailable for executable",
			"pid", fileInfo.Pid(), "dev_major", executable.DevMajor, "dev_minor", executable.DevMinor, "ino", executable.Ino,
			"cmd", fileInfo.CmdExePath())
	}
}

func (p *Tracer) RecordGoProbeAttachments(fileInfo *exec.FileInfo, attached map[string]bool) {
	if p == nil || fileInfo == nil {
		return
	}
	p.processMu.Lock()
	defer p.processMu.Unlock()
	if p.goAutoSDKReadyByExecutable == nil {
		p.goAutoSDKReadyByExecutable = map[goExecutableKey]bool{}
	}
	if p.goAutoSDKGlobalReadyByExecutable == nil {
		p.goAutoSDKGlobalReadyByExecutable = map[goExecutableKey]bool{}
	}
	executable, _ := goExecutableKeyFor(fileInfo)
	if p.goAutoSDKDirectEntryBarrierClosed || p.goAutoSDKShuttingDown {
		p.goAutoSDKReadyByExecutable[executable] = false
		p.goAutoSDKGlobalReadyByExecutable[executable] = false
		return
	}
	directReady := p.goAutoSDKEligibleByExecutable[executable]
	requiredProbes, ok := p.goAutoSDKProbesByExecutable[executable]
	directReady = directReady && ok
	for _, symbol := range requiredProbes {
		directReady = directReady && attached[symbol]
	}
	globalReady := p.goAutoSDKGlobalEligibleByExecutable[executable] &&
		!p.goAutoSDKGlobalEntryBarrierClosed
	globalProbes, ok := p.goAutoSDKGlobalProbesByExecutable[executable]
	globalReady = globalReady && ok
	for _, symbol := range globalProbes {
		globalReady = globalReady && attached[symbol]
	}
	p.goAutoSDKReadyByExecutable[executable] = directReady
	p.goAutoSDKGlobalReadyByExecutable[executable] = globalReady
	if !directReady && p.goAutoSDKEligibleByExecutable[executable] && p.log != nil {
		p.log.Debug("direct Go Auto SDK activation disabled after incomplete probe attachment",
			"pid", fileInfo.Pid(), "dev_major", executable.DevMajor, "dev_minor", executable.DevMinor, "ino", executable.Ino,
			"cmd", fileInfo.CmdExePath())
	}
	if !globalReady && p.goAutoSDKGlobalEligibleByExecutable[executable] && p.log != nil {
		p.log.Debug("global Go Auto SDK activation disabled after incomplete probe attachment",
			"pid", fileInfo.Pid(), "dev_major", executable.DevMajor, "dev_minor", executable.DevMinor, "ino", executable.Ino,
			"cmd", fileInfo.CmdExePath())
	}
}

func (p *Tracer) BeginGoAutoSDKAdmissionEntryAttachment(
	fileInfo *exec.FileInfo,
	symbol string,
) bool {
	if p == nil || fileInfo == nil || !goAutoSDKAdmissionEntrySymbol(symbol) {
		return false
	}
	p.processMu.Lock()
	defer p.processMu.Unlock()
	if p.goAutoSDKShuttingDown || p.goAutoSDKShutdownComplete {
		return false
	}
	switch {
	case goAutoSDKDirectEntrySymbol(symbol):
		if p.goAutoSDKDirectEntryBarrierClosed {
			return false
		}
		p.goAutoSDKDirectEntryAttaching++
	case goAutoSDKGlobalEntrySymbol(symbol):
		if !p.goAutoSDKPreAdmissionReady ||
			p.goAutoSDKGlobalEntryBarrierClosed {
			return false
		}
		p.goAutoSDKGlobalEntryAttaching++
	default:
		return false
	}
	return true
}

func (p *Tracer) FinishGoAutoSDKAdmissionEntryAttachment(
	fileInfo *exec.FileInfo,
	symbol string,
	directEntry io.Closer,
	attachmentErr error,
) {
	if p == nil || fileInfo == nil || !goAutoSDKAdmissionEntrySymbol(symbol) {
		return
	}

	direct := goAutoSDKDirectEntrySymbol(symbol)
	p.processMu.Lock()
	if direct && p.goAutoSDKDirectEntryAttaching > 0 {
		p.goAutoSDKDirectEntryAttaching--
	} else if !direct && p.goAutoSDKGlobalEntryAttaching > 0 {
		p.goAutoSDKGlobalEntryAttaching--
	}
	if directEntry == nil {
		p.processMu.Unlock()
		return
	}
	retain := attachmentErr == nil
	if direct {
		retain = retain &&
			!p.goAutoSDKDirectEntryBarrierClosed &&
			!p.goAutoSDKShuttingDown
	} else {
		// A global entry attachment that began before shutdown remains part of
		// the second barrier. It must stay attached while process flags are
		// restored, even though new attachments are already denied.
		retain = retain && !p.goAutoSDKGlobalEntryBarrierClosed
	}
	if retain {
		if direct {
			p.goAutoSDKDirectEntryClosers = append(
				p.goAutoSDKDirectEntryClosers,
				directEntry,
			)
		} else {
			p.goAutoSDKGlobalEntryClosers = append(
				p.goAutoSDKGlobalEntryClosers,
				directEntry,
			)
		}
		p.processMu.Unlock()
		return
	}
	if direct {
		p.goAutoSDKDirectEntryClosing++
	} else {
		p.goAutoSDKGlobalEntryClosing++
	}
	p.goAutoSDKShutdownComplete = false
	p.processMu.Unlock()

	closeErr := directEntry.Close()
	if closeErr != nil && p.log != nil {
		message := "closing late Go Auto SDK admission entry probe failed"
		if attachmentErr != nil {
			message = "rolling back partial Go Auto SDK admission entry probe failed"
		}
		p.log.Error(message, "error", closeErr)
	}

	p.processMu.Lock()
	if direct {
		p.goAutoSDKDirectEntryClosing--
	} else {
		p.goAutoSDKGlobalEntryClosing--
	}
	if closeErr != nil {
		if direct {
			p.goAutoSDKDirectEntryClosers = append(
				p.goAutoSDKDirectEntryClosers,
				directEntry,
			)
		} else {
			p.goAutoSDKGlobalEntryClosers = append(
				p.goAutoSDKGlobalEntryClosers,
				directEntry,
			)
		}
	}
	p.processMu.Unlock()
}

func goAutoSDKAdmissionEntrySymbol(symbol string) bool {
	return goAutoSDKDirectEntrySymbol(symbol) ||
		goAutoSDKGlobalEntrySymbol(symbol)
}

func goAutoSDKDirectEntrySymbol(symbol string) bool {
	for _, candidate := range goAutoSDKStartProbeSymbols {
		if symbol == candidate {
			return true
		}
	}
	return false
}

func goAutoSDKGlobalEntrySymbol(symbol string) bool {
	return symbol == goAutoSDKGlobalEntryProbeSymbol
}

func randomGoProcessGeneration() (uint64, error) {
	var value [8]byte
	if _, err := rand.Read(value[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(value[:]), nil
}

func (p *Tracer) registerGoProcessGeneration(
	pid app.PID,
	ns uint32,
	fileInfo *exec.FileInfo,
) bool {
	if p == nil || fileInfo == nil || p.goProcessGenerations == nil {
		return false
	}

	process := runtimeMetricTargetKey{pid: pid, ns: ns}
	if fileInfo.StartTime() == 0 {
		if state, tracked := p.goProcessGenerationByPID[process]; tracked {
			p.invalidateGoProcessGeneration(process, state)
		}
		return false
	}
	resolve := p.resolveGoProcessHostPID
	if resolve == nil {
		resolve = resolveGoProcessHostPID
	}
	hostPID, err := resolve(pid, ns)
	if err != nil {
		if state, tracked := p.goProcessGenerationByPID[process]; tracked {
			p.invalidateGoProcessGeneration(process, state)
		}
		if p.log != nil {
			p.log.Debug("resolving Go process generation PID failed",
				"pid", pid, "namespace", ns, "error", err)
		}
		return false
	}

	return p.registerGoProcessGenerationForHostPID(
		process,
		hostPID,
		fileInfo,
	)
}

func (p *Tracer) registerGoProcessGenerationForHostPID(
	process runtimeMetricTargetKey,
	hostPID uint32,
	fileInfo *exec.FileInfo,
) bool {
	if p == nil || p.goProcessGenerations == nil || fileInfo == nil ||
		fileInfo.StartTime() == 0 {
		return false
	}
	if p.goProcessGenerationByPID == nil {
		p.goProcessGenerationByPID = map[runtimeMetricTargetKey]goProcessGenerationState{}
	}
	if p.goProcessOwnerByHostPID == nil {
		p.goProcessOwnerByHostPID = map[uint32]runtimeMetricTargetKey{}
	}

	previousGeneration := uint64(0)
	if state, tracked := p.goProcessGenerationByPID[process]; tracked {
		if !state.retired && state.hostPID == hostPID && state.fileInfo == fileInfo {
			value := goProcessGenerationValue{
				Generation: state.generation,
				StartTime:  state.fileInfo.StartTime(),
			}
			if err := p.goProcessGenerations.Put(hostPID, value); err != nil {
				p.logProcessGenerationError(
					"refreshing Go process generation failed", process, hostPID, err,
				)
				return false
			}
			p.goProcessOwnerByHostPID[hostPID] = process
			return true
		}

		previousGeneration = state.generation
		if !p.invalidateGoProcessGeneration(process, state) {
			return false
		}
	}
	if owner, owned := p.goProcessOwnerByHostPID[hostPID]; owned && owner != process {
		if state, tracked := p.goProcessGenerationByPID[owner]; tracked {
			previousGeneration = state.generation
			if !p.invalidateGoProcessGeneration(owner, state) {
				return false
			}
		} else {
			delete(p.goProcessOwnerByHostPID, hostPID)
		}
	}

	generation, err := p.nextGoProcessGeneration(previousGeneration)
	if err != nil {
		p.logProcessGenerationError(
			"creating Go process generation failed", process, hostPID, err,
		)
		p.invalidateGoProcessGeneration(process, goProcessGenerationState{
			hostPID:    hostPID,
			generation: previousGeneration,
			fileInfo:   fileInfo,
			retired:    true,
		})
		return false
	}
	value := goProcessGenerationValue{
		Generation: generation,
		StartTime:  fileInfo.StartTime(),
	}
	if err := p.goProcessGenerations.Put(hostPID, value); err != nil {
		p.logProcessGenerationError(
			"registering Go process generation failed", process, hostPID, err,
		)
		p.invalidateGoProcessGeneration(process, goProcessGenerationState{
			hostPID:    hostPID,
			generation: generation,
			fileInfo:   fileInfo,
			retired:    true,
		})
		return false
	}

	p.goProcessGenerationByPID[process] = goProcessGenerationState{
		hostPID:    hostPID,
		generation: generation,
		fileInfo:   fileInfo,
	}
	p.goProcessOwnerByHostPID[hostPID] = process
	return true
}

func (p *Tracer) nextGoProcessGeneration(previous uint64) (uint64, error) {
	source := p.newGoProcessGeneration
	if source == nil {
		source = randomGoProcessGeneration
	}

	const attempts = 4
	for range attempts {
		generation, err := source()
		if err != nil {
			return 0, err
		}
		if generation != 0 && generation != previous {
			return generation, nil
		}
	}
	return 0, errors.New("go process generation source returned unusable values")
}

func (p *Tracer) retireGoProcessGeneration(pid app.PID, ns uint32) {
	if p == nil {
		return
	}
	process := runtimeMetricTargetKey{pid: pid, ns: ns}
	state, tracked := p.goProcessGenerationByPID[process]
	if !tracked {
		return
	}
	state.retired = true
	p.goProcessGenerationByPID[process] = state
	p.invalidateGoProcessGeneration(process, state)
}

func (p *Tracer) invalidateGoProcessGeneration(
	process runtimeMetricTargetKey,
	state goProcessGenerationState,
) bool {
	if p.goProcessOwnerByHostPID == nil {
		p.goProcessOwnerByHostPID = map[uint32]runtimeMetricTargetKey{}
	}
	state.retired = true
	p.goProcessGenerationByPID[process] = state
	if owner, owned := p.goProcessOwnerByHostPID[state.hostPID]; owned && owner != process {
		delete(p.goProcessGenerationByPID, process)
		return true
	}
	p.goProcessOwnerByHostPID[state.hostPID] = process
	if p.goProcessGenerations == nil {
		return false
	}

	err := p.goProcessGenerations.Delete(state.hostPID)
	if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
		delete(p.goProcessGenerationByPID, process)
		delete(p.goProcessOwnerByHostPID, state.hostPID)
		return true
	}

	p.logProcessGenerationError(
		"deleting Go process generation failed", process, state.hostPID, err,
	)
	disabled := goProcessGenerationValue{}
	if err := p.goProcessGenerations.Put(state.hostPID, disabled); err != nil {
		p.logProcessGenerationError(
			"disabling Go process generation failed", process, state.hostPID, err,
		)
		return false
	}

	delete(p.goProcessGenerationByPID, process)
	delete(p.goProcessOwnerByHostPID, state.hostPID)
	return true
}

func (p *Tracer) logProcessGenerationError(
	message string,
	process runtimeMetricTargetKey,
	hostPID uint32,
	err error,
) {
	if p.log != nil {
		p.log.Debug(message,
			"pid", process.pid, "namespace", process.ns, "host_pid", hostPID, "error", err)
	}
}

func (p *Tracer) goProcessKey(
	process runtimeMetricTargetKey,
	hostPID uint32,
) (goProcessKey, bool) {
	state, ok := p.goProcessGenerationByPID[process]
	owner, owned := p.goProcessOwnerByHostPID[hostPID]
	if !ok || !owned || owner != process ||
		state.retired || state.hostPID != hostPID || state.generation == 0 {
		return goProcessKey{}, false
	}
	return goProcessKey{
		PID:        uint64(hostPID),
		Generation: state.generation,
	}, true
}

func (p *Tracer) registerGoSpanOptionFunctions(
	pid app.PID,
	ns uint32,
	fileInfo *exec.FileInfo,
) bool {
	if p == nil || fileInfo == nil {
		return false
	}

	process := runtimeMetricTargetKey{pid: pid, ns: ns}
	executable, _ := goExecutableKeyFor(fileInfo)
	functions := p.goSpanOptionFuncsByExecutable[executable]
	if len(functions) == 0 {
		return p.clearGoSpanOptionFunctions(process)
	}
	if p.goSpanOptionFunctions == nil {
		return false
	}

	loadBias, err := procs.FindExeLoadBias(pid)
	if err != nil {
		p.log.Debug("resolving Go span-option function load bias failed",
			"pid", pid, "namespace", ns, "error", err)
		return false
	}
	pidInfo, err := runtimeMetricPIDInfo(pid, ns)
	if err != nil {
		p.log.Debug("resolving Go span-option function PID failed",
			"pid", pid, "namespace", ns, "error", err)
		return false
	}
	processKey, ok := p.goProcessKey(process, pidInfo.HostPid)
	if !ok {
		return false
	}

	keys := make([]goSpanOptionFunctionKey, 0, len(functions))
	for _, function := range functions {
		if function.entry > ^uint64(0)-loadBias {
			p.log.Debug("Go span-option function address overflowed",
				"pid", pid, "namespace", ns, "function", function.entry, "load_bias", loadBias)
			return false
		}
		key := goSpanOptionFunctionKey{
			HostPID:    processKey.PID,
			Generation: processKey.Generation,
			Function:   function.entry + loadBias,
		}
		keys = append(keys, key)
	}

	previousKeys := p.goSpanOptionKeysByProcess[process]
	for i, key := range keys {
		if err := p.goSpanOptionFunctions.Put(key, functions[i].optionType); err != nil {
			p.log.Debug("registering Go span-option function failed",
				"pid", pid, "namespace", ns, "function", key.Function, "error", err)
			tracked := make(
				[]goSpanOptionFunctionKey, 0, len(previousKeys)+i+1,
			)
			seen := make(map[goSpanOptionFunctionKey]struct{}, len(previousKeys)+i+1)
			for _, trackedKey := range append(previousKeys, keys[:i+1]...) {
				if _, ok := seen[trackedKey]; ok {
					continue
				}
				seen[trackedKey] = struct{}{}
				tracked = append(tracked, trackedKey)
			}
			p.goSpanOptionKeysByProcess[process] = tracked
			p.clearGoSpanOptionFunctions(process)
			return false
		}
	}

	desired := make(map[goSpanOptionFunctionKey]struct{}, len(keys))
	for _, key := range keys {
		desired[key] = struct{}{}
	}
	stale := make([]goSpanOptionFunctionKey, 0, len(previousKeys))
	for _, key := range previousKeys {
		if _, keep := desired[key]; keep {
			continue
		}
		err := p.goSpanOptionFunctions.Delete(key)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			stale = append(stale, key)
			p.log.Debug("deleting stale Go span-option function failed",
				"pid", pid, "namespace", ns,
				"function", key.Function, "error", err)
		}
	}
	if len(stale) != 0 {
		p.goSpanOptionKeysByProcess[process] = append(keys, stale...)
		return false
	}
	p.goSpanOptionKeysByProcess[process] = keys
	return true
}

func (p *Tracer) registerGoAutoSDKTypeInfo(
	pid app.PID,
	ns uint32,
	fileInfo *exec.FileInfo,
) bool {
	if p == nil || fileInfo == nil || p.goAutoSDKTypeInfos == nil {
		return false
	}

	executable, _ := goExecutableKeyFor(fileInfo)
	typeInfo, ok := p.goAutoSDKTypesByExecutable[executable]
	if !ok || !typeInfo.Valid() {
		return false
	}

	process := runtimeMetricTargetKey{pid: pid, ns: ns}
	pidInfo, err := runtimeMetricPIDInfo(pid, ns)
	if err != nil {
		if p.log != nil {
			p.log.Debug("resolving Go Auto SDK PID failed",
				"pid", pid, "namespace", ns, "error", err)
		}
		return false
	}
	hostPID := pidInfo.HostPid
	processKey, ok := p.goProcessKey(process, hostPID)
	if !ok {
		return false
	}

	loadBias, err := procs.FindExeLoadBias(pid)
	if err != nil {
		if p.log != nil {
			p.log.Debug("resolving Go Auto SDK type load bias failed",
				"pid", pid, "namespace", ns, "error", err)
		}
		return false
	}
	relocated, err := relocateGoAutoSDKTypeInfo(typeInfo, loadBias)
	if err != nil {
		if p.log != nil {
			p.log.Debug("relocating Go Auto SDK types failed",
				"pid", pid, "namespace", ns, "error", err)
		}
		return false
	}
	if p.goAutoSDKTypeInfoKeys == nil {
		p.goAutoSDKTypeInfoKeys = map[runtimeMetricTargetKey]goProcessKey{}
	}
	if previousKey, tracked := p.goAutoSDKTypeInfoKeys[process]; tracked &&
		previousKey != processKey {
		if err := p.goAutoSDKTypeInfos.Delete(previousKey); err != nil &&
			!errors.Is(err, ebpf.ErrKeyNotExist) {
			if p.log != nil {
				p.log.Debug("deleting stale Go Auto SDK types failed",
					"pid", pid, "namespace", ns,
					"host_pid", previousKey.PID,
					"generation", previousKey.Generation,
					"error", err)
			}
			return false
		}
		delete(p.goAutoSDKTypeInfoKeys, process)
	}
	if err := p.goAutoSDKTypeInfos.Put(processKey, relocated); err != nil {
		if p.log != nil {
			p.log.Debug("registering Go Auto SDK types failed",
				"pid", pid, "namespace", ns,
				"host_pid", hostPID,
				"generation", processKey.Generation,
				"error", err)
		}
		return false
	}
	p.goAutoSDKTypeInfoKeys[process] = processKey
	return true
}

func relocateGoAutoSDKTypeInfo(
	typeInfo goexec.GoAutoSDKTypeInfo,
	loadBias uint64,
) (BpfGoAutoSdkTypeInfoT, error) {
	if !typeInfo.Valid() {
		return BpfGoAutoSdkTypeInfoT{}, errors.New("go Auto SDK type information is incomplete")
	}
	if typeInfo.TraceContextKeyType > ^uint64(0)-loadBias {
		return BpfGoAutoSdkTypeInfoT{}, errors.New("go Auto SDK type address overflowed")
	}
	nonRecordingSpanType := uint64(0)
	if typeInfo.NonRecordingSpanType != 0 {
		if typeInfo.NonRecordingSpanType > ^uint64(0)-loadBias {
			return BpfGoAutoSdkTypeInfoT{}, errors.New("go Auto SDK type address overflowed")
		}
		nonRecordingSpanType = typeInfo.NonRecordingSpanType + loadBias
	}
	recordingSpanType, err := relocateGoAddress(typeInfo.RecordingSpanType, loadBias)
	if err != nil {
		return BpfGoAutoSdkTypeInfoT{}, err
	}
	attributeOptionType, err := relocateGoAddress(typeInfo.AttributeOptionType, loadBias)
	if err != nil {
		return BpfGoAutoSdkTypeInfoT{}, err
	}
	timestampOptionType, err := relocateGoAddress(typeInfo.TimestampOptionType, loadBias)
	if err != nil {
		return BpfGoAutoSdkTypeInfoT{}, err
	}

	return BpfGoAutoSdkTypeInfoT{
		TraceContextKeyType:        typeInfo.TraceContextKeyType + loadBias,
		NonRecordingSpanType:       nonRecordingSpanType,
		RecordingSpanType:          recordingSpanType,
		AttributeOptionType:        attributeOptionType,
		TimestampOptionType:        timestampOptionType,
		NonRecordingSpanContextPos: typeInfo.NonRecordingSpanContextPos,
		RecordingSpanContextPos:    typeInfo.RecordingSpanContextPos,
		SpanContextTraceIdPos:      typeInfo.SpanContextTraceIDPos,
		SpanContextSpanIdPos:       typeInfo.SpanContextSpanIDPos,
		SpanContextTraceFlagsPos:   typeInfo.SpanContextTraceFlagsPos,
		SpanContextRemotePos:       typeInfo.SpanContextRemotePos,
	}, nil
}

func relocateGoAddress(address, loadBias uint64) (uint64, error) {
	if address == 0 {
		return 0, nil
	}
	if address > ^uint64(0)-loadBias {
		return 0, errors.New("go runtime address overflowed")
	}
	return address + loadBias, nil
}

func (p *Tracer) deleteGoSpanOptionFunctions(pid app.PID, ns uint32) {
	if p != nil {
		p.clearGoSpanOptionFunctions(runtimeMetricTargetKey{pid: pid, ns: ns})
	}
}

func (p *Tracer) clearGoSpanOptionFunctions(process runtimeMetricTargetKey) bool {
	keys, ok := p.goSpanOptionKeysByProcess[process]
	if !ok {
		return true
	}
	if p.goSpanOptionFunctions == nil {
		return false
	}

	remaining := make([]goSpanOptionFunctionKey, 0, len(keys))
	for _, key := range keys {
		err := p.goSpanOptionFunctions.Delete(key)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			remaining = append(remaining, key)
			p.log.Debug("deleting Go span-option function failed",
				"pid", process.pid, "namespace", process.ns,
				"function", key.Function, "error", err)
		}
	}
	if len(remaining) != 0 {
		p.goSpanOptionKeysByProcess[process] = remaining
		return false
	}

	delete(p.goSpanOptionKeysByProcess, process)
	return true
}

func (p *Tracer) deleteGoAutoSDKTypeInfo(pid app.PID, ns uint32) {
	if p == nil {
		return
	}
	process := runtimeMetricTargetKey{pid: pid, ns: ns}
	key, ok := p.goAutoSDKTypeInfoKeys[process]
	if !ok || p.goAutoSDKTypeInfos == nil {
		return
	}
	if err := p.goAutoSDKTypeInfos.Delete(key); err != nil &&
		!errors.Is(err, ebpf.ErrKeyNotExist) {
		if p.log != nil {
			p.log.Debug("deleting Go Auto SDK types failed",
				"pid", pid, "namespace", ns,
				"host_pid", key.PID,
				"generation", key.Generation,
				"error", err)
		}
		return
	}
	delete(p.goAutoSDKTypeInfoKeys, process)
}

var goAutoSDKSharedProbeSymbols = []string{
	"go.opentelemetry.io/auto/sdk.(*tracer).start",
	"go.opentelemetry.io/auto/sdk.(*span).ended",
	"go.opentelemetry.io/auto/sdk.(*span).End",
}

var goAutoSDKGlobalProbeSymbols = []string{
	"go.opentelemetry.io/otel/internal/global.(*tracer).Start",
	"go.opentelemetry.io/otel/internal/global.(*tracer).newSpan",
}

var goAutoSDKStartProbeSymbols = []string{
	"go.opentelemetry.io/auto/sdk.tracer.Start",
	"go.opentelemetry.io/auto/sdk.(*tracer).Start",
}

const goAutoSDKGlobalEntryProbeSymbol = "go.opentelemetry.io/otel/internal/global.(*tracer).newSpan"

func goAutoSDKFunctionsAvailable(offsets *goexec.Offsets) bool {
	_, available := goAutoSDKAttachmentSymbols(offsets)
	return available
}

func goAutoSDKAttachmentSymbols(offsets *goexec.Offsets) ([]string, bool) {
	if !goAutoSDKOffsetsAvailable(offsets) {
		return nil, false
	}
	required := make([]string, 0, len(goAutoSDKSharedProbeSymbols)+1)
	for _, symbol := range goAutoSDKSharedProbeSymbols {
		if _, ok := offsets.Funcs[symbol]; !ok {
			return nil, false
		}
		required = append(required, symbol)
	}

	startFound := false
	for _, symbol := range goAutoSDKStartProbeSymbols {
		if _, ok := offsets.Funcs[symbol]; ok {
			required = append(required, symbol)
			startFound = true
			break
		}
	}
	if !startFound {
		return nil, false
	}
	return required, true
}

func goAutoSDKGlobalAttachmentSymbols(offsets *goexec.Offsets) ([]string, bool) {
	if !goAutoSDKOffsetsAvailable(offsets) {
		return nil, false
	}
	required := make(
		[]string,
		0,
		len(goAutoSDKSharedProbeSymbols)+len(goAutoSDKGlobalProbeSymbols),
	)
	for _, symbol := range goAutoSDKSharedProbeSymbols {
		if _, ok := offsets.Funcs[symbol]; !ok {
			return nil, false
		}
		required = append(required, symbol)
	}
	for _, symbol := range goAutoSDKGlobalProbeSymbols {
		function, ok := offsets.Funcs[symbol]
		if !ok ||
			(symbol == goAutoSDKGlobalEntryProbeSymbol &&
				function.Admission == 0) {
			return nil, false
		}
		required = append(required, symbol)
	}
	return required, true
}

func goAutoSDKOffsetsAvailable(offsets *goexec.Offsets) bool {
	return offsets != nil &&
		offsets.SupportsGoAutoSDKActivation() &&
		offsets.AutoSDKTypes.Valid()
}

func initMissingGoChannelOffsets(offTable *BpfOffTableT) {
	if offTable == nil {
		return
	}

	for _, field := range goChannelOffsetFields {
		offTable.Table[field] = missingGoOffset
	}
}

func initMissingGRPCWriterOffsets(offTable *BpfOffTableT) {
	if offTable == nil {
		return
	}

	for _, field := range []goexec.GoOffset{
		goexec.GrpcTransportBufWriterBufPos,
		goexec.GrpcTransportBufWriterOffsetPos,
		goexec.GrpcTransportBufWriterConnPos,
	} {
		offTable.Table[field] = missingGoOffset
	}
}

func (p *Tracer) recordGoChannelOffsetAvailability(fileInfo *exec.FileInfo, offsets *goexec.Offsets) {
	if p == nil || fileInfo == nil {
		return
	}

	if p.goChannelOffsetsByExecutable == nil {
		p.goChannelOffsetsByExecutable = map[goExecutableKey]bool{}
	}

	executable, _ := goExecutableKeyFor(fileInfo)
	hasOffsets := offsets.HasGoChannelOffsets()
	p.goChannelOffsetsByExecutable[executable] = hasOffsets
	p.currentBinaryExecutable = executable

	if !hasOffsets && p.log != nil {
		p.log.Debug("skipping Go channel link probes for binary with missing runtime.hchan offsets",
			"pid", fileInfo.Pid(), "dev_major", executable.DevMajor, "dev_minor", executable.DevMinor, "ino", executable.Ino,
			"cmd", fileInfo.CmdExePath())
	}
}

func (p *Tracer) recordGoHTTP2ServerOffsetAvailability(
	fileInfo *exec.FileInfo,
	available goHTTP2ServerOffsetAvailability,
) {
	if p == nil || fileInfo == nil {
		return
	}
	if p.goHTTP2ServerOffsetsByExecutable == nil {
		p.goHTTP2ServerOffsetsByExecutable = map[goExecutableKey]goHTTP2ServerOffsetAvailability{}
	}
	executable, _ := goExecutableKeyFor(fileInfo)
	p.goHTTP2ServerOffsetsByExecutable[executable] = available
	if (!available.xNet || !available.vendored) && p.log != nil {
		p.log.Debug("some Go HTTP/2 server probes are unavailable for binary with missing offsets",
			"pid", fileInfo.Pid(), "dev_major", executable.DevMajor, "dev_minor", executable.DevMinor, "ino", executable.Ino,
			"x_net_available", available.xNet,
			"vendored_available", available.vendored,
			"cmd", fileInfo.CmdExePath())
	}
}

func (p *Tracer) recordGoRuntimeMetricAvailability(fileInfo *exec.FileInfo, offsets *goexec.Offsets) {
	if p == nil || fileInfo == nil {
		return
	}

	if p.goRuntimeMetricMaskByExecutable == nil {
		p.goRuntimeMetricMaskByExecutable = map[goExecutableKey]uint64{}
	}
	if p.goRuntimeGCGoalSourceByExecutable == nil {
		p.goRuntimeGCGoalSourceByExecutable = map[goExecutableKey]goRuntimeGCGoalSource{}
	}

	executable, _ := goExecutableKeyFor(fileInfo)
	mask := goRuntimeMetricMask(offsets)
	gcGoalSource := selectGoRuntimeGCGoalSource(
		offsets,
		goexec.RuntimeMetricGCGoalArgumentSupported(fileInfo.ELF()),
	)
	if gcGoalSource != goRuntimeGCGoalSourceNone {
		mask |= goRuntimeMetricMemoryGCGoalMask
	}
	p.goRuntimeGCGoalSourceByExecutable[executable] = gcGoalSource
	includesSystem, modeKnown := goexec.RuntimeMetricGoroutineCountMode(fileInfo.ELF())
	if hasGoRuntimeGoroutineCountOffsets(offsets, includesSystem, modeKnown) {
		mask |= goRuntimeMetricGoroutineCountMask
	}
	supportsStableHeapSnapshotVersion, err := goexec.SupportsGoRuntimeMemoryMetrics(fileInfo.ELF())
	if err != nil && p.log != nil {
		p.log.Debug("Go runtime memory metric version detection failed",
			"pid", fileInfo.Pid(),
			"dev_major", executable.DevMajor, "dev_minor", executable.DevMinor,
			"ino", executable.Ino,
			"cmd", fileInfo.CmdExePath(),
			"error", err)
	}

	heapMetricsEnabled := mask&goRuntimeMetricHeapSnapshotMask != 0
	nextGenResolved := false
	if offsets != nil {
		_, nextGenResolved = offsets.Funcs[goRuntimeMetricHeapSnapshotSymbol]
	}

	if !supportsStableHeapSnapshotVersion {
		mask &^= goRuntimeMetricHeapSnapshotMask
	} else if heapMetricsEnabled && !nextGenResolved {
		mask &^= goRuntimeMetricHeapSnapshotMask
		if p.log != nil {
			p.log.Warn("Go runtime heap metric symbol unresolved; using scalar fallback",
				"pid", fileInfo.Pid(),
				"dev_major", executable.DevMajor, "dev_minor", executable.DevMinor,
				"ino", executable.Ino,
				"cmd", fileInfo.CmdExePath(),
				"missing_probe", goRuntimeMetricHeapSnapshotSymbol,
				"fallback_probe", goRuntimeMetricGCMarkDoneSymbol)
		}
	}
	p.goRuntimeMetricMaskByExecutable[executable] = mask

	if p.log != nil {
		p.log.Debug("Go runtime metric availability",
			"pid", fileInfo.Pid(),
			"dev_major", executable.DevMajor, "dev_minor", executable.DevMinor,
			"ino", executable.Ino,
			"cmd", fileInfo.CmdExePath(),
			"available_mask", mask,
			"base_available", hasBaseGoRuntimeMetrics(mask),
			"cpu_time_available", mask&goRuntimeMetricCPUTimeMask != 0,
			"memory_available", mask&goRuntimeMetricMemoryUsedMask != 0,
			"goroutine_count_available", mask&goRuntimeMetricGoroutineCountMask != 0,
			"memory_gc_goal_available", mask&goRuntimeMetricMemoryGCGoalMask != 0,
			"memory_gc_goal_source", gcGoalSource,
			"gc_pause_histogram_available", mask&goRuntimeMetricGCPauseHistogramMask != 0,
			"schedule_duration_histogram_available", mask&goRuntimeMetricScheduleDurationHistogramMask != 0)
	}
}

func selectGoRuntimeGCGoalSource(
	offsets *goexec.Offsets,
	goalArgumentSupported bool,
) goRuntimeGCGoalSource {
	if offsets == nil {
		return goRuntimeGCGoalSourceNone
	}
	if hasGoRuntimeMetricOffsets(offsets, goexec.RuntimeGCControllerHeapGoalPos) {
		return goRuntimeGCGoalSourceHeapGoalField
	}
	if _, ok := offsets.Funcs[goRuntimeMetricGCGoalSymbol]; ok && goalArgumentSupported {
		return goRuntimeGCGoalSourcePaceScavengerArgument
	}
	return goRuntimeGCGoalSourceNone
}

func goRuntimeMetricMask(offsets *goexec.Offsets) uint64 {
	if offsets == nil {
		return 0
	}

	mask := goRuntimeMetricProcessorLimitMask
	for _, group := range goRuntimeMetricOffsetGroups {
		if hasGoRuntimeMetricOffsets(offsets, group.fields...) {
			mask |= group.mask
		}
	}
	if !hasSupportedGoRuntimeHistogramLayout(offsets) {
		mask &^= goRuntimeMetricHistogramMask
	}

	return mask
}

func hasSupportedGoRuntimeHistogramLayout(offsets *goexec.Offsets) bool {
	underflowOffset, underflowOK := offsets.Field[goexec.RuntimeTimeHistogramUnderflowPos].(uint64)
	overflowOffset, overflowOK := offsets.Field[goexec.RuntimeTimeHistogramOverflowPos].(uint64)
	if !underflowOK || !overflowOK {
		return false
	}

	expectedUnderflowOffset := goRuntimeHistogramMaxBuckets * goRuntimeHistogramBucketSize
	return underflowOffset == expectedUnderflowOffset &&
		overflowOffset == expectedUnderflowOffset+goRuntimeHistogramBucketSize
}

func hasGoRuntimeMetricOffsets(offsets *goexec.Offsets, fields ...goexec.GoOffset) bool {
	if offsets == nil {
		return false
	}
	for _, field := range fields {
		if _, ok := offsets.Field[field].(uint64); !ok {
			return false
		}
	}
	return true
}

func hasGoRuntimeGoroutineCountOffsets(
	offsets *goexec.Offsets,
	includesSystem bool,
	modeKnown bool,
) bool {
	if !modeKnown || !hasGoRuntimeMetricOffsets(offsets, goRuntimeGoroutineCountCommonOffsetFields[:]...) {
		return false
	}
	return includesSystem || hasGoRuntimeMetricOffsets(offsets, goexec.RuntimeSchedNgSysPos)
}

func hasBaseGoRuntimeMetrics(mask uint64) bool {
	return mask&goRuntimeMetricBaseMask == goRuntimeMetricBaseMask
}

// registerRuntimeMetricTarget writes per-process Go runtime global addresses
// into BPF. Offsets stay inode-scoped in go_offsets_map, but these addresses
// are process-scoped for PIE/ASLR and must follow the PID allow lifecycle.
func (p *Tracer) registerRuntimeMetricTarget(pid app.PID, ns uint32, fileInfo *exec.FileInfo) {
	if fileInfo == nil || p.bpfObjects.GoRuntimeMetricTargets == nil {
		return
	}
	executable, _ := goExecutableKeyFor(fileInfo)
	availableMask := p.goRuntimeMetricMaskByExecutable[executable]
	if !hasBaseGoRuntimeMetrics(availableMask) {
		return
	}

	pidInfo, err := runtimeMetricPIDInfo(pid, ns)
	if err != nil {
		p.log.Debug("runtime metrics PID key lookup failed", "pid", pid, "ns", ns, "error", err)
		return
	}

	symbols, err := goexec.ResolveRuntimeMetricSymbols(fileInfo, pid)
	if err != nil {
		p.log.Debug("runtime metrics disabled for executable", "pid", pid,
			"dev_major", executable.DevMajor, "dev_minor", executable.DevMinor, "ino", executable.Ino, "error", err)
		return
	}
	availableMask = p.goRuntimeMetricMaskForSymbols(fileInfo, availableMask, symbols)
	p.goRuntimeMetricMaskByExecutable[executable] = availableMask

	value := BpfGoRuntimeMetricTargetT{
		MemstatsAddr:                 symbols.MemstatsAddr,
		GcControllerAddr:             symbols.GCControllerAddr,
		GomaxprocsAddr:               symbols.GOMAXPROCSAddr,
		WorkAddr:                     symbols.WorkAddr,
		AvailableMask:                availableMask,
		SizeClassToSizesAddr:         symbols.SizeClassToSizesAddr,
		SchedAddr:                    symbols.SchedAddr,
		AllglenAddr:                  symbols.AllgLenAddr,
		AllpAddr:                     symbols.AllpAddr,
		GoroutineCountIncludesSystem: symbols.GoroutineCountIncludesSystem,
		GcGoalSource:                 uint32(p.goRuntimeGCGoalSourceByExecutable[executable]),
	}

	if err := p.bpfObjects.GoRuntimeMetricTargets.Put(pidInfo, value); err != nil {
		p.log.Debug("setting runtime metric target failed", "pid", pid,
			"dev_major", executable.DevMajor, "dev_minor", executable.DevMinor, "ino", executable.Ino, "error", err)
		return
	}

	if p.runtimeMetricTargetKeys == nil {
		p.runtimeMetricTargetKeys = map[runtimeMetricTargetKey]BpfPidInfo{}
	}
	p.runtimeMetricTargetKeys[runtimeMetricTargetKey{pid: pid, ns: ns}] = pidInfo
}

func (p *Tracer) goRuntimeMetricMaskForSymbols(
	fileInfo *exec.FileInfo,
	mask uint64,
	symbols goexec.RuntimeMetricSymbols,
) uint64 {
	executable, _ := goExecutableKeyFor(fileInfo)
	if mask&goRuntimeMetricMemoryAllocsMask != 0 && symbols.SizeClassToSizesAddr == 0 {
		mask &^= goRuntimeMetricMemoryAllocsMask
		if p.log != nil {
			p.log.Warn("Go runtime size-class table symbol unresolved; disabling allocation metrics",
				"pid", fileInfo.Pid(),
				"dev_major", executable.DevMajor, "dev_minor", executable.DevMinor,
				"ino", executable.Ino,
				"cmd", fileInfo.CmdExePath())
		}
	}

	if mask&goRuntimeMetricGoroutineCountMask != 0 &&
		(symbols.SchedAddr == 0 || symbols.AllgLenAddr == 0 || symbols.AllpAddr == 0 ||
			!symbols.GoroutineCountModeKnown) {
		mask &^= goRuntimeMetricGoroutineCountMask
		if p.log != nil {
			p.log.Warn("Go runtime goroutine count metadata unresolved; disabling goroutine metric",
				"pid", fileInfo.Pid(),
				"dev_major", executable.DevMajor, "dev_minor", executable.DevMinor,
				"ino", executable.Ino,
				"cmd", fileInfo.CmdExePath())
		}
	}

	if mask&goRuntimeMetricHistogramMask != 0 && symbols.SchedAddr == 0 {
		mask &^= goRuntimeMetricHistogramMask
		if p.log != nil {
			p.log.Warn("Go runtime scheduler symbol unresolved; disabling histogram metrics",
				"pid", fileInfo.Pid(),
				"dev_major", executable.DevMajor, "dev_minor", executable.DevMinor,
				"ino", executable.Ino,
				"cmd", fileInfo.CmdExePath())
		}
	}
	return mask
}

// deleteRuntimeMetricTarget removes process-scoped runtime metadata whenever
// the process is no longer eligible for runtime metric collection.
func (p *Tracer) deleteRuntimeMetricTarget(pid app.PID, ns uint32) {
	process := runtimeMetricTargetKey{pid: pid, ns: ns}
	pidInfo, ok := p.runtimeMetricTargetKeys[process]
	if !ok {
		var err error
		pidInfo, err = runtimeMetricPIDInfo(pid, ns)
		if err != nil {
			p.log.Debug("runtime metrics PID key lookup failed", "pid", pid, "ns", ns, "error", err)
			return
		}
	}

	if p.bpfObjects.GoRuntimeMetricTargets != nil {
		_ = p.bpfObjects.GoRuntimeMetricTargets.Delete(pidInfo)
	}
	delete(p.runtimeMetricTargetKeys, process)
}

func runtimeMetricPIDInfo(pid app.PID, ns uint32) (BpfPidInfo, error) {
	pidInfo := BpfPidInfo{
		HostPid: uint32(pid),
		UserPid: uint32(pid),
		Ns:      ns,
	}

	pids, err := procs.FindNamespacedPids(pid)
	if err != nil {
		return BpfPidInfo{}, fmt.Errorf("reading namespaced PIDs: %w", err)
	}
	if len(pids) == 0 {
		return pidInfo, nil
	}

	pidInfo.HostPid = uint32(pids[0])
	pidInfo.UserPid = uint32(pids[len(pids)-1])
	return pidInfo, nil
}

func resolveGoProcessHostPID(pid app.PID, ns uint32) (uint32, error) {
	pidInfo, err := runtimeMetricPIDInfo(pid, ns)
	if err != nil {
		return 0, err
	}
	return pidInfo.HostPid, nil
}

func (p *Tracer) ProcessBinary(fileInfo *exec.FileInfo) {
	if p == nil {
		return
	}
	p.processMu.Lock()
	defer p.processMu.Unlock()

	if fileInfo == nil {
		p.currentBinaryExecutable = goExecutableKey{}
		return
	}

	p.currentBinaryExecutable, _ = goExecutableKeyFor(fileInfo)
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.goTracerResources().Add(c...)
}

func (p *Tracer) goTracerResources() *goTracerResources {
	p.resourcesMu.Lock()
	defer p.resourcesMu.Unlock()
	if p.resources == nil {
		p.resources = newGoTracerResources(p, &p.bpfObjects)
	}
	return p.resources
}

func (p *Tracer) ResourceTeardownReady() bool {
	if p == nil {
		return true
	}
	p.resourcesMu.Lock()
	defer p.resourcesMu.Unlock()
	return p.resources == nil || p.resources.teardownReady()
}

var goChannelLinkProbeSymbols = []string{
	"runtime.chansend1",
	"runtime.chanrecv1",
	"runtime.chanrecv2",
}

const (
	goRuntimeMetricGCMarkDoneSymbol   = "runtime.gcMarkDone"
	goRuntimeMetricHeapSnapshotSymbol = "runtime.(*scavengeIndex).nextGen"
	goRuntimeMetricGCGoalSymbol       = "runtime.gcPaceScavenger"
)

var goRuntimeMetricProbeSymbols = []string{
	goRuntimeMetricGCMarkDoneSymbol,
	goRuntimeMetricHeapSnapshotSymbol,
	goRuntimeMetricGCGoalSymbol,
}

var goHpackEncoderWriteFieldProbeSymbols = []string{
	"golang.org/x/net/http2/hpack.(*Encoder).WriteField",
	"vendor/golang.org/x/net/http2/hpack.(*Encoder).WriteField",
}

var goHTTP2XNetServerProbeSymbols = []string{
	"golang.org/x/net/http2.(*serverConn).runHandler",
	"golang.org/x/net/http2.(*serverConn).processHeaders",
}

var goHTTP2VendoredServerProbeSymbols = []string{
	"net/http.(*http2serverConn).runHandler",
	"net/http.(*http2serverConn).processHeaders",
}

var goHTTP2ServerProbeSymbols = append(
	append([]string(nil), goHTTP2XNetServerProbeSymbols...),
	goHTTP2VendoredServerProbeSymbols...,
)

// GoChannelLinkProbeSymbols returns the Go runtime symbols used to correlate direct channel handoffs.
func GoChannelLinkProbeSymbols() []string {
	return append([]string(nil), goChannelLinkProbeSymbols...)
}

// GoRuntimeMetricProbeSymbols returns every candidate used for per-binary runtime metric probes.
func GoRuntimeMetricProbeSymbols() []string {
	return append([]string(nil), goRuntimeMetricProbeSymbols...)
}

func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	probeState := p.goProbeState()
	m := map[string][]*ebpfcommon.ProbeDesc{
		// Go runtime
		"runtime.newproc1": {{
			Start: p.bpfObjects.ObiUprobeRuntimeNewproc1,
			End:   p.bpfObjects.ObiUprobeRuntimeNewproc1Return,
		}},
		"runtime.casgstatus": {{
			Start: p.bpfObjects.ObiUprobeRuntimeCasgstatus,
		}},
		"runtime.mstart1": {{
			Start: p.bpfObjects.ObiUprobeRuntimeMstart1,
		}},
		"runtime.mexit": {{
			Start: p.bpfObjects.ObiUprobeRuntimeMexit,
		}},
		// Go net/http
		"net/http.serverHandler.ServeHTTP": {{
			Start: p.bpfObjects.ObiUprobeServeHTTP,
		}},
		"net/http.(*response).finishRequest": {{
			End: p.bpfObjects.ObiUprobeServeHTTPReturns,
		}},
		"net/http.(*conn).readRequest": {{
			Start: p.bpfObjects.ObiUprobeReadRequestStart,
			End:   p.bpfObjects.ObiUprobeReadRequestReturns,
		}},
		// Go net/rpc/jsonrpc
		"net/rpc/jsonrpc.(*serverCodec).ReadRequestHeader": {{
			Start: p.bpfObjects.ObiUprobeJsonrpcReadRequestHeader,
			End:   p.bpfObjects.ObiUprobeJsonrpcReadRequestHeaderReturns,
		}},
		"net/http.(*Transport).roundTrip": {{ // HTTP client, works with Client.Do as well as using the RoundTripper directly
			Start: p.bpfObjects.ObiUprobeRoundTrip,
			End:   p.bpfObjects.ObiUprobeRoundTripReturn,
		}},
		"golang.org/x/net/http2.(*ClientConn).roundTrip": {{ // http2 client after 0.22
			Start: p.bpfObjects.ObiUprobeHttp2RoundTrip,
			End:   p.bpfObjects.ObiUprobeRoundTripReturn, // return is the same as for http 1.1
		}},
		"golang.org/x/net/http2.(*ClientConn).RoundTrip": {{ // http2 client
			Start: p.bpfObjects.ObiUprobeHttp2RoundTrip,
			End:   p.bpfObjects.ObiUprobeRoundTripReturn, // return is the same as for http 1.1
		}},
		"net/http.(*http2ClientConn).RoundTrip": {{ // http2 client vendored in Go
			Start: p.bpfObjects.ObiUprobeHttp2RoundTrip,
			End:   p.bpfObjects.ObiUprobeRoundTripReturn, // return is the same as for http 1.1
		}},
		"net/http.(*http2responseWriter).handlerDone": {{
			End: p.bpfObjects.ObiUprobeServeHTTPReturns,
		}},
		"golang.org/x/net/http2.(*responseWriter).handlerDone": {{
			End: p.bpfObjects.ObiUprobeServeHTTPReturns,
		}},
		"golang.org/x/net/http2.(*ClientConn).writeHeaders": {{ // http2 client
			Start: p.bpfObjects.ObiUprobeHttp2WriteHeaders,
		}},
		"net/http.(*http2ClientConn).writeHeaders": {{ // http2 client vendored in Go, but used from http 1.1 transition
			Start: p.bpfObjects.ObiUprobeHttp2WriteHeadersVendored,
		}},
		"golang.org/x/net/http2.(*responseWriterState).writeHeader": {{ // http2 server request done, capture the response code
			Start: p.bpfObjects.ObiUprobeHttp2ResponseWriterStateWriteHeader,
		}},
		"net/http.(*http2responseWriterState).writeHeader": {{ // same as above, vendored in go
			Start: p.bpfObjects.ObiUprobeHttp2ResponseWriterStateWriteHeader,
		}},
		"net/http.(*response).WriteHeader": {{
			Start: p.bpfObjects.ObiUprobeHttp2ResponseWriterStateWriteHeader, // http response code capture
		}},
		"golang.org/x/net/http2.(*serverConn).runHandler": {{
			Start: p.bpfObjects.ObiUprobeHttp2serverConnRunHandler, // http2 server connection tracking
			End:   p.bpfObjects.ObiUprobeHttp2serverConnRunHandlerReturns,
		}},
		"net/http.(*http2serverConn).runHandler": {{
			Start: p.bpfObjects.ObiUprobeHttp2serverConnRunHandler, // http2 server connection tracking, vendored in go
			End:   p.bpfObjects.ObiUprobeHttp2serverConnRunHandlerReturns,
		}},
		"golang.org/x/net/http2.(*serverConn).processHeaders": {{
			Start: p.bpfObjects.ObiUprobeHttp2ServerProcessHeaders, // http2 server request header parsing
			End:   p.bpfObjects.ObiUprobeHttp2ServerProcessHeadersReturns,
		}},
		"net/http.(*http2serverConn).processHeaders": {{
			Start: p.bpfObjects.ObiUprobeHttp2ServerProcessHeadersVendored, // http2 server request header parsing, vendored in go
			End:   p.bpfObjects.ObiUprobeHttp2ServerProcessHeadersReturnsVendored,
		}},
		// tracking of tcp connections for black-box propagation
		"net/http.(*conn).serve": {{ // http server
			Start: p.bpfObjects.ObiUprobeConnServe,
			End:   p.bpfObjects.ObiUprobeConnServeRet,
		}},
		"net.(*netFD).Read": {{
			Start: p.bpfObjects.ObiUprobeNetFdRead,
			End:   p.bpfObjects.ObiUprobeNetFdReadRet,
		}},
		"net.(*netFD).Write": {{
			Start: p.bpfObjects.ObiUprobeNetFdWrite,
		}},
		"crypto/tls.(*Conn).Read": {{
			Start: p.bpfObjects.ObiUprobeCryptoTlsRead,
			End:   p.bpfObjects.ObiUprobeCryptoTlsReadRet,
		}},
		"crypto/tls.(*Conn).Write": {{
			Start: p.bpfObjects.ObiUprobeCryptoTlsWrite,
			End:   p.bpfObjects.ObiUprobeCryptoTlsWriteRet,
		}},
		"net.(*netFD).Close": {{
			Start: p.bpfObjects.ObiUprobeNetFdClose,
		}},
		"net/http.(*persistConn).roundTrip": {{ // http client
			Start: p.bpfObjects.ObiUprobePersistConnRoundTrip,
		}},
		// sql
		"database/sql.(*DB).queryDC": {{
			Start: p.bpfObjects.ObiUprobeQueryDC,
			End:   p.bpfObjects.ObiUprobeQueryReturn,
		}},
		"database/sql.(*DB).execDC": {{
			Start: p.bpfObjects.ObiUprobeExecDC,
			End:   p.bpfObjects.ObiUprobeQueryReturn,
		}},
		// PostgreSQL lib/pq
		"github.com/lib/pq.network": {{
			End: p.bpfObjects.ObiUprobePqNetworkReturn,
		}},
		// PostgreSQL pgx
		"github.com/jackc/pgx/v5.(*Conn).Query": {{
			Start: p.bpfObjects.ObiUprobePgxQuery,
			End:   p.bpfObjects.ObiUprobePgxQueryReturn,
		}},
		"github.com/jackc/pgx/v5.(*Conn).Exec": {{
			Start: p.bpfObjects.ObiUprobePgxExec,
			End:   p.bpfObjects.ObiUprobePgxQueryReturn,
		}},
		// Go gRPC
		"google.golang.org/grpc.(*Server).handleStream": {{
			Start: p.bpfObjects.ObiUprobeServerHandleStream,
			End:   p.bpfObjects.ObiUprobeServerHandleStreamReturn,
		}},
		"google.golang.org/grpc/internal/transport.(*http2Server).WriteStatus": {{
			Start: p.bpfObjects.ObiUprobeTransportWriteStatus,
		}},
		// in grpc 1.69.0 they renamed the above WriteStatus to writeStatus lowercase
		"google.golang.org/grpc/internal/transport.(*http2Server).writeStatus": {{
			Start: p.bpfObjects.ObiUprobeTransportWriteStatus,
		}},
		"google.golang.org/grpc.(*ClientConn).Invoke": {{
			Start: p.bpfObjects.ObiUprobeClientConnInvoke,
			End:   p.bpfObjects.ObiUprobeClientConnInvokeReturn,
		}},
		"google.golang.org/grpc.(*ClientConn).NewStream": {{
			Start: p.bpfObjects.ObiUprobeClientConnNewStream,
			End:   p.bpfObjects.ObiUprobeClientConnNewStreamReturn,
		}},
		"google.golang.org/grpc.(*ClientConn).Close": {{
			Start: p.bpfObjects.ObiUprobeClientConnClose,
		}},
		"google.golang.org/grpc.(*clientStream).RecvMsg": {{
			Start: p.bpfObjects.ObiUprobeClientStreamRecvMsg,
			End:   p.bpfObjects.ObiUprobeClientStreamRecvMsgReturn,
		}},
		"google.golang.org/grpc.(*clientStream).finish": {{
			Start:    p.bpfObjects.ObiUprobeClientStreamFinish,
			Required: false,
		}},
		"google.golang.org/grpc/internal/transport.(*http2Client).NewStream": {{
			Start: p.bpfObjects.ObiUprobeTransportHttp2ClientNewStream,
			End:   p.bpfObjects.ObiUprobeTransportHttp2ClientNewStreamReturns,
		}},
		// Closes the loopyWriter race for stream registration — see
		// the two-hop bridge in go_grpc.c (executeAndPut → originateStream)
		"google.golang.org/grpc/internal/transport.(*controlBuffer).executeAndPut": {{
			Start: p.bpfObjects.ObiUprobeGrpcControlBufferExecuteAndPut,
		}},
		"google.golang.org/grpc/internal/transport.(*loopyWriter).originateStream": {{
			Start: p.bpfObjects.ObiUprobeGrpcLoopyWriterOriginateStream,
		}},
		"google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders": {{
			Start: p.bpfObjects.ObiUprobeHttp2ServerOperateHeaders,
		}},
		"google.golang.org/grpc/internal/transport.(*serverHandlerTransport).HandleStreams": {{
			Start: p.bpfObjects.ObiUprobeServerHandlerTransportHandleStreams,
		}},
		// Redis
		"github.com/redis/go-redis/v9/internal/pool.(*Conn).WithWriter": {{
			Start: p.bpfObjects.ObiUprobeRedisWithWriter,
			End:   p.bpfObjects.ObiUprobeRedisWithWriterRet,
		}},
		"github.com/redis/go-redis/v9.(*baseClient)._process": {{
			Start: p.bpfObjects.ObiUprobeRedisProcess,
			End:   p.bpfObjects.ObiUprobeRedisProcessRet,
		}},
		"github.com/redis/go-redis/v9.(*baseClient).pipelineProcessCmds": {{
			Start: p.bpfObjects.ObiUprobeRedisProcess,
			End:   p.bpfObjects.ObiUprobeRedisProcessRet,
		}},
		"github.com/redis/go-redis/v9.(*baseClient).txPipelineProcessCmds": {{
			Start: p.bpfObjects.ObiUprobeRedisProcess,
			End:   p.bpfObjects.ObiUprobeRedisProcessRet,
		}},
		// Kafka Go
		"github.com/segmentio/kafka-go.(*Writer).WriteMessages": {{ // runs on the same gorountine as other requests, finds traceparent info
			Start: p.bpfObjects.ObiUprobeWriterWriteMessages,
			End:   p.bpfObjects.ObiUprobeWriterWriteMessagesRet,
		}},
		"github.com/segmentio/kafka-go.(*Writer).produce": {{ // stores the current topic
			Start: p.bpfObjects.ObiUprobeWriterProduce,
		}},
		"github.com/segmentio/kafka-go.(*Client).roundTrip": {{ // has the goroutine connection with (*Writer).produce and msg* connection with protocol.RoundTrip
			Start: p.bpfObjects.ObiUprobeClientRoundTrip,
		}},
		"github.com/segmentio/kafka-go/protocol.RoundTrip": {{ // used for collecting the connection information
			Start: p.bpfObjects.ObiUprobeProtocolRoundtrip,
			End:   p.bpfObjects.ObiUprobeProtocolRoundtripRet,
		}},
		"github.com/segmentio/kafka-go.(*reader).read": {{ // used for capturing the info for the fetch operations
			Start: p.bpfObjects.ObiUprobeReaderRead,
			End:   p.bpfObjects.ObiUprobeReaderReadRet,
		}},
		"github.com/segmentio/kafka-go.(*reader).sendMessage": {{ // to accurately measure the start time
			Start: p.bpfObjects.ObiUprobeReaderSendMessage,
		}},
		// Kafka sarama
		"github.com/IBM/sarama.(*Broker).write": {{
			Start: p.bpfObjects.ObiUprobeSaramaBrokerWrite,
		}},
		"github.com/IBM/sarama.(*responsePromise).handle": {{
			Start: p.bpfObjects.ObiUprobeSaramaResponsePromiseHandle,
		}},
		"github.com/IBM/sarama.(*Broker).sendInternal": {{
			Start: p.bpfObjects.ObiUprobeSaramaSendInternal,
		}},
		"github.com/Shopify/sarama.(*Broker).write": {{
			Start: p.bpfObjects.ObiUprobeSaramaBrokerWrite,
		}},
		"github.com/Shopify/sarama.(*responsePromise).handle": {{
			Start: p.bpfObjects.ObiUprobeSaramaResponsePromiseHandle,
		}},
		"github.com/Shopify/sarama.(*Broker).sendInternal": {{
			Start: p.bpfObjects.ObiUprobeSaramaSendInternal,
		}},
		// Go OTel SDK
		"go.opentelemetry.io/otel/internal/global.(*tracer).Start": {{
			Start: p.bpfObjects.ObiUprobeTracerStartGlobal,
			End:   p.bpfObjects.ObiUprobeTracerStartReturns,
		}},
		"go.opentelemetry.io/auto/sdk.(*tracer).Start": {{
			Start: p.bpfObjects.ObiUprobeTracerStart,
			End:   p.bpfObjects.ObiUprobeTracerStartReturns,
		}},
		"go.opentelemetry.io/auto/sdk.tracer.Start": {{
			Start: p.bpfObjects.ObiUprobeTracerStartValue,
			End:   p.bpfObjects.ObiUprobeTracerStartReturns,
		}},
		"go.opentelemetry.io/otel/internal/global.(*nonRecordingSpan).End": {{
			Start: p.bpfObjects.ObiUprobeNonRecordingSpanEnd,
		}},
		"go.opentelemetry.io/auto/sdk.(*span).End": {{
			Start: p.bpfObjects.ObiUprobeNonRecordingSpanEnd,
		}},
		"go.opentelemetry.io/otel/internal/global.(*nonRecordingSpan).SetStatus": {{
			Start: p.bpfObjects.ObiUprobeSetStatus,
		}},
		"go.opentelemetry.io/auto/sdk.(*span).SetStatus": {{
			Start: p.bpfObjects.ObiUprobeSetStatus,
		}},
		"go.opentelemetry.io/otel/internal/global.(*nonRecordingSpan).SetAttributes": {{
			Start: p.bpfObjects.ObiUprobeSetAttributes,
		}},
		"go.opentelemetry.io/auto/sdk.(*span).SetAttributes": {{
			Start: p.bpfObjects.ObiUprobeSetAttributes,
		}},
		"go.opentelemetry.io/otel/internal/global.(*nonRecordingSpan).SetName": {{
			Start: p.bpfObjects.ObiUprobeSetName,
		}},
		"go.opentelemetry.io/auto/sdk.(*span).SetName": {{
			Start: p.bpfObjects.ObiUprobeSetName,
		}},
		"go.opentelemetry.io/otel/internal/global.(*nonRecordingSpan).RecordError": {{
			Start: p.bpfObjects.ObiUprobeRecordError,
		}},
		"go.opentelemetry.io/auto/sdk.(*span).RecordError": {{
			Start: p.bpfObjects.ObiUprobeRecordError,
		}},
		// Go MongoDB
		"go.mongodb.org/mongo-driver/x/mongo/driver.Operation.Execute": {{
			Start: p.bpfObjects.ObiUprobeMongoOpExecute,
			End:   p.bpfObjects.ObiUprobeMongoOpExecuteRet,
		}},
		"go.mongodb.org/mongo-driver/v2/x/mongo/driver.Operation.Execute": {{
			Start: p.bpfObjects.ObiUprobeMongoOpExecute,
			End:   p.bpfObjects.ObiUprobeMongoOpExecuteRet,
		}},
		// all of these point to the same probe, we just use it to find start time and collection name
		"go.mongodb.org/mongo-driver/mongo.(*Collection).insert": {{
			Start: p.bpfObjects.ObiUprobeMongoOpInsert,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).insert": {{
			Start: p.bpfObjects.ObiUprobeMongoOpInsert,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).delete": {{
			Start: p.bpfObjects.ObiUprobeMongoOpDelete,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).delete": {{
			Start: p.bpfObjects.ObiUprobeMongoOpDelete,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).updateOrReplace": {{
			Start: p.bpfObjects.ObiUprobeMongoOpUpdateOrReplace,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).updateOrReplace": {{
			Start: p.bpfObjects.ObiUprobeMongoOpUpdateOrReplace,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).find": {{
			Start: p.bpfObjects.ObiUprobeMongoOpFind,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).find": {{
			Start: p.bpfObjects.ObiUprobeMongoOpFind,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).Find": {{
			Start: p.bpfObjects.ObiUprobeMongoOpFind,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).Find": {{
			Start: p.bpfObjects.ObiUprobeMongoOpFind,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).drop": {{
			Start: p.bpfObjects.ObiUprobeMongoOpDrop,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).drop": {{
			Start: p.bpfObjects.ObiUprobeMongoOpDrop,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).findAndModify": {{
			Start: p.bpfObjects.ObiUprobeMongoOpFindAndModify,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).findAndModify": {{
			Start: p.bpfObjects.ObiUprobeMongoOpFindAndModify,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).Aggregate": {{
			Start: p.bpfObjects.ObiUprobeMongoOpAggregate,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).Aggregate": {{
			Start: p.bpfObjects.ObiUprobeMongoOpAggregate,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).CountDocuments": {{
			Start: p.bpfObjects.ObiUprobeMongoOpCountDocuments,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).CountDocuments": {{
			Start: p.bpfObjects.ObiUprobeMongoOpCountDocuments,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).EstimatedDocumentCount": {{
			Start: p.bpfObjects.ObiUprobeMongoOpEstimatedDocumentCount,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).EstimatedDocumentCount": {{
			Start: p.bpfObjects.ObiUprobeMongoOpEstimatedDocumentCount,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).Distinct": {{
			Start: p.bpfObjects.ObiUprobeMongoOpDistinct,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).Distinct": {{
			Start: p.bpfObjects.ObiUprobeMongoOpDistinct,
		}},
	}

	if !probeState.http2XNetServer {
		for _, symbol := range goHTTP2XNetServerProbeSymbols {
			delete(m, symbol)
		}
	}
	if !probeState.http2VendoredServer {
		for _, symbol := range goHTTP2VendoredServerProbeSymbols {
			delete(m, symbol)
		}
	}

	if p.supportsContextPropagation() {
		m["go.opentelemetry.io/otel/internal/global.(*tracer).newSpan"] = []*ebpfcommon.ProbeDesc{{
			Start:           p.bpfObjects.ObiUprobeTracerNewSpan,
			End:             p.bpfObjects.ObiUprobeTracerNewSpanReturn,
			AttachStartLast: true,
		}}
		m["go.opentelemetry.io/auto/sdk.(*tracer).start"] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeAutoSdkTracerStart,
		}}
		m["go.opentelemetry.io/auto/sdk.(*span).ended"] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeAutoSdkSpanEnded,
		}}
	}

	if probeState.runtimeHeapSnapshot {
		// Go 1.23+ heap statistics use a rotating ring. Collect at nextGen after GC
		// accounting and before the world restarts so the ring cannot rotate mid-read.
		m[goRuntimeMetricHeapSnapshotSymbol] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeGoRuntimeMetrics,
		}}
	} else {
		// Older Go versions expose only the scalar metric set and may not contain
		// nextGen. Keep the gcMarkDone return probe for backward compatibility.
		m[goRuntimeMetricGCMarkDoneSymbol] = []*ebpfcommon.ProbeDesc{{
			End: p.bpfObjects.ObiUprobeGoRuntimeMetrics,
		}}
	}

	if probeState.runtimeGCGoal {
		m[goRuntimeMetricGCGoalSymbol] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeGoRuntimeGcGoal,
		}}
	}

	if probeState.channelLinks {
		m[goChannelLinkProbeSymbols[0]] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeRuntimeChansend1,
			End:   p.bpfObjects.ObiUprobeRuntimeChansend1Return,
		}}
		m[goChannelLinkProbeSymbols[1]] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeRuntimeChanrecv1,
			End:   p.bpfObjects.ObiUprobeRuntimeChanrecv1Return,
		}}
		m[goChannelLinkProbeSymbols[2]] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeRuntimeChanrecv2,
			End:   p.bpfObjects.ObiUprobeRuntimeChanrecv2Return,
		}}
	}

	// HTTP Header extraction
	// with bpf_loop we scan the buffer with a single uprobe - this is less overhead
	// otherwise we have a probe per header net/textproto.(*Reader).readContinuedLineSlice
	if p.supportsBPFLoop {
		m["net/textproto.readMIMEHeader"] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeReadMimeHeader,
		}}
		// old go versions
		m["net/textproto.(*Reader).ReadMIMEHeader"] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeReadMimeHeader,
		}}
	} else {
		m["net/textproto.(*Reader).readContinuedLineSlice"] = []*ebpfcommon.ProbeDesc{{
			End: p.bpfObjects.ObiUprobeReadContinuedLineSliceReturns,
		}}
	}

	// Route extraction
	if !p.disabledRouteHarvesting {
		// Go mux router
		m["net/http.(*ServeMux).findHandler"] = []*ebpfcommon.ProbeDesc{{
			End: p.bpfObjects.ObiUprobeFindHandlerRet,
		}}
		m["net/http.(*serveMux121).findHandler"] = []*ebpfcommon.ProbeDesc{{
			End: p.bpfObjects.ObiUprobeFindHandlerRet,
		}}
		// Gorilla mux router
		m["github.com/gorilla/mux.routeRegexpGroup.setMatch"] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeMuxSetMatch,
		}}
		// Gin router
		m["github.com/gin-gonic/gin.(*node).getValue"] = []*ebpfcommon.ProbeDesc{{
			End: p.bpfObjects.ObiUprobeGinGetValueRet,
		}}
	}

	if p.supportsContextPropagation() {
		m["net/http.Header.writeSubset"] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeWriteSubset,        // http 1.x context propagation
			End:   p.bpfObjects.ObiUprobeWriteSubsetReturns, // inject only if no traceparent present
		}}
		p.addGoHpackTraceparentProbes(m)
		m["golang.org/x/net/http2.(*Framer).WriteHeaders"] = []*ebpfcommon.ProbeDesc{
			{ // http2 context propagation
				Start: p.bpfObjects.ObiUprobeGolangHttp2FramerWriteHeaders,
				End:   p.bpfObjects.ObiUprobeHttp2FramerWriteHeadersReturns,
			},
			{ // for grpc
				Start: p.bpfObjects.ObiUprobeGrpcFramerWriteHeaders,
				End:   p.bpfObjects.ObiUprobeGrpcFramerWriteHeadersReturns,
			},
		}
		m["net/http.(*http2Framer).WriteHeaders"] = []*ebpfcommon.ProbeDesc{{ // http2 context propagation
			Start: p.bpfObjects.ObiUprobeNetHttp2FramerWriteHeaders,
			End:   p.bpfObjects.ObiUprobeHttp2FramerWriteHeadersReturns,
		}}
	}

	return m
}

func (p *Tracer) addGoHpackTraceparentProbes(m map[string][]*ebpfcommon.ProbeDesc) {
	for _, symbol := range goHpackEncoderWriteFieldProbeSymbols {
		m[symbol] = []*ebpfcommon.ProbeDesc{{
			Required: false,
			Start:    p.bpfObjects.ObiUprobeHpackEncoderWriteField,
		}}
	}
}

type goProbeSelectionState struct {
	channelLinks        bool
	http2XNetServer     bool
	http2VendoredServer bool
	runtimeHeapSnapshot bool
	runtimeGCGoal       bool
}

func (p *Tracer) goProbeState() goProbeSelectionState {
	if p == nil {
		return goProbeSelectionState{}
	}

	p.processMu.Lock()
	defer p.processMu.Unlock()

	executable := p.currentBinaryExecutable
	if executable == (goExecutableKey{}) {
		return goProbeSelectionState{}
	}
	http2 := p.goHTTP2ServerOffsetsByExecutable[executable]
	return goProbeSelectionState{
		channelLinks:        p.goChannelOffsetsByExecutable[executable],
		http2XNetServer:     http2.xNet,
		http2VendoredServer: http2.vendored,
		runtimeHeapSnapshot: p.goRuntimeMetricMaskByExecutable[executable]&goRuntimeMetricHeapSnapshotMask != 0,
		runtimeGCGoal: p.goRuntimeGCGoalSourceByExecutable[executable] ==
			goRuntimeGCGoalSourcePaceScavengerArgument,
	}
}

func (p *Tracer) goChannelLinkProbesEnabled() bool {
	return p.goProbeState().channelLinks
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc {
	return nil
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg { return nil }

func (p *Tracer) SockOps() []ebpfcommon.SockOps { return nil }

func (p *Tracer) Iters() []*ebpfcommon.Iter { return nil }

func (p *Tracer) Tracing() []*ebpfcommon.Tracing { return nil }

func (p *Tracer) RecordInstrumentedLib(_ uint64, _ []io.Closer) {}

func (p *Tracer) AddInstrumentedLibRef(_ uint64) {}

func (p *Tracer) UnlinkInstrumentedLib(_ uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(_ uint64) bool {
	return false
}

func (p *Tracer) Run(ctx context.Context, ebpfEventContext *ebpfcommon.EBPFEventContext, eventsChan *msg.Queue[[]request.Span]) {
	p.startGoAutoSDKRun(ctx)
	defer func() {
		if err := p.goTracerResources().Close(); err != nil {
			p.logGoAutoSDKError("closing Go tracer resources failed", err)
		}
	}()
	parseContext := ebpfcommon.NewEBPFParseContext(
		p.cfg,
		eventsChan,
		p.pidsFilter,
		ebpfcommon.WithMisclassifiedEventHandler(ctx, ebpfEventContext.HandleMisclassifiedEvent),
	)
	defer parseContext.Close()
	ebpfcommon.SharedRingbuf(
		ebpfEventContext,
		p.cfg,
		p.bpfObjects.Events,
		func(record *ringbuf.Record) (request.Span, bool, error) {
			if handled, err := ebpfcommon.HandleRuntimeMetricsRecord(ctx, ebpfEventContext, record, p.pidsFilter, p.log); handled {
				return request.Span{}, true, err
			}
			s, ignore, err := ebpfcommon.ReadBPFTraceAsSpan(parseContext, p.cfg, record, p.pidsFilter)
			if !ignore && err == nil && !s.IsValid() {
				return s, true, nil
			}
			return s, ignore, err
		},
		p.pidsFilter.Filter,
		slog.With("component", "ringbuf.Tracer"),
		p.metrics,
	)(
		ctx,
		nil,
		eventsChan,
	)
}

func (p *Tracer) SetEventContext(_ *ebpfcommon.EBPFEventContext) {}

func (p *Tracer) Capabilities() ebpfcommon.TracerCapability { return 0 }

func (p *Tracer) Required() bool {
	return true
}
