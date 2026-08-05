// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/logenricher"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type Instrumentable struct {
	Type                 svc.InstrumentableType
	InstrumentationError error

	// in some runtimes, like python gunicorn, we need to allow
	// tracing both the parent pid and all of its children pid
	ChildPids []app.PID
	// ChildFileInfos preserves per-process service configuration while the
	// parent FileInfo remains the owner of shared executable instrumentation.
	ChildFileInfos map[app.PID]*exec.FileInfo

	FileInfo *exec.FileInfo
	Offsets  *goexec.Offsets
	Tracer   *ProcessTracer

	LogEnricherEnabled   bool
	ExecutableGeneration uint64
}

func (ie *Instrumentable) FileInfoForPID(pid app.PID) *exec.FileInfo {
	if ie == nil {
		return nil
	}
	if ie.FileInfo != nil && ie.FileInfo.Pid() == pid {
		return ie.FileInfo
	}
	if fi := ie.ChildFileInfos[pid]; fi != nil {
		return fi
	}
	return ie.FileInfo
}

func (ie *Instrumentable) CopyToServiceAttributes() {
	if ie == nil || ie.FileInfo == nil {
		return
	}
	ie.FileInfo.ApplyServiceDefaults(ie.Type)
	for _, fi := range ie.ChildFileInfos {
		if fi != nil && fi != ie.FileInfo {
			fi.ApplyServiceDefaults(ie.Type)
		}
	}
}

type PIDsAccounter interface {
	// AllowPID notifies the tracer to accept traces from the given PID, sharing
	// the FileInfo so mutable service state (flags, harvested routes, k8s
	// metadata) goes through its synchronized API.
	AllowPID(app.PID, uint32, *exec.FileInfo)
	// BlockPID notifies the tracer to stop accepting traces from the process
	// with the provided PID. After receiving them via ringbuffer, it should
	// discard them.
	BlockPID(app.PID, uint32)
}

// IncarnationPIDsAccounter requires the exact FileInfo admitted for a process.
type IncarnationPIDsAccounter interface {
	BlockPIDForProcess(app.PID, uint32, *exec.FileInfo)
}

// PIDAdmissionController reports whether a process can be safely admitted.
// Tracers that do not implement it retain the legacy best-effort AllowPID
// behavior.
type PIDAdmissionController interface {
	AllowPIDForProcess(app.PID, uint32, *exec.FileInfo) bool
}

// PIDAdmissionRetryController keeps rejected exact-incarnation admissions
// queued until they are either admitted or explicitly canceled. The marker
// remains authoritative even after any prerequisite cleanup has settled.
type PIDAdmissionRetryController interface {
	PIDAdmissionRetryPending(app.PID, uint32, *exec.FileInfo) bool
	CancelPIDAdmissionRetry(app.PID, uint32, *exec.FileInfo)
}

// ExecutableUnlinkReadiness lets a tracer retain executable links while
// process-specific cleanup still depends on their return probes.
type ExecutableUnlinkReadiness interface {
	ExecutableUnlinkReady(*exec.FileInfo) bool
}

// ResourceTeardownReadiness lets a tracer retain process and shared resources
// when its Run shutdown could not safely detach them.
type ResourceTeardownReadiness interface {
	ResourceTeardownReady() bool
}

// ResourceTeardownWaiter lets a tracer keep retrying cleanup after Run exits.
// ProcessTracer waits for that owner before tearing down executable or shared
// resources.
type ResourceTeardownWaiter interface {
	WaitForResourceTeardown()
}

func BlockPIDForProcess(
	accounter PIDsAccounter,
	pid app.PID,
	ns uint32,
	fileInfo *exec.FileInfo,
) {
	if incarnationAccounter, ok := accounter.(IncarnationPIDsAccounter); ok {
		incarnationAccounter.BlockPIDForProcess(pid, ns, fileInfo)
		return
	}
	accounter.BlockPID(pid, ns)
}

type CommonTracer interface {
	// LoadSpecs returns one SpecBundle per BPF collection. Each bundle contains
	// the collection spec, the object pointer to populate, and the constants to rewrite.
	LoadSpecs() ([]*ebpfcommon.SpecBundle, error)
	// AddCloser adds io.Closer instances that need to be invoked when the
	// Run function ends.
	AddCloser(c ...io.Closer)
	// SetupTailCalls sets up any tail call jump tables after all specs are loaded.
	SetupTailCalls()
}

type KprobesTracer interface {
	CommonTracer
	// KProbes returns a map with the name of the kernel probes that need to be
	// tapped into. Start matches kprobe, End matches kretprobe
	KProbes() map[string]ebpfcommon.ProbeDesc
	Tracepoints() map[string]ebpfcommon.ProbeDesc
}

// Tracer is an individual eBPF program (e.g. the net/http or the grpc tracers)
type Tracer interface {
	PIDsAccounter
	KprobesTracer
	// GoProbes returns a slice with the name of Go functions that need to be inspected
	// in the executable, as well as the eBPF programs that optionally need to be
	// inserted as the Go function start and end probes
	GoProbes() map[string][]*ebpfcommon.ProbeDesc
	// UProbes returns a map with the module name mapping to the uprobes that need to be
	// tapped into. Start matches uprobe, End matches uretprobe.
	// The module name key may carry a version constraint in square brackets, which causes
	// the entry to be selected only when the library's version satisfies the constraint.
	// See matchVersionedUprobeLibrary for how selection is performed.
	UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc
	// USDTProbes returns a map with the module name mapping to USDT probes.
	USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc
	// SocketFilters  returns a list of programs that need to be loaded as a
	// generic eBPF socket filter
	SocketFilters() []*ebpf.Program
	// SockMsgs returns a list of programs that need to be loaded as a
	// BPF_PROG_TYPE_SK_MSG eBPF programs
	SockMsgs() []ebpfcommon.SockMsg
	// SockOps returns a list of programs that need to be loaded as a
	// BPF_PROG_TYPE_SOCK_OPS eBPF programs
	SockOps() []ebpfcommon.SockOps
	// Iters returns a list of programs that need to be loaded as a
	// BPF_PROG_TYPE_TRACING with BPF_TRACE_ITER attach type
	Iters() []*ebpfcommon.Iter
	// Tracing() returns a list of programs that need to be loaded as a
	// BPF_PROG_TYPE_TRACING
	Tracing() []*ebpfcommon.Tracing
	// Probes can potentially instrument a shared library among multiple executables
	// These two functions alow programs to remember this and avoid duplicated instrumentations
	// The argument is the OS file id
	// Closers are the associated closable resources to this lib, that may be
	// closed when UnlinkInstrumentedLib() is called
	RecordInstrumentedLib(uint64, []io.Closer)
	AddInstrumentedLibRef(uint64)
	AlreadyInstrumentedLib(uint64) bool
	UnlinkInstrumentedLib(uint64)
	RegisterOffsets(*exec.FileInfo, *goexec.Offsets)
	ProcessBinary(*exec.FileInfo)
	SetEventContext(*ebpfcommon.EBPFEventContext)
	Required() bool
	Capabilities() ebpfcommon.TracerCapability
	// Run will do the action of listening for eBPF traces and forward them
	// periodically to the output channel.
	Run(context.Context, *ebpfcommon.EBPFEventContext, *msg.Queue[[]request.Span])
}

// Subset of the above interface, which supports loading eBPF programs which
// are not tied to service monitoring
type UtilityTracer interface {
	KprobesTracer
	Run(context.Context)
}

type ProcessTracerType int

const (
	Go = ProcessTracerType(iota)
	Generic
)

// ExecutableKey identifies an executable across filesystems.
type ExecutableKey struct {
	Dev uint64
	Ino uint64
}

// ProcessTracer instruments an executable with eBPF and provides the eBPF readers
// that will forward the traces to later stages in the pipeline
// TODO: We need to pass the ELFInfo from this ProcessTracker to inside a Tracer
// so that the GPU kernel event listener can find symbols names from addresses
// in the ELF file.
type ProcessTracer struct {
	log                       *slog.Logger
	metrics                   imetrics.Reporter
	shutdownTimeout           time.Duration
	bpffsPath                 string
	instrumentablesMu         sync.Mutex
	nextExecutableGeneration  uint64
	instrumentableGenerations map[ExecutableKey]uint64

	Type            ProcessTracerType
	Instrumentables map[ExecutableKey]*instrumenter
	Programs        []Tracer
}

// ExecutableInstanceUpdate owns the additions made while refreshing an
// existing executable's process-specific probes. Callers must finalize every
// successful update exactly once so the tracer can either publish or roll back
// those additions.
type ExecutableInstanceUpdate struct {
	once     sync.Once
	finalize func(commit bool)
}

func (u *ExecutableInstanceUpdate) Commit() {
	if u == nil {
		return
	}
	u.once.Do(func() {
		if u.finalize != nil {
			u.finalize(true)
		}
	})
}

func (u *ExecutableInstanceUpdate) Rollback() {
	if u == nil {
		return
	}
	u.once.Do(func() {
		if u.finalize != nil {
			u.finalize(false)
		}
	})
}

func (pt *ProcessTracer) AllowPID(pid app.PID, ns uint32, fi *exec.FileInfo) bool {
	logEnricherEnabled := fi.LogEnricherEnabled()
	for i := range pt.Programs {
		if _, ok := pt.Programs[i].(*logenricher.Tracer); ok && !logEnricherEnabled {
			continue
		}
		if admissionController, ok := pt.Programs[i].(PIDAdmissionController); ok {
			if !admissionController.AllowPIDForProcess(pid, ns, fi) {
				return false
			}
			continue
		}
		pt.Programs[i].AllowPID(pid, ns, fi)
	}
	return true
}

func (pt *ProcessTracer) PIDAdmissionRetryPending(
	pid app.PID,
	ns uint32,
	fi *exec.FileInfo,
) bool {
	for _, program := range pt.Programs {
		if readiness, ok := program.(PIDAdmissionRetryController); ok &&
			readiness.PIDAdmissionRetryPending(pid, ns, fi) {
			return true
		}
	}
	return false
}

func (pt *ProcessTracer) CancelPIDAdmissionRetry(
	pid app.PID,
	ns uint32,
	fi *exec.FileInfo,
) {
	for _, program := range pt.Programs {
		if readiness, ok := program.(PIDAdmissionRetryController); ok {
			readiness.CancelPIDAdmissionRetry(pid, ns, fi)
		}
	}
}

func (pt *ProcessTracer) BlockPID(pid app.PID, ns uint32) {
	pt.BlockPIDForProcess(pid, ns, nil)
}

func (pt *ProcessTracer) BlockPIDForProcess(
	pid app.PID,
	ns uint32,
	fileInfo *exec.FileInfo,
) {
	for i := range pt.Programs {
		BlockPIDForProcess(pt.Programs[i], pid, ns, fileInfo)
	}
}
