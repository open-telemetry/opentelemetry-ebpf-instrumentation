// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
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
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	ebpfsampling "go.opentelemetry.io/obi/pkg/internal/ebpf/sampling"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/netns"
	"go.opentelemetry.io/obi/pkg/internal/netolly/ifaces"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 Bpf ../../../../bpf/generictracer/generictracer.c -- -I../../../../bpf

type Tracer struct {
	processMu             sync.Mutex
	processStartTime      map[genericProcessKey]uint64
	processHostStartTime  map[genericProcessKey]uint64
	processHostAlias      map[genericProcessKey]genericProcessKey
	processHostOwner      map[genericProcessKey]genericProcessKey
	processFileInfo       map[genericProcessKey]*exec.FileInfo
	samplerCleanupRetries map[samplerCleanupRetryKey]samplerCleanupRetry
	runResourcesShutdown  bool
	runResourcesClosing   bool
	runResourcesClosed    bool
	bpfObjectsClaimed     bool
	runResourcesCloseDone chan struct{}
	runResourcesDone      chan struct{}
	runResourcesDoneSent  bool
	cleanupOwnerStarted   bool
	resolveHostPID        func(app.PID) (uint32, error)

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
	samplerManager   samplerLifecycleManager
}

type genericProcessKey struct {
	pid app.PID
	ns  uint32
}

type samplerCleanupRetryKey struct {
	process   genericProcessKey
	startTime uint64
	ino       uint64
	fileInfo  *exec.FileInfo
}

type samplerCleanupRetry struct {
	ino                   uint64
	admissionPending      bool
	pidFilterBlockPending bool
	cleanupComplete       bool
}

type http2ConnectionMapWriter interface {
	Update(key, value any, flags ebpf.MapUpdateFlags) error
}

type http2ConnectionTrackerReader interface {
	Lookup(key, valueOut any) error
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
	BlockPIDForProcess(app.PID, uint32, uint64) bool
}

func tlog() *slog.Logger {
	return slog.With("component", "generic.Tracer")
}

func New(pidFilter ebpfcommon.ServiceFilter, cfg *obi.Config, metrics imetrics.Reporter) *Tracer {
	return &Tracer{
		log:                   tlog(),
		cfg:                   cfg,
		metrics:               metrics,
		processStartTime:      map[genericProcessKey]uint64{},
		processHostStartTime:  map[genericProcessKey]uint64{},
		processHostAlias:      map[genericProcessKey]genericProcessKey{},
		processHostOwner:      map[genericProcessKey]genericProcessKey{},
		processFileInfo:       map[genericProcessKey]*exec.FileInfo{},
		samplerCleanupRetries: map[samplerCleanupRetryKey]samplerCleanupRetry{},
		resolveHostPID:        genericTracerHostPID,
		runResourcesDone:      make(chan struct{}),
		pidsFilter:            pidFilter,
		qdiscs:                map[ifaces.Interface]*netlink.GenericQdisc{},
		egressFilters:         map[ifaces.Interface]*netlink.BpfFilter{},
		ingressFilters:        map[ifaces.Interface]*netlink.BpfFilter{},
		instrumentedLibs:      make(ebpfcommon.InstrumentedLibsT),
		libsMux:               sync.Mutex{},
		iters:                 []*ebpfcommon.Iter{},
	}
}

// Keep in sync with the BPF side, which asserts the relation between both
// constants at compile time (bpf/pid/pid.h).
const (
	// mirrors k_max_concurrent_pids (bpf/pid/maps/map_sizing.h): estimate of
	// 1000 concurrent processes (including children) * 3 namespaces per pid
	maxConcurrentPids = 3001
	// mirrors k_prime_hash (bpf/pid/pid.h): closest prime below
	// maxConcurrentPids * 64; modulo by a prime distributes the hash evenly
	// across the segment bit array
	primeHash = 192053
	// Mirrors k_process_clock_tick_ns in bpf/common/process_incarnation.h.
	processClockTickNanoseconds  = uint64(10_000_000)
	shutdownCleanupRetryInterval = 100 * time.Millisecond
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

// validateValidPidsMap ensures the loaded map matches the index space written
// by rebuildValidPids: a smaller map makes pid_matches() lookups miss and fail
// open, while a larger one leaves segments unset, silently filtering out
// matching PIDs.
func (p *Tracer) validateValidPidsMap() error {
	if got := p.bpfObjects.ValidPids.MaxEntries(); got != maxConcurrentPids {
		return fmt.Errorf(
			"valid_pids BPF map holds %d entries, expected %d: BPF and userspace PID filter constants have diverged",
			got, maxConcurrentPids)
	}

	return nil
}

func (p *Tracer) rebuildValidPids() error {
	if p.bpfObjects.ValidPids == nil {
		return nil
	}

	v := p.buildPidFilter()

	p.log.Debug("number of segments in pid filter cache", "len", len(v))

	for i, segment := range v {
		if err := p.bpfObjects.ValidPids.Put(uint32(i), segment); err != nil {
			return fmt.Errorf("setting up pid segment %d in BPF space: %w", i, err)
		}
	}

	return nil
}

func (p *Tracer) AllowPID(pid app.PID, ns uint32, fi *exec.FileInfo) {
	p.AllowPIDForProcess(pid, ns, fi)
}

func (p *Tracer) AllowPIDForProcess(pid app.PID, ns uint32, fi *exec.FileInfo) bool {
	p.processMu.Lock()
	defer p.unlockProcessAndCloseRunResourcesIfReady()

	startTime := fi.StartTime()
	key := genericProcessKey{pid: pid, ns: ns}
	if p.samplerManager != nil {
		attrs := fi.ServiceAttrs()
		samplerReady := p.samplerManager.AllowPIDForProcess(
			pid, ns, startTime, attrs.SamplerConfig, false,
		)
		if !samplerReady &&
			!p.samplerManager.FallbackSafeForProcessIncarnation(pid, ns, startTime) {
			if !p.samplerCleanupSafe(pid, ns, startTime) {
				pidFilterBlocked := p.blockPIDFilter(pid, ns)
				p.deleteProcessStartTime(key, p.processStartTime[key])
				delete(p.processFileInfo, key)
				p.queueSamplerCleanupRetry(
					key, startTime, fi.Ino(), fi, true, !pidFilterBlocked,
				)
				return false
			}
		}
	}
	p.deleteSamplerCleanupRetry(samplerCleanupRetryKey{
		process:   key,
		startTime: startTime,
		ino:       fi.Ino(),
		fileInfo:  fi,
	})
	p.admitPID(pid, ns, fi)
	return true
}

func (p *Tracer) admitPID(pid app.PID, ns uint32, fi *exec.FileInfo) {
	key := genericProcessKey{pid: pid, ns: ns}
	startTime := fi.StartTime()
	p.pidsFilter.AllowPID(pid, ns, fi, ebpfcommon.PIDTypeKProbes)
	if p.processStartTime == nil {
		p.processStartTime = map[genericProcessKey]uint64{}
	}
	if p.processHostAlias == nil {
		p.processHostAlias = map[genericProcessKey]genericProcessKey{}
	}
	if p.processHostStartTime == nil {
		p.processHostStartTime = map[genericProcessKey]uint64{}
	}
	if p.processHostOwner == nil {
		p.processHostOwner = map[genericProcessKey]genericProcessKey{}
	}
	if p.processFileInfo == nil {
		p.processFileInfo = map[genericProcessKey]*exec.FileInfo{}
	}
	p.recordProcessStartTime(key, startTime)
	p.processFileInfo[key] = fi

	if err := p.rebuildValidPids(); err != nil {
		p.log.Error("rebuilding the BPF PID filter", "error", err)
		return
	}

	// Keep the cache consistent with the updated filter.
	if p.bpfObjects.PidCache != nil {
		pidU32 := uint32(pid)
		_ = p.bpfObjects.PidCache.Put(pidU32, pidU32)
	}
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
	defer p.unlockProcessAndCloseRunResourcesIfReady()

	key := genericProcessKey{pid: pid, ns: ns}
	admittedFileInfo, admitted := p.processFileInfo[key]
	if fileInfo != nil && (!admitted || admittedFileInfo != fileInfo) {
		return
	}
	admittedStartTime, admitted := p.processStartTime[key]
	startTime := uint64(0)
	ino := uint64(0)
	var cleanupFileInfo *exec.FileInfo
	if admitted {
		startTime = admittedStartTime
		ino = fileInfoInode(admittedFileInfo)
		cleanupFileInfo = admittedFileInfo
	}
	if fileInfo != nil {
		startTime = fileInfo.StartTime()
		ino = fileInfo.Ino()
		cleanupFileInfo = fileInfo
	}
	pidFilterBlocked := p.blockPIDFilter(pid, ns)
	p.deleteProcessStartTime(key, admittedStartTime)
	delete(p.processFileInfo, key)
	if !pidFilterBlocked {
		p.queueSamplerCleanupRetry(
			key, startTime, ino, cleanupFileInfo, false, true,
		)
		return
	}
	if !p.samplerCleanupSafe(pid, ns, startTime) {
		p.queueSamplerCleanupRetry(
			key, startTime, ino, cleanupFileInfo, false, false,
		)
		return
	}
	p.deleteSamplerCleanupRetry(samplerCleanupRetryKey{
		process:   key,
		startTime: startTime,
		ino:       ino,
		fileInfo:  cleanupFileInfo,
	})
}

func genericTracerHostPID(pid app.PID) (uint32, error) {
	pids, err := procs.FindNamespacedPids(pid)
	if err != nil {
		return 0, fmt.Errorf("reading namespaced PIDs: %w", err)
	}
	if len(pids) == 0 {
		return uint32(pid), nil
	}
	return uint32(pids[0]), nil
}

func (p *Tracer) rememberProcessStartTime(
	key genericProcessKey,
	hostPID app.PID,
	startTime uint64,
) {
	if previousStartTime, exists := p.processStartTime[key]; exists {
		p.deleteProcessStartTime(key, previousStartTime)
	}
	hostKey := genericProcessKey{pid: hostPID, ns: key.ns}
	p.processStartTime[key] = startTime
	if previousOwner, exists := p.processHostOwner[hostKey]; exists && previousOwner != key {
		delete(p.processHostAlias, previousOwner)
	}
	p.processHostStartTime[hostKey] = startTime
	p.processHostAlias[key] = hostKey
	p.processHostOwner[hostKey] = key
}

func (p *Tracer) recordProcessStartTime(key genericProcessKey, startTime uint64) {
	if previousStartTime, exists := p.processStartTime[key]; exists {
		p.deleteProcessStartTime(key, previousStartTime)
	}
	p.processStartTime[key] = startTime
	resolver := p.resolveHostPID
	if resolver == nil {
		resolver = genericTracerHostPID
	}
	hostPID, err := resolver(key.pid)
	if err != nil || hostPID == 0 {
		// Normal tracing admission can continue, but delayed userspace
		// recovery has no proven host-TGID identity and stays disabled.
		return
	}
	p.rememberProcessStartTime(key, app.PID(hostPID), startTime)
}

func (p *Tracer) deleteProcessStartTime(key genericProcessKey, startTime uint64) {
	delete(p.processStartTime, key)
	hostKey, exists := p.processHostAlias[key]
	delete(p.processHostAlias, key)
	if exists && p.processHostOwner[hostKey] == key &&
		p.processHostStartTime[hostKey] == startTime {
		delete(p.processHostStartTime, hostKey)
		delete(p.processHostOwner, hostKey)
	}
}

func (p *Tracer) samplerCleanupSafe(pid app.PID, ns uint32, startTime uint64) bool {
	return p.samplerManager == nil ||
		(p.samplerManager.BlockPIDForProcess(pid, ns, startTime) &&
			p.samplerManager.FallbackSafeForProcessIncarnation(pid, ns, startTime))
}

func (p *Tracer) queueSamplerCleanupRetry(
	process genericProcessKey,
	startTime uint64,
	ino uint64,
	fileInfo *exec.FileInfo,
	admissionPending bool,
	pidFilterBlockPending bool,
) {
	if p.samplerCleanupRetries == nil {
		p.samplerCleanupRetries = map[samplerCleanupRetryKey]samplerCleanupRetry{}
	}
	retryKey := samplerCleanupRetryKey{
		process: process, startTime: startTime, ino: ino, fileInfo: fileInfo,
	}
	retry := p.samplerCleanupRetries[retryKey]
	if ino != 0 {
		retry.ino = ino
	}
	retry.admissionPending = retry.admissionPending || admissionPending
	retry.pidFilterBlockPending = retry.pidFilterBlockPending || pidFilterBlockPending
	retry.cleanupComplete = false
	p.samplerCleanupRetries[retryKey] = retry
}

func fileInfoInode(fileInfo *exec.FileInfo) uint64 {
	if fileInfo == nil {
		return 0
	}
	return fileInfo.Ino()
}

func (p *Tracer) deleteSamplerCleanupRetry(key samplerCleanupRetryKey) {
	delete(p.samplerCleanupRetries, key)
}

func (p *Tracer) retrySamplerCleanups() {
	p.processMu.Lock()
	defer p.unlockProcessAndCloseRunResourcesIfReady()

	for key, retry := range p.samplerCleanupRetries {
		if retry.cleanupComplete {
			continue
		}
		if retry.pidFilterBlockPending {
			if !p.pidFilterBlockRetrySuperseded(key) &&
				!p.syncBlockedPIDFilter(key.process.pid) {
				continue
			}
			retry.pidFilterBlockPending = false
			p.samplerCleanupRetries[key] = retry
		}
		if !p.samplerCleanupSafe(key.process.pid, key.process.ns, key.startTime) {
			continue
		}
		if !retry.admissionPending {
			p.deleteSamplerCleanupRetry(key)
			continue
		}
		retry.cleanupComplete = true
		p.samplerCleanupRetries[key] = retry
	}
}

func (p *Tracer) pidFilterBlockRetrySuperseded(key samplerCleanupRetryKey) bool {
	startTime, admitted := p.processStartTime[key.process]
	if !admitted {
		return false
	}
	return startTime != key.startTime || p.processFileInfo[key.process] != key.fileInfo
}

func (p *Tracer) PIDAdmissionRetryPending(
	pid app.PID,
	ns uint32,
	fileInfo *exec.FileInfo,
) bool {
	if fileInfo == nil || fileInfo.Pid() != pid || fileInfo.Ns() != ns {
		return false
	}
	p.processMu.Lock()
	defer p.processMu.Unlock()
	retry, pending := p.samplerCleanupRetries[samplerCleanupRetryKey{
		process:   genericProcessKey{pid: pid, ns: ns},
		startTime: fileInfo.StartTime(),
		ino:       fileInfo.Ino(),
		fileInfo:  fileInfo,
	}]
	return pending && retry.admissionPending
}

func (p *Tracer) CancelPIDAdmissionRetry(
	pid app.PID,
	ns uint32,
	fileInfo *exec.FileInfo,
) {
	if fileInfo == nil || fileInfo.Pid() != pid || fileInfo.Ns() != ns {
		return
	}
	p.processMu.Lock()
	defer p.unlockProcessAndCloseRunResourcesIfReady()
	key := samplerCleanupRetryKey{
		process:   genericProcessKey{pid: pid, ns: ns},
		startTime: fileInfo.StartTime(),
		ino:       fileInfo.Ino(),
		fileInfo:  fileInfo,
	}
	retry, pending := p.samplerCleanupRetries[key]
	if !pending {
		return
	}
	if retry.cleanupComplete {
		p.deleteSamplerCleanupRetry(key)
		return
	}
	retry.admissionPending = false
	p.samplerCleanupRetries[key] = retry
}

func (p *Tracer) ExecutableUnlinkReady(fileInfo *exec.FileInfo) bool {
	if fileInfo == nil {
		return true
	}
	p.processMu.Lock()
	defer p.processMu.Unlock()
	for key, retry := range p.samplerCleanupRetries {
		if key.fileInfo != nil &&
			key.fileInfo.Dev() == fileInfo.Dev() &&
			retry.ino == fileInfo.Ino() {
			return false
		}
	}
	return true
}

func (p *Tracer) ResourceTeardownReady() bool {
	p.processMu.Lock()
	defer p.processMu.Unlock()
	return len(p.samplerCleanupRetries) == 0 &&
		(!p.runResourcesShutdown || p.runResourcesClosed)
}

func (p *Tracer) WaitForResourceTeardown() {
	p.processMu.Lock()
	if !p.runResourcesShutdown || p.runResourcesClosed {
		p.processMu.Unlock()
		return
	}
	done := p.ensureRunResourcesDoneLocked()
	p.processMu.Unlock()
	<-done
}

func (p *Tracer) unlockProcessAndCloseRunResourcesIfReady() {
	p.processMu.Unlock()
	p.closeRunResourcesIfReady()
}

func (p *Tracer) shutdownRunResources() {
	// The attacher cancels pending admissions before the tracer context. Make
	// one final cleanup attempt while the maps and return probes are available.
	p.retrySamplerCleanups()

	p.processMu.Lock()
	p.runResourcesShutdown = true
	p.ensureRunResourcesDoneLocked()
	startCleanupOwner := len(p.samplerCleanupRetries) != 0 &&
		!p.cleanupOwnerStarted
	if startCleanupOwner {
		p.cleanupOwnerStarted = true
	}
	p.processMu.Unlock()
	if startCleanupOwner {
		go p.runPostCancellationCleanup()
	}
	p.closeRunResourcesIfReady()
}

func (p *Tracer) runPostCancellationCleanup() {
	ticker := time.NewTicker(shutdownCleanupRetryInterval)
	defer ticker.Stop()

	p.processMu.Lock()
	done := p.ensureRunResourcesDoneLocked()
	p.processMu.Unlock()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			p.retrySamplerCleanups()
		}
	}
}

func (p *Tracer) closeRunResourcesIfReady() {
	for {
		p.processMu.Lock()
		if !p.runResourcesShutdown || len(p.samplerCleanupRetries) != 0 {
			p.processMu.Unlock()
			return
		}
		if p.runResourcesClosing {
			closeDone := p.runResourcesCloseDone
			p.processMu.Unlock()
			<-closeDone
			continue
		}
		if p.runResourcesClosed {
			p.signalRunResourcesDoneLocked()
			p.processMu.Unlock()
			return
		}

		closers := append([]io.Closer(nil), p.closers...)
		p.closers = nil
		if !p.bpfObjectsClaimed {
			closers = append(closers, &p.bpfObjects)
			p.bpfObjectsClaimed = true
		}
		if len(closers) == 0 {
			p.runResourcesClosed = true
			p.signalRunResourcesDoneLocked()
			p.processMu.Unlock()
			return
		}
		p.runResourcesClosing = true
		p.runResourcesClosed = false
		p.runResourcesCloseDone = make(chan struct{})
		closeDone := p.runResourcesCloseDone
		p.processMu.Unlock()

		p.closeRunResources(closers)

		p.processMu.Lock()
		p.runResourcesClosing = false
		p.runResourcesClosed = len(p.closers) == 0 && p.bpfObjectsClaimed
		closeMore := !p.runResourcesClosed
		close(closeDone)
		p.runResourcesCloseDone = nil
		if p.runResourcesClosed {
			p.signalRunResourcesDoneLocked()
		}
		p.processMu.Unlock()
		if !closeMore {
			return
		}
	}
}

func (p *Tracer) closeRunResources(closers []io.Closer) {
	var wg sync.WaitGroup
	for _, closer := range closers {
		if closer == nil {
			continue
		}
		wg.Add(1)
		go func(c io.Closer) {
			defer wg.Done()
			if err := c.Close(); err != nil && p.log != nil {
				p.log.Debug("closing generic tracer resource failed", "error", err)
			}
		}(closer)
	}
	wg.Wait()
}

func (p *Tracer) ensureRunResourcesDoneLocked() chan struct{} {
	if p.runResourcesDone == nil {
		p.runResourcesDone = make(chan struct{})
	}
	return p.runResourcesDone
}

func (p *Tracer) signalRunResourcesDoneLocked() {
	done := p.ensureRunResourcesDoneLocked()
	if !p.runResourcesDoneSent {
		close(done)
		p.runResourcesDoneSent = true
	}
}

func (p *Tracer) blockPIDFilter(pid app.PID, ns uint32) bool {
	p.pidsFilter.BlockPID(pid, ns)
	return p.syncBlockedPIDFilter(pid)
}

func (p *Tracer) syncBlockedPIDFilter(pid app.PID) bool {
	rebuildErr := p.rebuildValidPids()
	var cacheErr error
	if p.bpfObjects.PidCache != nil {
		pidU32 := uint32(pid)
		cacheErr = p.bpfObjects.PidCache.Delete(pidU32)
		if errors.Is(cacheErr, ebpf.ErrKeyNotExist) {
			cacheErr = nil
		}
	}
	if err := errors.Join(rebuildErr, cacheErr); err != nil {
		p.log.Error("blocking PID in the BPF filter", "error", err)
		return false
	}

	return true
}

func (p *Tracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	if p.traceparentParsingEnabled() {
		p.log.Info("Enabling trace information parsing", "bpf_loop_enabled", ebpfcommon.SupportsEBPFLoops(p.log, p.cfg.EBPF.OverrideBPFLoopEnabled))
	}

	spec, err := LoadBpf()
	if err != nil {
		return nil, fmt.Errorf("can't load bpf collection from reader: %w", err)
	}

	ebpfcommon.FixupSpec(spec, p.cfg.EBPF.OverrideBPFLoopEnabled)

	return []*ebpfcommon.SpecBundle{{Spec: spec, Objects: &p.bpfObjects, Constants: p.constants()}}, nil
}

func (p *Tracer) traceparentParsingEnabled() bool {
	if p.cfg.EBPF.TrackRequestHeaders || p.cfg.EBPF.ContextPropagation.IsEnabled() {
		return true
	}

	if samplerNeedsTraceparent(&p.cfg.Traces.SamplerConfig) {
		return true
	}
	for i := range p.cfg.Discovery.Instrument {
		if samplerNeedsTraceparent(p.cfg.Discovery.Instrument[i].SamplerConfig) {
			return true
		}
	}
	for i := range p.cfg.Discovery.Services {
		if samplerNeedsTraceparent(p.cfg.Discovery.Services[i].SamplerConfig) {
			return true
		}
	}

	return false
}

func samplerNeedsTraceparent(config *services.SamplerConfig) bool {
	if config == nil {
		return false
	}
	canonical, err := config.Canonical()
	// Validation reports malformed sampler configurations before BPF loading.
	// Keep extraction enabled if validation was bypassed so trace context is
	// not silently discarded while the sampler falls back.
	return err != nil || canonical.Type == services.SamplerTypeParentBased ||
		canonical.Type == services.SamplerTypeTraceIDRatio
}

func (p *Tracer) SetupTailCalls() {
	samplerConfig, err := p.cfg.Traces.SamplerConfig.Canonical()
	if err != nil {
		p.log.Error("invalid sampler configuration", "error", err)
	}
	p.samplerManager = ebpfsampling.NewManager(
		p.log,
		p.bpfObjects.GlobalSamplerConfig,
		p.bpfObjects.SamplerOverrides,
		p.bpfObjects.SamplerReadyPids,
		nil,
		samplerConfig,
	)
	p.samplerManager.InstallGlobal()

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
		p.bpfObjects.ObiProtocolHttp2,                           // 7
		p.bpfObjects.ObiProtocolHttp2GrpcFrames,                 // 8
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrame,       // 9
		p.bpfObjects.ObiProtocolHttp2GrpcHandleEndFrame,         // 10
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrameServer, // 11
		nil, // 12 (reserved)
		// Large buffer multi-batch emission
		p.bpfObjects.ObiLargeBufEmitContinue,                          // 13  k_tail_large_buf_emit_continue
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrameServerCommit, // 14
		// Go SDK-only slots in the gotracer jump table
		nil, // 15
		nil, // 16
		nil, // 17
		nil, // 18
		// HTTP/2 server traceparent validation
		p.bpfObjects.ObiProtocolHttp2GrpcValidateServerTraceparent, // 19
		// Ongoing HTTP/1 request continuation
		p.bpfObjects.ObiHandleHttpContinuation, // 20
		// HTTP/2 client terminal resolution
		p.bpfObjects.ObiProtocolHttp2GrpcFinishClient, // 21
		// HTTP/2 server HPACK parser continuation
		p.bpfObjects.ObiProtocolHttp2GrpcParseServerHeaders, // 22
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

	traceparentParsingEnabled := p.traceparentParsingEnabled()
	if traceparentParsingEnabled {
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
	m["g_bpf_traceparent_enabled"] = traceparentParsingEnabled
	m["jvm_sampling_interval_ns"] = uint64(0)
	if p.jvmRuntimeMetricsEnabled() {
		m["jvm_sampling_interval_ns"] = uint64(p.cfg.JVMRuntimeMetrics.SamplingInterval.Nanoseconds())
	}

	return m
}

func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets) {}

func (p *Tracer) ProcessBinary(_ *exec.FileInfo) {}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.processMu.Lock()
	p.closers = append(p.closers, c...)
	if len(c) > 0 {
		p.runResourcesClosed = false
	}
	p.processMu.Unlock()
	p.closeRunResourcesIfReady()
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
	return m
}

func (p *Tracer) USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc {
	if !p.jvmRuntimeMetricsEnabled() {
		return nil
	}
	return map[string][]*ebpfcommon.USDTProbeDesc{
		"libjvm.so": {
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
		},
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
					if errors.Is(err, os.ErrNotExist) {
						p.log.Debug("process gone before iterating its netns", "pid", pid)
						break
					}
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
	runCtx, cancelRun := context.WithCancel(ctx)
	unsetMisclassifiedHandler := ebpfEventContext.SetMisclassifiedEventHandler(
		p.handleMisclassifiedEvent,
	)

	p.initializePIDFilter()

	timeoutTicker := time.NewTicker(2 * time.Second)
	parseContext := ebpfcommon.NewEBPFParseContext(
		&p.cfg.EBPF,
		eventsChan,
		p.pidsFilter,
		ebpfcommon.WithMisclassifiedEventHandler(runCtx, ebpfEventContext.HandleMisclassifiedEvent),
	)
	var background sync.WaitGroup
	background.Add(1)
	go func() {
		defer background.Done()
		p.lookForTimeouts(runCtx, parseContext, timeoutTicker, eventsChan)
	}()

	p.runItersForPids()

	p.log.Info("Launching p.Tracer")

	cfg := &p.cfg.EBPF
	if p.jvmRuntimeMetricsEnabled() {
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
			return p.processSharedRingbufRecord(runCtx, parseContext, cfg, record)
		},
		p.pidsFilter.Filter,
		p.log,
		p.metrics,
	)(runCtx, nil, eventsChan)
	<-runCtx.Done()

	cancelRun()
	timeoutTicker.Stop()
	background.Wait()
	parseContext.Close()
	unsetMisclassifiedHandler()
	p.shutdownRunResources()
}

func (p *Tracer) initializePIDFilter() {
	p.processMu.Lock()
	defer p.processMu.Unlock()

	// At this point we now have loaded the bpf objects, which means we should insert any
	// pids that are allowed into the bpf map
	if p.bpfObjects.ValidPids != nil {
		if err := p.validateValidPidsMap(); err != nil {
			p.log.Error("BPF PID filter map sizing is invalid, discovery filtering may not be enforced", "error", err)
		}
		if err := p.rebuildValidPids(); err != nil {
			p.log.Error("setting up the BPF PID filter, discovery filtering may not be enforced", "error", err)
		}
	} else {
		p.log.Error("BPF Pids map is not created yet, this is a bug.")
	}
}

func (p *Tracer) jvmRuntimeMetricsEnabled() bool {
	return p.cfg != nil && p.cfg.JoinMetricsConfig().Features.AppRuntime()
}

func (p *Tracer) processSharedRingbufRecord(
	ctx context.Context,
	parseContext *ebpfcommon.EBPFParseContext,
	cfg *config.EBPFTracer,
	record *ringbuf.Record,
) (request.Span, bool, error) {
	if handled, err := p.eventCtx.HandleInternalEvent(record); handled {
		return request.Span{}, true, err
	}

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
		p.log.Debug(
			"received JVM memory pool event",
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

//nolint:cyclop
func (p *Tracer) lookForTimeouts(ctx context.Context, parseCtx *ebpfcommon.EBPFParseContext, ticker *time.Ticker, eventsChan *msg.Queue[[]request.Span]) {
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			p.retrySamplerCleanups()
			if p.bpfObjects.OngoingHttp != nil {
				i := p.bpfObjects.OngoingHttp.Iterate()
				var k BpfPidConnectionInfoT
				var v BpfHttpInfoT
				for i.Next(&k, &v) {
					// Check if we have a lingering request which we've completed, as in it has EndMonotimeNs
					// but it hasn't been posted yet, likely missed by the logic that looks at finishing requests
					// where we track the full response. If we haven't updated the EndMonotimeNs in more than some
					// short interval, we are likely not going to finish this request from eBPF, so let's do it here.
					if v.EndMonotimeNs != 0 && v.Submitted == 0 && t.After(timing.KernelTime(v.EndMonotimeNs).Add(10*time.Second)) {
						// Must use unsafe here, the two bpfHttpInfoTs are the same but generated from different
						// ebpf2go outputs
						s, ignore, err := ebpfcommon.HTTPInfoEventToSpan(parseCtx, (*ebpfcommon.BPFHTTPInfo)(unsafe.Pointer(&v)))
						if !ignore && err == nil {
							eventsChan.SendCtx(ctx, p.pidsFilter.Filter([]request.Span{s}))
						}
						if err := p.bpfObjects.OngoingHttp.Delete(k); err != nil {
							p.log.Debug("Error deleting ongoing request", "error", err)
						}
					} else if v.EndMonotimeNs == 0 && p.cfg.EBPF.HTTPRequestTimeout.Milliseconds() > 0 && t.After(timing.KernelTime(v.StartMonotimeNs).Add(p.cfg.EBPF.HTTPRequestTimeout)) {
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

func (p *Tracer) handleMisclassifiedEvent(ctx context.Context, event ebpfcommon.MisclassifiedEvent) {
	if ctx == nil || ctx.Err() != nil || event.EventType != ebpfcommon.EventTypeKHTTP2 ||
		p.bpfObjects.OngoingHttp2Connections == nil {
		return
	}
	_, err := p.writeMisclassifiedHTTP2Connection(
		p.bpfObjects.OngoingHttp2Connections,
		p.bpfObjects.ConnectionTracker,
		event.TCPInfo,
	)
	if err != nil {
		p.log.Debug("error writing HTTP2/gRPC connection info", "error", err)
	}
}

func (p *Tracer) writeMisclassifiedHTTP2Connection(
	connections http2ConnectionMapWriter,
	connectionTracker http2ConnectionTrackerReader,
	tcpInfo *ebpfcommon.TCPRequestInfo,
) (bool, error) {
	if connections == nil || connectionTracker == nil || tcpInfo == nil {
		return false, nil
	}

	processKey := genericProcessKey{
		pid: app.PID(tcpInfo.Pid.HostPid),
		ns:  tcpInfo.Pid.Ns,
	}
	p.processMu.Lock()
	admittedStartTime, admitted := p.processHostStartTime[processKey]
	p.processMu.Unlock()
	exactStartTime := tcpInfo.ProcessStartTime
	if !admitted || admittedStartTime == 0 || exactStartTime == 0 ||
		exactStartTime-(exactStartTime%processClockTickNanoseconds) != admittedStartTime ||
		tcpInfo.ConnectionTime == 0 || tcpInfo.ConnectionNetns == 0 ||
		tcpInfo.StartMonotimeNs == 0 {
		return false, nil
	}

	key := BpfPidConnectionInfoT{
		Conn: canonicalHTTP2ConnectionInfo(tcpInfo.ConnInfo),
		Pid:  tcpInfo.Pid.HostPid,
	}
	tracked := BpfTrackedConnectionT{}
	if err := connectionTracker.Lookup(&key.Conn, &tracked); errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if tracked.Time == 0 || tracked.Time != tcpInfo.ConnectionTime ||
		tracked.Netns != tcpInfo.ConnectionNetns {
		return false, nil
	}
	value := BpfHttp2ConnInfoDataT{
		Id:               tcpInfo.StartMonotimeNs,
		ProcessStartTime: exactStartTime,
		ConnectionTime:   tcpInfo.ConnectionTime,
		Flags:            tcpInfo.Ssl,
	}
	if err := connections.Update(&key, value, ebpf.UpdateNoExist); errors.Is(err, syscall.EEXIST) {
		return false, nil
	} else if err != nil {
		return true, err
	}
	return true, nil
}

func canonicalHTTP2ConnectionInfo(src ebpfcommon.BpfConnectionInfoT) BpfConnectionInfoT {
	ebpfcommon.SortConnectionInfo(&src)
	return bpfConnInfoT(src)
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
