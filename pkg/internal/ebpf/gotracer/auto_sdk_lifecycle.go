// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gotracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

const (
	goAutoSDKFlagCaptured  uint8 = 0
	goAutoSDKFlagActive    uint8 = 1
	goAutoSDKFlagQuiescing uint8 = 2

	goAutoSDKOuterCallNone           uint8 = 0
	goAutoSDKOuterCallCapture        uint8 = 1
	goAutoSDKOuterCallActive         uint8 = 2
	goAutoSDKOuterCallConsumedActive uint8 = 3
	goAutoSDKOuterCallDirectActive   uint8 = 4
	goAutoSDKOuterCallDirectConsumed uint8 = 5
	goAutoSDKOuterCallPre            uint8 = 6

	goAutoSDKPendingEpoch      = ^uint32(0)
	goAutoSDKPendingGeneration = ^uint64(0)
	goAutoSDKPendingPID        = uint64(0)
	goAutoSDKPendingStartTime  = ^uint64(0)

	goAutoSDKDrainAttempts = 8
	goAutoSDKDrainInterval = 10 * time.Millisecond
)

type goAutoSDKShutdownBudget struct {
	deadline       time.Time
	remainingScans int
}

func newGoAutoSDKShutdownBudget() *goAutoSDKShutdownBudget {
	return newGoAutoSDKShutdownBudgetUntil(
		time.Now().Add(goAutoSDKDrainAttempts * goAutoSDKDrainInterval),
	)
}

func newGoAutoSDKShutdownBudgetUntil(overallDeadline time.Time) *goAutoSDKShutdownBudget {
	deadline := time.Now().Add(goAutoSDKDrainAttempts * goAutoSDKDrainInterval)
	if overallDeadline.Before(deadline) {
		deadline = overallDeadline
	}
	return &goAutoSDKShutdownBudget{
		deadline:       deadline,
		remainingScans: goAutoSDKDrainAttempts,
	}
}

func (b *goAutoSDKShutdownBudget) takeScan() bool {
	if !b.available() || b.remainingScans == 0 {
		return false
	}
	b.remainingScans--
	return true
}

func (b *goAutoSDKShutdownBudget) available() bool {
	return b != nil && time.Now().Before(b.deadline)
}

type goAutoSDKRestoreTarget struct {
	process runtimeMetricTargetKey
	state   goAutoSDKFlagState
}

// Holding the preparation-opened /proc session prevents a reused numeric PID
// from redirecting flag activation or restoration to another process.
type goAutoSDKProcessIncarnation struct {
	session   goAutoSDKProcessSession
	closeOnce sync.Once
	closeErr  error
}

type goAutoSDKProcessRoot struct {
	file      *os.File
	closeOnce sync.Once
	closeErr  error
}

func newGoAutoSDKProcessRoot(file *os.File) *goAutoSDKProcessRoot {
	return &goAutoSDKProcessRoot{file: file}
}

func (r *goAutoSDKProcessRoot) Close() error {
	if r == nil || r.file == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		r.closeErr = r.file.Close()
	})
	return r.closeErr
}

func newGoAutoSDKProcessIncarnation(
	session goAutoSDKProcessSession,
) *goAutoSDKProcessIncarnation {
	if session == nil {
		return nil
	}
	return &goAutoSDKProcessIncarnation{session: session}
}

func (i *goAutoSDKProcessIncarnation) Close() error {
	if i == nil || i.session == nil {
		return nil
	}
	i.closeOnce.Do(func() {
		i.closeErr = i.session.Close()
	})
	return i.closeErr
}

func (p *Tracer) closeGoAutoSDKProcessIncarnation(
	incarnation *goAutoSDKProcessIncarnation,
) {
	if err := incarnation.Close(); err != nil {
		p.logGoAutoSDKError("closing Go Auto SDK process session failed", err)
	}
}

func (p *Tracer) closeGoAutoSDKProcessRoot(root *goAutoSDKProcessRoot) {
	if err := root.Close(); err != nil {
		p.logGoAutoSDKError("closing Go process root failed", err)
	}
}

func (p *Tracer) openGoAutoSDKProcessIncarnation(
	root *goAutoSDKProcessRoot,
	fileInfo *exec.FileInfo,
) (*goAutoSDKProcessIncarnation, error) {
	if p.goAutoSDKProcessAccess == nil || root == nil || fileInfo == nil {
		return nil, errors.New("process access is unavailable")
	}
	session, err := p.goAutoSDKProcessAccess.Open(root.file, fileInfo)
	if err != nil {
		return nil, err
	}
	incarnation := newGoAutoSDKProcessIncarnation(session)
	if incarnation == nil {
		return nil, errors.New("opening process returned a nil session")
	}
	actualStartTime, err := session.StartTime()
	startTime := fileInfo.StartTime()
	if err != nil || actualStartTime != startTime {
		if err == nil {
			err = fmt.Errorf("process start time changed from %d to %d",
				startTime, actualStartTime)
		}
		p.closeGoAutoSDKProcessIncarnation(incarnation)
		return nil, err
	}
	return incarnation, nil
}

func (p *Tracer) prepareGoProcessRootLocked(
	process runtimeMetricTargetKey,
	fileInfo *exec.FileInfo,
	required bool,
) *goAutoSDKProcessRoot {
	if admission, ok := p.goProcessAdmissions[process]; ok &&
		admission.fileInfo == fileInfo {
		if required && p.samplerManager != nil &&
			p.goAutoSDKProcessAccess != nil {
			if admission.processRoot != nil {
				return admission.processRoot
			}
			root := fileInfo.TakeProcessRoot()
			if root == nil {
				return nil
			}
			return newGoAutoSDKProcessRoot(root)
		}
		p.closeGoAutoSDKProcessRoot(admission.processRoot)
		return nil
	}
	if !required || p.samplerManager == nil ||
		p.goAutoSDKProcessAccess == nil {
		return nil
	}
	// Ownership moves from discovery into this process admission. The attacher
	// closes the root when no tracer claims it synchronously.
	root := fileInfo.TakeProcessRoot()
	if root == nil {
		return nil
	}
	return newGoAutoSDKProcessRoot(root)
}

func (p *Tracer) retainedGoProcessRootLocked(
	process runtimeMetricTargetKey,
	fileInfo *exec.FileInfo,
) *goAutoSDKProcessRoot {
	if admission, ok := p.goProcessAdmissions[process]; ok &&
		admission.fileInfo == fileInfo {
		return admission.processRoot
	}
	return nil
}

type managedGoAutoSDKEventReader struct {
	reader goAutoSDKEventReader
	mu     sync.Mutex
	closed bool
}

func (r *managedGoAutoSDKEventReader) Read() (ringbuf.Record, error) {
	return r.reader.Read()
}

func (r *managedGoAutoSDKEventReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	if err := r.reader.Close(); err != nil {
		return err
	}
	r.closed = true
	return nil
}

func (p *Tracer) startGoAutoSDKRun(ctx context.Context) {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return
	}

	p.processMu.Lock()
	defer p.processMu.Unlock()
	if ctx.Err() != nil || p.goAutoSDKRunStarted ||
		p.goAutoSDKShuttingDown || p.goAutoSDKShutdownComplete {
		return
	}
	p.goAutoSDKRunStarted = true
	if p.samplerManager == nil {
		return
	}

	for _, admission := range p.goAutoSDKAdmissions {
		if admission.globalPatchReady {
			p.ensureGoAutoSDKEventReader()
			break
		}
	}
	for process, admission := range p.goAutoSDKAdmissions {
		p.reconcileGoAutoSDKAdmission(process, admission)
	}
}

func (p *Tracer) reconcileGoAutoSDKAdmission(
	process runtimeMetricTargetKey,
	admission goAutoSDKAdmissionState,
) bool {
	generation, tracked := p.goProcessGenerationByPID[process]
	if !tracked || generation.retired || generation.fileInfo == nil ||
		generation.fileInfo != admission.fileInfo ||
		generation.fileInfo.StartTime() != admission.startTime {
		p.disableGoAutoSDKAdmissionLocked(process, admission)
		return true
	}

	globalProtocol := admission.globalReady &&
		admission.globalPatchReady &&
		p.goAutoSDKDiscoveryReady &&
		p.goAutoSDKGlobalReadyByExecutable[admission.executable]
	ready := p.goAutoSDKActivationReady(
		admission.executable,
		admission.optionFunctionsReady,
		admission.typeInfoReady,
		admission.samplerReady,
		admission.generationReady,
		globalProtocol,
	)
	if ready {
		if p.samplerManager.EnableAutoSDKWithSetupMode(
			process.pid,
			process.ns,
			globalProtocol,
			func(hostPID uint32, startTime uint64, epoch uint32) bool {
				return p.prepareGoAutoSDKDirectAdmission(
					process,
					hostPID,
					startTime,
					epoch,
					globalProtocol,
				)
			},
		) {
			publishedAdmission := admission
			if current, ok := p.goAutoSDKAdmissions[process]; ok &&
				current.fileInfo == admission.fileInfo {
				publishedAdmission = current
			}
			publishedAdmission.authorityActive = true
			p.goAutoSDKAdmissions[process] = publishedAdmission
			return true
		}
		if globalProtocol {
			current, ok := p.goAutoSDKAdmissions[process]
			_, prepared := p.goAutoSDKFlagStates[process]
			if ok && current.fileInfo == admission.fileInfo &&
				(!current.globalReady || !current.globalPatchReady) &&
				!prepared {
				return p.reconcileGoAutoSDKAdmission(process, current)
			}
		}
		fallbackSafe := p.restoreSamplerFallback(
			process.pid,
			process.ns,
			admission.startTime,
		)
		if fallbackSafe &&
			!p.goAutoSDKAuthorityRequiresRestore(process, admission) {
			p.disableGoAutoSDKAdmissionLocked(process, admission)
			return true
		}
		if fallbackSafe && p.restoreGoAutoSDKFlag(process) {
			p.disableGoAutoSDKAdmissionLocked(process, admission)
			return true
		}
	} else {
		fallbackSafe := p.samplerManager.QuiesceAutoSDKForProcess(
			process.pid,
			process.ns,
			admission.startTime,
		) && p.samplerManager.FallbackSafeForProcessIncarnation(
			process.pid,
			process.ns,
			admission.startTime,
		)
		if !fallbackSafe {
			fallbackSafe = p.restoreSamplerFallback(
				process.pid,
				process.ns,
				admission.startTime,
			)
		}
		if fallbackSafe &&
			!p.goAutoSDKAuthorityRequiresRestore(process, admission) {
			p.disableGoAutoSDKAdmissionLocked(process, admission)
			return true
		}
		if fallbackSafe && p.restoreGoAutoSDKFlag(process) {
			p.disableGoAutoSDKAdmissionLocked(process, admission)
			return true
		}
	}

	p.queueGoAutoSDKRestoreRetryLocked(process, admission.startTime, true)
	p.blockIndeterminateProcess(process.pid, process.ns)
	return false
}

func (p *Tracer) goAutoSDKAuthorityRequiresRestore(
	process runtimeMetricTargetKey,
	admission goAutoSDKAdmissionState,
) bool {
	if admission.authorityActive {
		return true
	}
	_, prepared := p.goAutoSDKFlagStates[process]
	return prepared
}

func (p *Tracer) disableGoAutoSDKAdmissionLocked(
	process runtimeMetricTargetKey,
	admission goAutoSDKAdmissionState,
) {
	current, ok := p.goAutoSDKAdmissions[process]
	if !ok || current.fileInfo != admission.fileInfo {
		return
	}
	delete(p.goAutoSDKAdmissions, process)
	processAdmission, ok := p.goProcessAdmissions[process]
	if !ok || processAdmission.fileInfo != admission.fileInfo {
		return
	}
	p.closeGoAutoSDKProcessRoot(processAdmission.processRoot)
	processAdmission.processRoot = nil
	p.goProcessAdmissions[process] = processAdmission
}

func (p *Tracer) disableRestoredGoAutoSDKAdmissionLocked(
	process runtimeMetricTargetKey,
	startTime uint64,
	fileInfo *exec.FileInfo,
) {
	admission, ok := p.goAutoSDKAdmissions[process]
	if !ok || admission.authorityActive ||
		admission.startTime != startTime || admission.fileInfo != fileInfo {
		return
	}
	p.disableGoAutoSDKAdmissionLocked(process, admission)
}

func (p *Tracer) ensureGoAutoSDKEventReader() bool {
	if p == nil || p.goAutoSDKShuttingDown {
		return false
	}
	if p.goAutoSDKDiscoveryReady && p.goAutoSDKEventReader != nil {
		return true
	}
	if p.goAutoSDKEventReader != nil {
		if err := p.goAutoSDKEventReader.Close(); err != nil {
			p.logGoAutoSDKError("closing failed Go Auto SDK flag discovery reader failed",
				err)
			return false
		}
		p.goAutoSDKEventReader = nil
	}
	if p.bpfObjects.GoAutoSdkFlagEvents == nil {
		p.logGoAutoSDKError("starting Go Auto SDK flag discovery failed",
			errors.New("flag discovery ring buffer is unavailable"))
		return false
	}

	factory := p.newGoAutoSDKEventReader
	if factory == nil {
		factory = func(events *ebpf.Map) (goAutoSDKEventReader, error) {
			return ringbuf.NewReader(events)
		}
	}
	rawReader, err := factory(p.bpfObjects.GoAutoSdkFlagEvents)
	if err != nil {
		p.logGoAutoSDKError("starting Go Auto SDK flag discovery failed", err)
		return false
	}
	if rawReader == nil {
		p.logGoAutoSDKError("starting Go Auto SDK flag discovery failed",
			errors.New("flag discovery reader is unavailable"))
		return false
	}
	reader := &managedGoAutoSDKEventReader{reader: rawReader}

	p.goAutoSDKEventReader = reader
	p.goAutoSDKDiscoveryReady = true
	p.goAutoSDKEventWG.Add(1)
	go p.readGoAutoSDKFlagEvents(reader)
	return true
}

func (p *Tracer) readGoAutoSDKFlagEvents(reader goAutoSDKEventReader) {
	defer p.goAutoSDKEventWG.Done()
	for {
		record, err := reader.Read()
		if err != nil {
			if !errors.Is(err, ringbuf.ErrClosed) {
				p.logGoAutoSDKError("reading Go Auto SDK flag discovery failed", err)
			}
			closeErr := reader.Close()
			if closeErr != nil {
				p.logGoAutoSDKError("closing failed Go Auto SDK flag discovery reader failed",
					closeErr)
			}
			p.processMu.Lock()
			if p.goAutoSDKEventReader == reader {
				p.goAutoSDKDiscoveryReady = false
				if closeErr == nil {
					p.goAutoSDKEventReader = nil
				}
				if !p.goAutoSDKShuttingDown {
					for process, state := range p.goAutoSDKFlagStates {
						if !state.globalProtocol && state.flagPtr == 0 &&
							!state.restoreRequired &&
							!state.discardRequired {
							continue
						}
						p.queueGoAutoSDKRestoreRetryLocked(
							process,
							state.startTime,
							false,
						)
					}
				}
			}
			p.processMu.Unlock()
			return
		}
		if len(record.RawSample) != 16 {
			p.logGoAutoSDKError("reading Go Auto SDK flag discovery failed",
				fmt.Errorf("unexpected process key size %d", len(record.RawSample)))
			continue
		}

		key := goProcessKey{
			PID:        binary.NativeEndian.Uint64(record.RawSample[:8]),
			Generation: binary.NativeEndian.Uint64(record.RawSample[8:]),
		}
		p.processMu.Lock()
		p.activateGoAutoSDKFlag(key)
		p.processMu.Unlock()
	}
}

func (p *Tracer) goProcessStartTime(process runtimeMetricTargetKey) uint64 {
	if admission, ok := p.goProcessAdmissions[process]; ok && admission.startTime != 0 {
		return admission.startTime
	}
	if admission, ok := p.goAutoSDKAdmissions[process]; ok && admission.startTime != 0 {
		return admission.startTime
	}
	if state, ok := p.goAutoSDKFlagStates[process]; ok && state.startTime != 0 {
		return state.startTime
	}
	if generation, ok := p.goProcessGenerationByPID[process]; ok &&
		generation.fileInfo != nil {
		return generation.fileInfo.StartTime()
	}
	return 0
}

func (p *Tracer) goAutoSDKRestorationStartTime(
	process runtimeMetricTargetKey,
	fallback uint64,
) uint64 {
	if state, ok := p.goAutoSDKFlagStates[process]; ok && state.startTime != 0 {
		return state.startTime
	}
	if startTime := p.goProcessStartTime(process); startTime != 0 {
		return startTime
	}
	return fallback
}

func (p *Tracer) restoreGoAutoSDKFlagForIncarnation(
	process runtimeMetricTargetKey,
	startTime uint64,
) bool {
	if startTime == 0 {
		return p.restoreGoAutoSDKFlag(process)
	}
	if state, ok := p.goAutoSDKFlagStates[process]; ok {
		if state.startTime != startTime {
			if admission, admitted := p.goProcessAdmissions[process]; admitted && admission.startTime == startTime {
				return p.restoreGoAutoSDKFlag(process)
			}
			return true
		}
		return p.restoreGoAutoSDKFlag(process)
	}
	if generation, ok := p.goProcessGenerationByPID[process]; ok &&
		generation.fileInfo != nil {
		if generation.fileInfo.StartTime() != startTime {
			return true
		}
		return p.restoreGoAutoSDKFlag(process)
	}
	return true
}

func (p *Tracer) hasGoAutoSDKRestoreRetryLocked(
	process runtimeMetricTargetKey,
) bool {
	for retry := range p.goAutoSDKRestoreRetries {
		if retry.process == process {
			return true
		}
	}
	return false
}

func (p *Tracer) runGoAutoSDKRestoreRetryLocked(
	retry goAutoSDKRestoreRetryKey,
	cleanupProcess bool,
) bool {
	if !p.restoreGoAutoSDKFlagForIncarnation(retry.process, retry.startTime) {
		return false
	}
	if cleanupProcess {
		p.disableRestoredGoAutoSDKAdmissionLocked(
			retry.process,
			retry.startTime,
			retry.fileInfo,
		)
		return p.finishBlockedGoProcess(retry.process, retry.startTime)
	}
	if admission, ok := p.goAutoSDKAdmissions[retry.process]; ok &&
		admission.startTime == retry.startTime &&
		admission.fileInfo == retry.fileInfo {
		if p.goAutoSDKReadyByExecutable[admission.executable] {
			admission.globalReady = false
			admission.globalPatchReady = false
			p.goAutoSDKAdmissions[retry.process] = admission
			return p.reconcileGoAutoSDKAdmission(retry.process, admission)
		}
		p.disableGoAutoSDKAdmissionLocked(retry.process, admission)
	}
	return true
}

func (p *Tracer) settleGoAutoSDKRestoreRetriesLocked(
	process runtimeMetricTargetKey,
) bool {
	for {
		settled := true
		for retry, cleanupProcess := range p.goAutoSDKRestoreRetries {
			if retry.process != process {
				continue
			}
			if !p.runGoAutoSDKRestoreRetryLocked(retry, cleanupProcess) {
				return false
			}
			delete(p.goAutoSDKRestoreRetries, retry)
			settled = false
			break
		}
		if settled {
			delete(p.goAutoSDKQuiescing, process)
			return true
		}
	}
}

func (p *Tracer) quiesceGoProcessIncarnationLocked(
	process runtimeMetricTargetKey,
	startTime uint64,
) bool {
	fileInfo := p.goProcessFileInfo(process)
	if p.goAutoSDKQuiescing == nil {
		p.goAutoSDKQuiescing = map[runtimeMetricTargetKey]bool{}
	}
	p.goAutoSDKQuiescing[process] = true
	if !p.restoreGoAutoSDKFlagForIncarnation(process, startTime) {
		p.queueGoAutoSDKRestoreRetryLocked(process, startTime, true)
		return false
	}
	p.disableRestoredGoAutoSDKAdmissionLocked(process, startTime, fileInfo)
	p.pidsFilter.BlockPID(process.pid, process.ns)
	p.deleteRuntimeMetricTarget(process.pid, process.ns)
	if !p.finishBlockedGoProcess(process, startTime) {
		p.queueGoAutoSDKRestoreRetryLocked(process, startTime, true)
		return false
	}
	if !p.hasGoAutoSDKRestoreRetryLocked(process) {
		delete(p.goAutoSDKQuiescing, process)
	}
	return true
}

func (p *Tracer) prepareGoProcessAdmissionLocked(
	process runtimeMetricTargetKey,
	fileInfo *exec.FileInfo,
) bool {
	if fileInfo == nil || fileInfo.StartTime() == 0 {
		return false
	}
	startTime := fileInfo.StartTime()
	if !p.settleGoAutoSDKRestoreRetriesLocked(process) {
		return false
	}
	if previousStartTime := p.goProcessStartTime(process); previousStartTime != 0 {
		previousFileInfo := p.goProcessFileInfo(process)
		if (previousStartTime != startTime || previousFileInfo != fileInfo) &&
			!p.quiesceGoProcessIncarnationLocked(process, previousStartTime) {
			return false
		}
	}

	resolve := p.resolveGoProcessHostPID
	if resolve == nil {
		resolve = resolveGoProcessHostPID
	}
	hostPID, err := resolve(process.pid, process.ns)
	if err != nil {
		return true
	}
	owner, owned := p.goProcessOwnerByHostPID[hostPID]
	if !owned || owner == process {
		return true
	}
	if !p.settleGoAutoSDKRestoreRetriesLocked(owner) {
		return false
	}
	ownerStartTime := p.goProcessStartTime(owner)
	return ownerStartTime == 0 ||
		p.quiesceGoProcessIncarnationLocked(owner, ownerStartTime)
}

func (p *Tracer) queueGoAutoSDKRestoreRetryLocked(
	process runtimeMetricTargetKey,
	startTime uint64,
	cleanupProcess bool,
) {
	if p.goAutoSDKShuttingDown {
		return
	}
	if p.goAutoSDKQuiescing == nil {
		p.goAutoSDKQuiescing = map[runtimeMetricTargetKey]bool{}
	}
	if p.goAutoSDKRestoreRetries == nil {
		p.goAutoSDKRestoreRetries = map[goAutoSDKRestoreRetryKey]bool{}
	}
	if startTime == 0 {
		startTime = p.goProcessStartTime(process)
	}
	retry := goAutoSDKRestoreRetryKey{
		process:   process,
		startTime: startTime,
		fileInfo:  p.goProcessFileInfo(process),
	}
	p.goAutoSDKQuiescing[process] = true
	p.goAutoSDKRestoreRetries[retry] = p.goAutoSDKRestoreRetries[retry] || cleanupProcess
	p.startGoAutoSDKRestoreRetryLocked()
}

func (p *Tracer) startGoAutoSDKRestoreRetryLocked() {
	if p.goAutoSDKRestoreRetrying || p.goAutoSDKShuttingDown ||
		len(p.goAutoSDKRestoreRetries) == 0 {
		return
	}
	p.goAutoSDKRestoreRetrying = true
	p.goAutoSDKRestoreRetryWG.Add(1)
	go p.retryGoAutoSDKRestores()
}

func (p *Tracer) retryGoAutoSDKRestores() {
	defer p.goAutoSDKRestoreRetryWG.Done()
	for {
		p.processMu.Lock()
		if p.goAutoSDKShuttingDown {
			p.goAutoSDKRestoreRetrying = false
			p.processMu.Unlock()
			return
		}
		for retry, cleanupProcess := range p.goAutoSDKRestoreRetries {
			if p.runGoAutoSDKRestoreRetryLocked(retry, cleanupProcess) {
				delete(p.goAutoSDKRestoreRetries, retry)
				if !p.hasGoAutoSDKRestoreRetryLocked(retry.process) {
					delete(p.goAutoSDKQuiescing, retry.process)
				}
			}
		}
		if len(p.goAutoSDKRestoreRetries) == 0 {
			p.goAutoSDKRestoreRetrying = false
			p.processMu.Unlock()
			return
		}
		p.processMu.Unlock()
		p.pauseGoAutoSDKRestoreRetry()
	}
}

func (p *Tracer) pauseGoAutoSDKRestoreRetry() {
	if p.goAutoSDKRestoreRetryPause != nil {
		p.goAutoSDKRestoreRetryPause()
		return
	}
	time.Sleep(25 * time.Millisecond)
}

func goAutoSDKInflightKeyForState(
	state goAutoSDKFlagState,
) goAutoSDKInflightKey {
	return goAutoSDKInflightKey{
		PID:        state.key.PID,
		Generation: state.key.Generation,
		StartTime:  state.startTime,
		Epoch:      state.epoch,
	}
}

func goAutoSDKPendingState() goAutoSDKFlagState {
	return goAutoSDKFlagState{
		key: goProcessKey{
			PID:        goAutoSDKPendingPID,
			Generation: goAutoSDKPendingGeneration,
		},
		startTime: goAutoSDKPendingStartTime,
		epoch:     goAutoSDKPendingEpoch,
	}
}

func goAutoSDKIsPendingState(state goAutoSDKFlagState) bool {
	return state.key.PID == goAutoSDKPendingPID &&
		state.key.Generation == goAutoSDKPendingGeneration &&
		state.startTime == goAutoSDKPendingStartTime &&
		state.epoch == goAutoSDKPendingEpoch
}

func (p *Tracer) provisionGoAutoSDKInflight(
	state goAutoSDKFlagState,
) bool {
	if p.goAutoSDKInflight == nil ||
		(state.key.PID == 0 && !goAutoSDKIsPendingState(state)) ||
		state.key.Generation == 0 || state.startTime == 0 || state.epoch == 0 {
		return false
	}
	key := goAutoSDKInflightKeyForState(state)
	var current goAutoSDKInflightValue
	err := p.goAutoSDKInflight.Lookup(key, &current)
	switch {
	case err == nil:
		return current.State == 0
	case !errors.Is(err, ebpf.ErrKeyNotExist):
		p.logGoAutoSDKError("looking up Go Auto SDK in-flight state failed", err)
		return false
	}
	if err := p.goAutoSDKInflight.Update(
		key, goAutoSDKInflightValue{}, ebpf.UpdateNoExist,
	); err != nil {
		p.logGoAutoSDKError("provisioning Go Auto SDK in-flight state failed", err)
		return false
	}
	if err := p.goAutoSDKInflight.Lookup(key, &current); err != nil ||
		current.State != 0 {
		if err == nil {
			err = errors.New("new in-flight state is not empty")
		}
		p.logGoAutoSDKError("validating Go Auto SDK in-flight state failed", err)
		if deleteErr := p.goAutoSDKInflight.Delete(key); deleteErr != nil &&
			!errors.Is(deleteErr, ebpf.ErrKeyNotExist) {
			p.logGoAutoSDKError(
				"rolling back Go Auto SDK in-flight state failed", deleteErr,
			)
		}
		return false
	}
	return true
}

func (p *Tracer) prepareGoAutoSDKDirectAdmission(
	process runtimeMetricTargetKey,
	hostPID uint32,
	startTime uint64,
	epoch uint32,
	globalProtocol bool,
) bool {
	if hostPID == 0 || startTime == 0 || epoch == 0 {
		return false
	}
	generation, tracked := p.goProcessGenerationByPID[process]
	if !tracked || generation.retired || generation.hostPID != hostPID ||
		generation.generation == 0 || generation.fileInfo == nil ||
		generation.fileInfo.StartTime() != startTime {
		return false
	}
	admission, admitted := p.goProcessAdmissions[process]
	if !admitted || admission.fileInfo != generation.fileInfo ||
		admission.startTime != startTime {
		return false
	}
	autoSDKAdmission, autoSDKAdmitted := p.goAutoSDKAdmissions[process]
	globalProtocol = globalProtocol && autoSDKAdmitted &&
		autoSDKAdmission.fileInfo == generation.fileInfo &&
		autoSDKAdmission.globalReady &&
		autoSDKAdmission.globalPatchReady &&
		p.goAutoSDKDiscoveryReady &&
		p.goAutoSDKGlobalReadyByExecutable[autoSDKAdmission.executable]
	state := goAutoSDKFlagState{
		key: goProcessKey{
			PID:        uint64(hostPID),
			Generation: generation.generation,
		},
		startTime:      startTime,
		epoch:          epoch,
		original:       0,
		globalProtocol: globalProtocol,
		fileInfo:       generation.fileInfo,
	}
	if current, ok := p.goAutoSDKFlagStates[process]; ok {
		exact := current.key == state.key &&
			current.startTime == state.startTime &&
			current.epoch == state.epoch &&
			current.flagPtr == 0 &&
			!current.restoreRequired &&
			!current.discardRequired &&
			current.globalProtocol == state.globalProtocol &&
			current.fileInfo == state.fileInfo
		return exact &&
			p.provisionGoAutoSDKInflight(current)
	}
	if !p.provisionGoAutoSDKInflight(state) {
		return false
	}
	if globalProtocol && autoSDKAdmission.globalPatchReady {
		incarnation, err := p.openGoAutoSDKProcessIncarnation(
			admission.processRoot,
			generation.fileInfo,
		)
		if err != nil {
			autoSDKAdmission.globalPatchReady = false
			p.goAutoSDKAdmissions[process] = autoSDKAdmission
			p.logGoAutoSDKError(
				"pinning Go Auto SDK process for global activation failed",
				err,
			)
			if !p.deleteGoAutoSDKInflight(state) {
				if p.goAutoSDKFlagStates == nil {
					p.goAutoSDKFlagStates = map[runtimeMetricTargetKey]goAutoSDKFlagState{}
				}
				p.goAutoSDKFlagStates[process] = state
			}
			return false
		} else {
			state.incarnation = incarnation
		}
	}
	if p.goAutoSDKFlagStates == nil {
		p.goAutoSDKFlagStates = map[runtimeMetricTargetKey]goAutoSDKFlagState{}
	}
	p.goAutoSDKFlagStates[process] = state
	return true
}

func (p *Tracer) validateGoAutoSDKPendingAdmission() bool {
	if !p.goAutoSDKPreAdmissionReady {
		return false
	}
	_, err := p.goAutoSDKInflightCount(goAutoSDKPendingState())
	if err != nil {
		p.logGoAutoSDKError(
			"validating Go Auto SDK pre-admission latch failed",
			err,
		)
		return false
	}
	return true
}

func (p *Tracer) goAutoSDKInflightCount(
	state goAutoSDKFlagState,
) (uint32, error) {
	if p.goAutoSDKInflight == nil {
		return 0, errors.New("in-flight map is unavailable")
	}
	var current goAutoSDKInflightValue
	if err := p.goAutoSDKInflight.Lookup(
		goAutoSDKInflightKeyForState(state), &current,
	); err != nil {
		return 0, err
	}
	activeCalls, err := goAutoSDKInflightCountFromValue(current)
	if err != nil || activeCalls != 0 {
		return activeCalls, err
	}

	// Tracing programs cannot use map-value spin locks on the minimum supported
	// kernels. Require two zero snapshots of the single atomic lifetime word
	// before userspace treats a synchronously closed admission gate as drained.
	if err := p.goAutoSDKInflight.Lookup(
		goAutoSDKInflightKeyForState(state), &current,
	); err != nil {
		return 0, err
	}
	return goAutoSDKInflightCountFromValue(current)
}

func goAutoSDKInflightCountFromValue(
	current goAutoSDKInflightValue,
) (uint32, error) {
	if current.poisonGeneration() != 0 {
		return 0, errors.New("in-flight state is poisoned")
	}
	activeCalls := current.activeCalls()
	if activeCalls > goAutoSDKMaxInflightCalls {
		return 0, errors.New("in-flight state is corrupt")
	}
	return activeCalls, nil
}

func (p *Tracer) deleteGoAutoSDKInflight(
	state goAutoSDKFlagState,
) bool {
	if p.goAutoSDKInflight == nil {
		return false
	}
	err := p.goAutoSDKInflight.Delete(goAutoSDKInflightKeyForState(state))
	if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
		return true
	}
	p.logGoAutoSDKError("deleting Go Auto SDK in-flight state failed", err)
	return false
}

func (p *Tracer) activateGoAutoSDKFlag(key goProcessKey) {
	if p == nil || p.goAutoSDKShuttingDown || !p.goAutoSDKDiscoveryReady ||
		p.goAutoSDKGlobalEntryBarrierClosed ||
		!p.goAutoSDKPreAdmissionReady || !p.goAutoSDKTailCallsReady ||
		p.goAutoSDKFlags == nil || p.goAutoSDKReadiness == nil ||
		key.PID == 0 || key.PID > uint64(^uint32(0)) ||
		key.Generation == 0 || !p.validateGoAutoSDKPendingAdmission() {
		return
	}

	var flag goAutoSDKFlagValue
	if err := p.goAutoSDKFlags.Lookup(key, &flag); err != nil {
		p.logGoAutoSDKError("looking up Go Auto SDK flag discovery failed", err)
		return
	}
	if flag.FlagPtr == 0 || flag.StartTime == 0 || flag.Epoch == 0 ||
		flag.Activated > goAutoSDKFlagQuiescing {
		p.logGoAutoSDKError("validating Go Auto SDK flag discovery failed",
			errors.New("flag discovery metadata is incomplete"))
		return
	}

	hostPID := uint32(key.PID)
	process, owned := p.goProcessOwnerByHostPID[hostPID]
	generation, tracked := p.goProcessGenerationByPID[process]
	if !owned || !tracked || generation.retired || generation.hostPID != hostPID ||
		generation.generation != key.Generation || generation.fileInfo == nil ||
		generation.fileInfo.StartTime() != flag.StartTime ||
		p.goAutoSDKQuiescing[process] {
		return
	}
	admission, admitted := p.goProcessAdmissions[process]
	if !admitted || admission.fileInfo != generation.fileInfo ||
		admission.processRoot == nil {
		return
	}
	autoSDKAdmission, autoSDKAdmitted := p.goAutoSDKAdmissions[process]
	executable, executableOK := goExecutableKeyFor(generation.fileInfo)
	if !autoSDKAdmitted ||
		autoSDKAdmission.fileInfo != generation.fileInfo ||
		!autoSDKAdmission.globalReady ||
		!autoSDKAdmission.globalPatchReady ||
		!executableOK ||
		!p.goAutoSDKGlobalReadyByExecutable[executable] {
		return
	}

	var readiness goAutoSDKReadinessValue
	if err := p.goAutoSDKReadiness.Lookup(hostPID, &readiness); err != nil {
		p.logGoAutoSDKError("looking up Go Auto SDK readiness failed", err)
		return
	}
	if readiness.Ready != 1 || readiness.AutoSDKGlobalReady != 1 ||
		readiness.StartTime != flag.StartTime ||
		readiness.Epoch != flag.Epoch {
		return
	}

	state, prepared := p.goAutoSDKFlagStates[process]
	if !prepared {
		if p.goAutoSDKFlagStates == nil {
			p.goAutoSDKFlagStates = map[runtimeMetricTargetKey]goAutoSDKFlagState{}
		}
		p.goAutoSDKFlagStates[process] = goAutoSDKFlagState{
			key:            key,
			startTime:      flag.StartTime,
			epoch:          flag.Epoch,
			original:       0,
			globalProtocol: true,
			fileInfo:       generation.fileInfo,
		}
		p.failGoAutoSDKActivation(
			process,
			errors.New("go Auto SDK in-flight state was not prepared before readiness"),
		)
		return
	}
	exactPrepared := state.key == key &&
		state.startTime == flag.StartTime &&
		state.epoch == flag.Epoch &&
		state.globalProtocol &&
		state.fileInfo == generation.fileInfo
	if !exactPrepared {
		p.failGoAutoSDKActivation(
			process,
			errors.New("prepared Go Auto SDK in-flight state does not match discovery"),
		)
		return
	}
	if state.incarnation == nil || state.incarnation.session == nil {
		incarnation, err := p.openGoAutoSDKProcessIncarnation(
			admission.processRoot,
			generation.fileInfo,
		)
		if err != nil {
			p.logGoAutoSDKError("pinning Go Auto SDK process for global activation failed", err)
			return
		}
		state.incarnation = incarnation
		p.goAutoSDKFlagStates[process] = state
	}
	processSession := state.incarnation.session
	actualStartTime, err := processSession.StartTime()
	if err != nil || actualStartTime != flag.StartTime {
		if err == nil {
			err = fmt.Errorf("process start time changed from %d to %d",
				flag.StartTime, actualStartTime)
		}
		p.failGoAutoSDKActivation(process, err)
		return
	}
	if state.flagPtr != 0 {
		if state.flagPtr == flag.FlagPtr &&
			flag.Activated == goAutoSDKFlagActive {
			return
		}
		p.failGoAutoSDKActivation(
			process,
			errors.New("an unresolved Go Auto SDK flag activation already exists"),
		)
		return
	}
	if flag.Activated == goAutoSDKFlagActive {
		p.logGoAutoSDKError("validating Go Auto SDK flag discovery failed",
			errors.New("active flag has no restoration state"))
		return
	}
	if flag.Activated == goAutoSDKFlagQuiescing {
		return
	}

	original, err := processSession.Read(flag.FlagPtr)
	if err != nil {
		if errors.Is(err, errGoAutoSDKProcessMemoryGone) {
			p.failGoAutoSDKActivationForGoneMemory(process, state, err)
			return
		}
		p.failGoAutoSDKActivation(process, err)
		return
	}
	if original != 0 {
		p.failGoAutoSDKActivation(
			process,
			fmt.Errorf("go Auto SDK flag is already owned: value %d", original),
		)
		return
	}
	if _, err := p.goAutoSDKInflightCount(state); err != nil {
		p.failGoAutoSDKActivation(
			process,
			fmt.Errorf("go Auto SDK in-flight state is unavailable: %w", err),
		)
		return
	}
	state.flagPtr = flag.FlagPtr
	state.original = 0
	state.restoreRequired = true
	p.goAutoSDKFlagStates[process] = state

	// Publish exact admission before draining PRE. Every handler that starts
	// after this publication migrates to the exact counter, while handlers
	// that observed the old gate keep PRE nonzero until their owning return.
	flag.Activated = goAutoSDKFlagActive
	if err := p.goAutoSDKFlags.Put(key, flag); err != nil {
		p.failGoAutoSDKActivation(process, err)
		return
	}
	if !p.waitForGoAutoSDKPreAdmissionCalls() {
		p.failGoAutoSDKActivation(
			process,
			errors.New("pre-admission Go Auto SDK calls did not drain"),
		)
		return
	}

	if err := processSession.Write(flag.FlagPtr, 1); err != nil {
		if errors.Is(err, errGoAutoSDKProcessMemoryGone) {
			p.failGoAutoSDKActivationForGoneMemory(process, state, err)
			return
		}
		p.failGoAutoSDKActivation(process, err)
		return
	}
	activated, err := processSession.Read(flag.FlagPtr)
	if err != nil {
		if errors.Is(err, errGoAutoSDKProcessMemoryGone) {
			p.failGoAutoSDKActivationForGoneMemory(process, state, err)
			return
		}
		p.failGoAutoSDKActivation(process, err)
		return
	}
	if activated != 1 {
		p.failGoAutoSDKActivation(
			process,
			fmt.Errorf("go Auto SDK flag activation read back %d", activated),
		)
		return
	}
}

func (p *Tracer) failGoAutoSDKActivationForGoneMemory(
	process runtimeMetricTargetKey,
	state goAutoSDKFlagState,
	cause error,
) {
	state.restoreRequired = false
	state.discardRequired = true
	p.goAutoSDKFlagStates[process] = state
	if !p.discardStaleGoAutoSDKFlag(process, state) {
		p.queueGoAutoSDKRestoreRetryLocked(process, state.startTime, false)
		p.logGoAutoSDKError(
			"discarding unavailable Go Auto SDK process memory failed",
			cause,
		)
		return
	}
	p.logGoAutoSDKError("activating Go Auto SDK flag failed", cause)
}

func (p *Tracer) failGoAutoSDKActivation(
	process runtimeMetricTargetKey,
	cause error,
) {
	admission, admitted := p.goAutoSDKAdmissions[process]
	cleanupSafe := p.restoreGoAutoSDKFlag(process)
	if !cleanupSafe {
		p.queueGoAutoSDKRestoreRetryLocked(
			process,
			p.goAutoSDKRestorationStartTime(process, 0),
			false,
		)
		p.logGoAutoSDKError(
			"restoring Go Auto SDK flag failed; retaining readiness and probes",
			cause,
		)
		return
	}
	if admitted {
		p.disableGoAutoSDKAdmissionLocked(process, admission)
	}

	p.logGoAutoSDKError("activating Go Auto SDK flag failed", cause)
}

func (p *Tracer) restoreGoAutoSDKFlag(process runtimeMetricTargetKey) bool {
	state, ok := p.goAutoSDKFlagStates[process]
	if !ok {
		admission, admitted := p.goAutoSDKAdmissions[process]
		if !admitted {
			return true
		}
		if !admission.globalReady {
			if admission.authorityActive {
				p.logGoAutoSDKError(
					"restoring Go Auto SDK authority failed",
					errors.New("active direct authority has no exact state"),
				)
				return false
			}
			return true
		}
		return p.cleanupCapturedGoAutoSDKFlag(process)
	}
	target, cleanupSafe := p.prepareActiveGoAutoSDKFlagRestore(process, state)
	if !cleanupSafe || target == nil {
		return cleanupSafe
	}
	if target.state.globalProtocol &&
		!p.waitForGoAutoSDKPreAdmissionCalls() {
		return false
	}
	if !p.waitForGoAutoSDKOuterCalls(target.state) {
		return false
	}
	return p.finishGoAutoSDKFlagRestore(*target)
}

func (p *Tracer) prepareActiveGoAutoSDKFlagRestore(
	process runtimeMetricTargetKey,
	state goAutoSDKFlagState,
) (*goAutoSDKRestoreTarget, bool) {
	target, cleanupSafe := p.prepareGoAutoSDKFlagMemoryRestore(process, state)
	if !cleanupSafe || target == nil {
		return target, cleanupSafe
	}
	if !p.quiesceGoAutoSDKRestoreTarget(*target) {
		return nil, false
	}
	return target, true
}

func (p *Tracer) prepareGoAutoSDKFlagMemoryRestore(
	process runtimeMetricTargetKey,
	state goAutoSDKFlagState,
) (*goAutoSDKRestoreTarget, bool) {
	if state.flagPtr == 0 && !state.restoreRequired && !state.discardRequired &&
		(!state.globalProtocol || state.incarnation == nil) {
		return &goAutoSDKRestoreTarget{process: process, state: state}, true
	}
	if state.incarnation == nil || state.incarnation.session == nil {
		p.logGoAutoSDKError(
			"restoring Go Auto SDK flag failed",
			errors.New("exact process incarnation is unavailable"),
		)
		return nil, false
	}
	if state.discardRequired {
		return nil, p.discardStaleGoAutoSDKFlag(process, state)
	}

	hostPID := uint32(state.key.PID)
	processSession := state.incarnation.session
	actualStartTime, err := processSession.StartTime()
	if err != nil {
		if goAutoSDKProcessGone(err) {
			return nil, p.discardStaleGoAutoSDKFlag(process, state)
		}
		p.logGoAutoSDKError("reading Go Auto SDK process start time during restore failed", err)
		return nil, false
	}
	if actualStartTime != state.startTime {
		return nil, p.discardStaleGoAutoSDKFlag(process, state)
	}

	generation, tracked := p.goProcessGenerationByPID[process]
	owner, owned := p.goProcessOwnerByHostPID[hostPID]
	if !tracked || !owned || owner != process || generation.retired ||
		generation.hostPID != hostPID || generation.generation != state.key.Generation ||
		generation.fileInfo == nil || generation.fileInfo != state.fileInfo ||
		generation.fileInfo.StartTime() != state.startTime {
		p.logGoAutoSDKError("restoring Go Auto SDK flag failed",
			errors.New("live process generation no longer matches restoration state"))
		return nil, false
	}
	if state.original != 0 {
		p.logGoAutoSDKError("restoring Go Auto SDK flag failed",
			errors.New("restoration state does not own a zero flag"))
		return nil, false
	}
	if p.goAutoSDKFlags == nil {
		return nil, false
	}

	if state.flagPtr != 0 && state.restoreRequired {
		if err := processSession.Write(state.flagPtr, state.original); err != nil {
			if errors.Is(err, errGoAutoSDKProcessMemoryGone) {
				state.restoreRequired = false
				state.discardRequired = true
				p.goAutoSDKFlagStates[process] = state
				return nil, p.discardStaleGoAutoSDKFlag(process, state)
			}
			if goAutoSDKProcessGone(err) {
				return nil, p.discardStaleGoAutoSDKFlag(process, state)
			}
			p.logGoAutoSDKError("restoring Go Auto SDK flag failed", err)
			return nil, false
		}
		restored, err := processSession.Read(state.flagPtr)
		if err != nil {
			if errors.Is(err, errGoAutoSDKProcessMemoryGone) {
				state.restoreRequired = false
				state.discardRequired = true
				p.goAutoSDKFlagStates[process] = state
				return nil, p.discardStaleGoAutoSDKFlag(process, state)
			}
			if goAutoSDKProcessGone(err) {
				return nil, p.discardStaleGoAutoSDKFlag(process, state)
			}
			p.logGoAutoSDKError("verifying restored Go Auto SDK flag failed", err)
			return nil, false
		}
		if restored != state.original {
			p.logGoAutoSDKError("verifying restored Go Auto SDK flag failed",
				fmt.Errorf("read back %d, expected %d", restored, state.original))
			return nil, false
		}
		state.restoreRequired = false
		p.goAutoSDKFlagStates[process] = state
	}

	return &goAutoSDKRestoreTarget{process: process, state: state}, true
}

func (p *Tracer) quiesceGoAutoSDKRestoreTarget(
	target goAutoSDKRestoreTarget,
) bool {
	if target.state.flagPtr != 0 {
		flag := goAutoSDKFlagValue{
			FlagPtr:   target.state.flagPtr,
			StartTime: target.state.startTime,
			Epoch:     target.state.epoch,
			Activated: goAutoSDKFlagQuiescing,
		}
		if err := p.goAutoSDKFlags.Put(target.state.key, flag); err != nil {
			p.logGoAutoSDKError("marking Go Auto SDK flag quiescing failed", err)
			return false
		}
	}
	return p.quiesceGoAutoSDKReadiness(
		target.process,
		target.state.startTime,
	)
}

func (p *Tracer) finishGoAutoSDKFlagRestore(target goAutoSDKRestoreTarget) bool {
	if p.goAutoSDKFlags != nil {
		if err := p.goAutoSDKFlags.Delete(target.state.key); err != nil &&
			!errors.Is(err, ebpf.ErrKeyNotExist) {
			p.logGoAutoSDKError("deleting Go Auto SDK flag discovery failed", err)
			return false
		}
	} else if target.state.globalProtocol {
		return false
	}
	if !p.deleteGoAutoSDKInflight(target.state) {
		return false
	}
	delete(p.goAutoSDKFlagStates, target.process)
	p.closeGoAutoSDKProcessIncarnation(target.state.incarnation)
	if admission, ok := p.goAutoSDKAdmissions[target.process]; ok &&
		admission.startTime == target.state.startTime &&
		admission.fileInfo == target.state.fileInfo {
		admission.authorityActive = false
		p.goAutoSDKAdmissions[target.process] = admission
	}
	return true
}

func (p *Tracer) cleanupCapturedGoAutoSDKFlag(process runtimeMetricTargetKey) bool {
	if _, ok := p.goAutoSDKFlagStates[process]; ok {
		return p.restoreGoAutoSDKFlag(process)
	}
	target, cleanupSafe := p.prepareCapturedGoAutoSDKFlagRestore(process)
	if !cleanupSafe || target == nil {
		return cleanupSafe
	}
	if !p.waitForGoAutoSDKPreAdmissionCalls() {
		return false
	}
	if !p.waitForGoAutoSDKOuterCalls(target.state) {
		return false
	}
	return p.finishGoAutoSDKFlagRestore(*target)
}

func (p *Tracer) prepareCapturedGoAutoSDKFlagRestore(
	process runtimeMetricTargetKey,
) (*goAutoSDKRestoreTarget, bool) {
	target, cleanupSafe := p.prepareCapturedGoAutoSDKFlagMemoryRestore(process)
	if !cleanupSafe || target == nil {
		return target, cleanupSafe
	}
	if !p.quiesceGoAutoSDKRestoreTarget(*target) {
		return nil, false
	}
	return target, true
}

func (p *Tracer) prepareCapturedGoAutoSDKFlagMemoryRestore(
	process runtimeMetricTargetKey,
) (*goAutoSDKRestoreTarget, bool) {
	generation, tracked := p.goProcessGenerationByPID[process]
	if !tracked || generation.retired || generation.fileInfo == nil ||
		generation.hostPID == 0 || generation.generation == 0 {
		return nil, true
	}

	state := goAutoSDKFlagState{
		key: goProcessKey{
			PID:        uint64(generation.hostPID),
			Generation: generation.generation,
		},
		startTime:      generation.fileInfo.StartTime(),
		globalProtocol: true,
		fileInfo:       generation.fileInfo,
	}
	if !p.goAutoSDKPreAdmissionReady &&
		!p.goAutoSDKDiscoveryReady && p.goAutoSDKFlags == nil {
		return nil, p.quiesceGoAutoSDKReadiness(
			process,
			generation.fileInfo.StartTime(),
		)
	}
	autoSDKAdmission, enabled := p.goAutoSDKAdmissions[process]
	if !enabled {
		return nil, true
	}
	if autoSDKAdmission.fileInfo != generation.fileInfo {
		p.logGoAutoSDKError(
			"reconstructing captured Go Auto SDK state failed",
			errors.New("auto SDK admission does not match the process generation"),
		)
		return nil, false
	}
	if !autoSDKAdmission.authorityActive {
		return nil, true
	}
	admission, admitted := p.goProcessAdmissions[process]
	if !admitted || admission.fileInfo != generation.fileInfo ||
		admission.processRoot == nil {
		p.logGoAutoSDKError(
			"reconstructing captured Go Auto SDK state failed",
			errors.New("exact process incarnation is unavailable"),
		)
		return nil, false
	}
	if p.goAutoSDKFlags != nil {
		var flag goAutoSDKFlagValue
		if err := p.goAutoSDKFlags.Lookup(state.key, &flag); err == nil {
			if flag.FlagPtr == 0 || flag.StartTime != state.startTime ||
				flag.Epoch == 0 || flag.Activated > goAutoSDKFlagQuiescing {
				p.logGoAutoSDKError(
					"reconstructing captured Go Auto SDK state failed",
					errors.New("discovered flag metadata is not exact"),
				)
				return nil, false
			}
			state.flagPtr = flag.FlagPtr
			state.epoch = flag.Epoch
			state.original = 0
			state.restoreRequired = flag.Activated == goAutoSDKFlagActive
			if state.restoreRequired {
				p.logGoAutoSDKError(
					"reconstructing captured Go Auto SDK state failed",
					errors.New("active flag has no retained process incarnation"),
				)
				return nil, false
			}
			incarnation, err := p.openGoAutoSDKProcessIncarnation(
				admission.processRoot,
				generation.fileInfo,
			)
			if err != nil {
				p.logGoAutoSDKError(
					"pinning captured Go Auto SDK process failed",
					err,
				)
				return nil, false
			}
			state.incarnation = incarnation
			if p.goAutoSDKFlagStates == nil {
				p.goAutoSDKFlagStates = map[runtimeMetricTargetKey]goAutoSDKFlagState{}
			}
			p.goAutoSDKFlagStates[process] = state
			return p.prepareGoAutoSDKFlagMemoryRestore(process, state)
		} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
			p.logGoAutoSDKError("looking up captured Go Auto SDK flag failed", err)
			return nil, false
		}
	}
	if p.goAutoSDKOuterCalls == nil {
		p.logGoAutoSDKError("draining captured Go Auto SDK calls failed",
			errors.New("outer-call map is unavailable"))
		return nil, false
	}
	incarnation, err := p.openGoAutoSDKProcessIncarnation(
		admission.processRoot,
		generation.fileInfo,
	)
	if err != nil {
		if goAutoSDKProcessGone(err) {
			return nil, p.discardStaleGoAutoSDKFlag(process, state)
		}
		p.logGoAutoSDKError(
			"pinning captured Go Auto SDK process failed",
			err,
		)
		return nil, false
	}
	state.incarnation = incarnation
	stale, err := p.goAutoSDKProcessIncarnationStale(state)
	if err != nil {
		p.logGoAutoSDKError(
			"checking process during captured Go Auto SDK cleanup failed", err,
		)
		p.closeGoAutoSDKProcessIncarnation(state.incarnation)
		return nil, false
	}
	if stale {
		cleanupSafe := p.discardStaleGoAutoSDKFlag(process, state)
		if !cleanupSafe {
			p.closeGoAutoSDKProcessIncarnation(state.incarnation)
		}
		return nil, cleanupSafe
	}
	p.logGoAutoSDKError(
		"reconstructing captured Go Auto SDK state failed",
		errors.New(
			"live process has no flag metadata for a potentially migrated exact counter",
		),
	)
	p.closeGoAutoSDKProcessIncarnation(state.incarnation)
	return nil, false
}

func (p *Tracer) quiesceGoAutoSDKReadiness(
	process runtimeMetricTargetKey,
	startTime uint64,
) bool {
	if p.samplerManager == nil {
		return true
	}
	if !p.samplerManager.QuiesceAutoSDKForProcess(
		process.pid, process.ns, startTime,
	) || !p.samplerManager.FallbackSafeForProcessIncarnation(
		process.pid, process.ns, startTime,
	) {
		p.logGoAutoSDKError("revoking Go Auto SDK readiness failed",
			errors.New("fallback state is not safe"))
		return false
	}
	return true
}

func (p *Tracer) waitForGoAutoSDKOuterCalls(state goAutoSDKFlagState) bool {
	for attempt := 0; attempt < goAutoSDKDrainAttempts; attempt++ {
		inFlight, err := p.goAutoSDKInflightCount(state)
		if err != nil {
			p.logGoAutoSDKError("checking in-flight Go Auto SDK calls failed", err)
			return false
		}
		if inFlight == 0 {
			return true
		}
		p.pauseGoAutoSDKDrain()
	}
	if goAutoSDKIsPendingState(state) {
		p.logGoAutoSDKError(
			"draining Go Auto SDK pre-admission calls failed",
			errors.New("global pre-admission calls remained after the bounded drain"),
		)
		return false
	}
	stale, err := p.goAutoSDKProcessIncarnationStale(state)
	if err != nil {
		p.logGoAutoSDKError("checking process during Go Auto SDK call drain failed", err)
		return false
	}
	if stale {
		if err := p.deleteGoAutoSDKOuterCalls(state); err != nil {
			p.logGoAutoSDKError("deleting stale Go Auto SDK calls failed", err)
			return false
		}
		return p.deleteGoAutoSDKInflight(state)
	}
	p.logGoAutoSDKError("draining in-flight Go Auto SDK calls failed",
		errors.New("matching calls remained after the bounded drain"))
	return false
}

func (p *Tracer) waitForGoAutoSDKPreAdmissionCalls() bool {
	if !p.goAutoSDKPreAdmissionReady {
		return false
	}
	return p.waitForGoAutoSDKOuterCalls(goAutoSDKPendingState())
}

func (p *Tracer) waitForGoAutoSDKShutdownTargets(
	targets []goAutoSDKRestoreTarget,
	budget *goAutoSDKShutdownBudget,
) bool {
	if len(targets) == 0 {
		return true
	}
	for budget.takeScan() {
		allZero := true
		for _, target := range targets {
			if !budget.available() {
				p.logGoAutoSDKError("draining in-flight Go Auto SDK calls failed",
					errors.New("shutdown deadline expired during the counter scan"))
				return false
			}
			inFlight, err := p.goAutoSDKInflightCount(target.state)
			if err != nil {
				p.logGoAutoSDKError(
					"checking in-flight Go Auto SDK calls failed", err,
				)
				return false
			}
			if inFlight != 0 {
				allZero = false
			}
		}
		if allZero {
			return true
		}
		if budget.remainingScans > 0 {
			p.pauseGoAutoSDKDrainUntil(budget.deadline)
		}
	}

	p.logGoAutoSDKError("draining in-flight Go Auto SDK calls failed",
		errors.New("matching calls remained after the bounded drain"))
	return false
}

func (p *Tracer) deleteGoAutoSDKOuterCalls(state goAutoSDKFlagState) error {
	keys, err := p.goAutoSDKOuterCallKeys(state, 0)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if err := p.goAutoSDKOuterCalls.Delete(key); err != nil &&
			!errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

func (p *Tracer) goAutoSDKOuterCallKeys(
	state goAutoSDKFlagState,
	limit int,
) ([]goAddrKey, error) {
	return p.goAutoSDKOuterCallKeysMatching(state, limit, nil)
}

func (p *Tracer) goAutoSDKOuterCallKeysMatching(
	state goAutoSDKFlagState,
	limit int,
	stateMatches func(uint8) bool,
) ([]goAddrKey, error) {
	if p.goAutoSDKOuterCalls == nil {
		return nil, errors.New("outer-call map is unavailable")
	}

	var previous goAddrKey
	first := true
	seen := map[goAddrKey]struct{}{}
	var matches []goAddrKey
	for {
		var next goAddrKey
		var previousKey any
		if !first {
			previousKey = &previous
		}
		err := p.goAutoSDKOuterCalls.NextKey(previousKey, &next)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return matches, nil
		}
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[next]; duplicate {
			return nil, errors.New("outer-call map changed during iteration")
		}
		seen[next] = struct{}{}

		var call goAutoSDKOuterCallValue
		err = p.goAutoSDKOuterCalls.Lookup(next, &call)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, err
		}
		if err == nil && next.PID == state.key.PID &&
			call.Generation == state.key.Generation &&
			call.StartTime == state.startTime &&
			(state.epoch == 0 || call.Epoch == state.epoch) &&
			(stateMatches == nil || stateMatches(call.State)) {
			matches = append(matches, next)
			if limit > 0 && len(matches) == limit {
				return matches, nil
			}
		}
		previous = next
		first = false
	}
}

func (p *Tracer) goAutoSDKProcessIncarnationStale(
	state goAutoSDKFlagState,
) (bool, error) {
	if state.incarnation == nil || state.incarnation.session == nil {
		return false, errors.New("exact process incarnation is unavailable")
	}
	startTime, err := state.incarnation.session.StartTime()
	if err != nil {
		if goAutoSDKProcessGone(err) {
			return true, nil
		}
		return false, err
	}
	return startTime != state.startTime, nil
}

func (p *Tracer) pauseGoAutoSDKDrain() {
	if p.goAutoSDKDrainPause != nil {
		p.goAutoSDKDrainPause()
		return
	}
	time.Sleep(goAutoSDKDrainInterval)
}

func (p *Tracer) pauseGoAutoSDKDrainUntil(deadline time.Time) {
	if p.goAutoSDKDrainPause != nil {
		p.goAutoSDKDrainPause()
		return
	}
	delay := min(goAutoSDKDrainInterval, time.Until(deadline))
	if delay > 0 {
		time.Sleep(delay)
	}
}

func (p *Tracer) discardStaleGoAutoSDKFlag(
	process runtimeMetricTargetKey,
	state goAutoSDKFlagState,
) bool {
	if !p.quiesceGoAutoSDKReadiness(process, state.startTime) {
		return false
	}
	if !p.waitForGoAutoSDKPreAdmissionCalls() {
		return false
	}
	if state.epoch != 0 && !p.waitForGoAutoSDKOuterCalls(state) {
		return false
	}
	if err := p.deleteGoAutoSDKOuterCalls(state); err != nil {
		p.logGoAutoSDKError("deleting stale Go Auto SDK calls failed", err)
		return false
	}
	if state.epoch != 0 && !p.deleteGoAutoSDKInflight(state) {
		return false
	}
	if p.goAutoSDKFlags != nil {
		if err := p.goAutoSDKFlags.Delete(state.key); err != nil &&
			!errors.Is(err, ebpf.ErrKeyNotExist) {
			p.logGoAutoSDKError("deleting stale Go Auto SDK flag discovery failed", err)
			return false
		}
	}
	delete(p.goAutoSDKFlagStates, process)
	p.closeGoAutoSDKProcessIncarnation(state.incarnation)
	if admission, ok := p.goProcessAdmissions[process]; ok &&
		admission.fileInfo == state.fileInfo {
		p.closeGoAutoSDKProcessRoot(admission.processRoot)
		admission.processRoot = nil
		p.goProcessAdmissions[process] = admission
	}
	if admission, ok := p.goAutoSDKAdmissions[process]; ok &&
		admission.fileInfo == state.fileInfo {
		delete(p.goAutoSDKAdmissions, process)
	}
	return true
}

func (p *Tracer) logGoAutoSDKError(message string, err error) {
	if p != nil && p.log != nil {
		p.log.Error(message, "error", err)
	}
}

type goTracerResources struct {
	tracer  *Tracer
	closeMu sync.Mutex
	mu      sync.Mutex
	closers []io.Closer
	closed  bool
}

func newGoTracerResources(tracer *Tracer, closers ...io.Closer) *goTracerResources {
	return &goTracerResources{
		tracer:  tracer,
		closers: append([]io.Closer(nil), closers...),
	}
}

func (r *goTracerResources) Add(closers ...io.Closer) {
	if r == nil || len(closers) == 0 {
		return
	}

	r.closeMu.Lock()
	defer r.closeMu.Unlock()

	r.mu.Lock()
	if !r.closed {
		r.closers = append(r.closers, closers...)
		r.mu.Unlock()
		return
	}
	r.closed = false
	r.closers = append(r.closers, closers...)
	r.mu.Unlock()

	_, err := r.closePendingClosers()
	if err != nil && r.tracer != nil {
		r.tracer.logGoAutoSDKError("closing late Go tracer resources failed", err)
	}
}

func (r *goTracerResources) Close() error {
	if r == nil {
		return nil
	}

	r.closeMu.Lock()
	defer r.closeMu.Unlock()

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()

	timeout := time.Duration(0)
	if r.tracer != nil {
		timeout = r.tracer.shutdownTimeout
	}
	if timeout <= 0 {
		timeout = goAutoSDKDrainAttempts * goAutoSDKDrainInterval
	}
	overallDeadline := time.Now().Add(timeout)
	autoSDKSafe := r.tracer == nil
	var closeErr error
	for time.Now().Before(overallDeadline) {
		if !autoSDKSafe {
			budget := newGoAutoSDKShutdownBudgetUntil(overallDeadline)
			autoSDKSafe = r.tracer.shutdownGoAutoSDKWithBudget(budget)
		}
		if autoSDKSafe {
			var closed bool
			closed, closeErr = r.closePendingClosers()
			if closed {
				return nil
			}
		}
		if time.Now().Before(overallDeadline) {
			if r.tracer != nil {
				r.tracer.pauseGoAutoSDKDrainUntil(overallDeadline)
			} else {
				delay := min(goAutoSDKDrainInterval, time.Until(overallDeadline))
				if delay > 0 {
					time.Sleep(delay)
				}
			}
		}
	}
	if autoSDKSafe {
		return fmt.Errorf(
			"closing Go tracer resources remained incomplete until the shutdown deadline: %w",
			closeErr,
		)
	}
	return errors.New(
		"shutdown of Go Auto SDK remained unsafe until the shutdown deadline; eBPF resources remain attached",
	)
}

func (r *goTracerResources) teardownReady() bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

func (r *goTracerResources) closePendingClosers() (bool, error) {
	r.mu.Lock()
	closers := r.closers
	r.closers = nil
	r.mu.Unlock()

	failed, closeErr := closeGoTracerClosers(closers)

	r.mu.Lock()
	r.closers = append(failed, r.closers...)
	r.closed = len(r.closers) == 0
	closed := r.closed
	r.mu.Unlock()

	return closed, closeErr
}

func closeGoTracerClosers(closers []io.Closer) ([]io.Closer, error) {
	failed := make([]io.Closer, 0, len(closers))
	var closeErr error
	for i := len(closers) - 1; i >= 0; i-- {
		if closers[i] != nil {
			if err := closers[i].Close(); err != nil {
				failed = append(failed, closers[i])
				closeErr = errors.Join(closeErr, err)
			}
		}
	}
	for left, right := 0, len(failed)-1; left < right; left, right = left+1, right-1 {
		failed[left], failed[right] = failed[right], failed[left]
	}
	return failed, closeErr
}

func waitForGoAutoSDKShutdownGroup(
	group *sync.WaitGroup,
	done *chan struct{},
	budget *goAutoSDKShutdownBudget,
) bool {
	if !budget.available() {
		return false
	}
	if *done == nil {
		*done = make(chan struct{})
		go func(done chan struct{}) {
			group.Wait()
			close(done)
		}(*done)
	}
	timer := time.NewTimer(time.Until(budget.deadline))
	defer timer.Stop()
	select {
	case <-*done:
		return true
	case <-timer.C:
		return false
	}
}

func (p *Tracer) closeGoAutoSDKEntryBarrier(
	pending []io.Closer,
	budget *goAutoSDKShutdownBudget,
	phase string,
) ([]io.Closer, bool) {
	for index, closer := range pending {
		if !budget.available() {
			return pending[index:], false
		}
		if closer == nil {
			continue
		}
		if err := closer.Close(); err != nil {
			p.logGoAutoSDKError(
				"closing Go Auto SDK "+phase+" entry probe failed",
				err,
			)
			return pending[index:], false
		}
	}
	return nil, budget.available()
}

func (p *Tracer) shutdownGoAutoSDK() bool {
	return p.shutdownGoAutoSDKWithBudget(newGoAutoSDKShutdownBudget())
}

func (p *Tracer) shutdownGoAutoSDKWithBudget(
	budget *goAutoSDKShutdownBudget,
) bool {
	if p == nil {
		return true
	}
	if !budget.available() {
		return false
	}
	p.goAutoSDKShutdownMu.Lock()
	defer p.goAutoSDKShutdownMu.Unlock()
	p.processMu.Lock()
	shutdownComplete := p.goAutoSDKShutdownComplete &&
		p.goAutoSDKDirectEntryAttaching == 0 &&
		p.goAutoSDKDirectEntryClosing == 0 &&
		len(p.goAutoSDKDirectEntryClosers) == 0 &&
		p.goAutoSDKGlobalEntryAttaching == 0 &&
		p.goAutoSDKGlobalEntryClosing == 0 &&
		len(p.goAutoSDKGlobalEntryClosers) == 0
	p.processMu.Unlock()
	if shutdownComplete {
		return true
	}
	if !budget.available() {
		return false
	}

	p.processMu.Lock()
	p.goAutoSDKShuttingDown = true
	if p.goAutoSDKQuiescing == nil {
		p.goAutoSDKQuiescing = map[runtimeMetricTargetKey]bool{}
	}
	for process := range p.goProcessGenerationByPID {
		if !budget.available() {
			p.processMu.Unlock()
			return false
		}
		p.goAutoSDKQuiescing[process] = true
	}
	// Phase 1: stop direct public Start admission while readiness remains
	// published. Every direct callback that began before Link.Close returns has
	// therefore either registered its exact count or poisoned that authority.
	p.goAutoSDKDirectEntryBarrierClosed = true
	directEntryClosers := p.goAutoSDKDirectEntryClosers
	p.goAutoSDKDirectEntryClosers = nil
	p.processMu.Unlock()

	failedDirectEntries, directEntryBarrierSafe := p.closeGoAutoSDKEntryBarrier(
		directEntryClosers,
		budget,
		"direct Start",
	)

	p.processMu.Lock()
	p.goAutoSDKDirectEntryClosers = append(
		failedDirectEntries,
		p.goAutoSDKDirectEntryClosers...,
	)
	if !directEntryBarrierSafe ||
		p.goAutoSDKDirectEntryAttaching != 0 ||
		p.goAutoSDKDirectEntryClosing != 0 ||
		len(p.goAutoSDKDirectEntryClosers) != 0 ||
		p.goAutoSDKGlobalEntryAttaching != 0 ||
		p.goAutoSDKGlobalEntryClosing != 0 {
		p.processMu.Unlock()
		return false
	}

	globalProtocolActive := len(p.goAutoSDKGlobalEntryClosers) != 0

	// Phase 2: restore and read back every owned process-global boolean while
	// global newSpan entry admission is still attached. During this interval a
	// call can no longer rely on a direct Start probe, so newSpan must remain
	// responsible for committing its exact count before it can observe true.
	targets := make([]goAutoSDKRestoreTarget, 0, len(p.goProcessGenerationByPID))
	for process := range p.goProcessGenerationByPID {
		if !budget.available() {
			p.processMu.Unlock()
			return false
		}
		var target *goAutoSDKRestoreTarget
		var cleanupSafe bool
		if state, ok := p.goAutoSDKFlagStates[process]; ok {
			target, cleanupSafe = p.prepareGoAutoSDKFlagMemoryRestore(process, state)
		} else {
			target, cleanupSafe = p.prepareCapturedGoAutoSDKFlagMemoryRestore(process)
		}
		if !cleanupSafe {
			p.processMu.Unlock()
			return false
		}
		if target != nil {
			targets = append(targets, *target)
			globalProtocolActive = globalProtocolActive || target.state.globalProtocol
		}
	}

	// Phase 3: once all booleans are observably false, synchronously detach the
	// global entry probes. Their return probes stay attached so every admitted
	// capture can retire its exact count.
	p.goAutoSDKGlobalEntryBarrierClosed = true
	globalEntryClosers := p.goAutoSDKGlobalEntryClosers
	p.goAutoSDKGlobalEntryClosers = nil
	p.processMu.Unlock()

	failedGlobalEntries, globalEntryBarrierSafe := p.closeGoAutoSDKEntryBarrier(
		globalEntryClosers,
		budget,
		"global newSpan",
	)

	p.processMu.Lock()
	p.goAutoSDKGlobalEntryClosers = append(
		failedGlobalEntries,
		p.goAutoSDKGlobalEntryClosers...,
	)
	if !globalEntryBarrierSafe ||
		p.goAutoSDKGlobalEntryAttaching != 0 ||
		p.goAutoSDKGlobalEntryClosing != 0 ||
		len(p.goAutoSDKGlobalEntryClosers) != 0 {
		p.processMu.Unlock()
		return false
	}

	// Phase 4: with both entry barriers closed and M=false, publish quiescing
	// state and revoke readiness. No new callback can acquire either lifetime
	// protocol after this point.
	for _, target := range targets {
		if !budget.available() ||
			!p.quiesceGoAutoSDKRestoreTarget(target) {
			p.processMu.Unlock()
			return false
		}
	}

	// Phase 5: after entry detachment is synchronous, first drain the global
	// PRE latch. Only then can no callback still migrate ownership into an old
	// exact counter between its zero scan and deletion. The reserved latch is
	// retained until map teardown and is never reset or stale-deleted.
	if globalProtocolActive {
		if !p.goAutoSDKPreAdmissionReady {
			p.processMu.Unlock()
			return false
		}
		pending := goAutoSDKRestoreTarget{
			state: goAutoSDKPendingState(),
		}
		inFlight, err := p.goAutoSDKInflightCount(pending.state)
		if err != nil {
			p.logGoAutoSDKError(
				"checking Go Auto SDK pre-admission latch failed",
				err,
			)
			p.processMu.Unlock()
			return false
		}
		if inFlight != 0 && !p.waitForGoAutoSDKShutdownTargets(
			[]goAutoSDKRestoreTarget{pending},
			budget,
		) {
			p.processMu.Unlock()
			return false
		}
	}

	// With PRE at zero, drain the exact counters before deleting their
	// flag/counter state. All return probes remain available throughout.
	if !p.waitForGoAutoSDKShutdownTargets(targets, budget) {
		p.processMu.Unlock()
		return false
	}
	for _, target := range targets {
		if !budget.available() {
			p.processMu.Unlock()
			return false
		}
		if !p.finishGoAutoSDKFlagRestore(target) {
			p.processMu.Unlock()
			return false
		}
		p.disableRestoredGoAutoSDKAdmissionLocked(
			target.process,
			target.state.startTime,
			target.state.fileInfo,
		)
	}

	reader := p.goAutoSDKEventReader
	p.goAutoSDKDiscoveryReady = false
	p.processMu.Unlock()

	if !budget.available() {
		return false
	}
	if reader != nil {
		if err := reader.Close(); err != nil {
			p.logGoAutoSDKError("closing Go Auto SDK flag discovery failed", err)
			return false
		}
		p.processMu.Lock()
		if p.goAutoSDKEventReader == reader {
			p.goAutoSDKEventReader = nil
		}
		p.processMu.Unlock()
	}
	if !budget.available() {
		return false
	}
	if !waitForGoAutoSDKShutdownGroup(
		&p.goAutoSDKEventWG,
		&p.goAutoSDKEventDone,
		budget,
	) || !waitForGoAutoSDKShutdownGroup(
		&p.goAutoSDKRestoreRetryWG,
		&p.goAutoSDKRestoreRetryDone,
		budget,
	) {
		return false
	}
	p.processMu.Lock()
	if p.goAutoSDKDirectEntryAttaching != 0 ||
		p.goAutoSDKDirectEntryClosing != 0 ||
		len(p.goAutoSDKDirectEntryClosers) != 0 ||
		p.goAutoSDKGlobalEntryAttaching != 0 ||
		p.goAutoSDKGlobalEntryClosing != 0 ||
		len(p.goAutoSDKGlobalEntryClosers) != 0 {
		p.processMu.Unlock()
		return false
	}
	clear(p.goAutoSDKRestoreRetries)
	clear(p.goProcessAdmissionRetries)
	for process, admission := range p.goProcessAdmissions {
		p.closeGoAutoSDKProcessRoot(admission.processRoot)
		delete(p.goProcessAdmissions, process)
	}
	p.goAutoSDKShutdownComplete = true
	p.processMu.Unlock()
	return true
}
