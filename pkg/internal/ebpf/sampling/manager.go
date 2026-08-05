// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sampling // import "go.opentelemetry.io/obi/pkg/internal/ebpf/sampling"

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

type bpfMap interface {
	Put(key, value any) error
	Lookup(key, valueOut any) error
	Delete(key any) error
}

type resourceMapIdentity struct {
	kernelID ebpf.MapID
	fallback bpfMap
}

type resourceMapIdentityProvider interface {
	resourceMapIdentity() (resourceMapIdentity, bool)
}

type identifiedMap struct {
	target      bpfMap
	identity    resourceMapIdentity
	identityErr error
}

func (m *identifiedMap) Put(key, value any) error {
	if err := m.mapIdentityError(); err != nil {
		return err
	}
	return m.target.Put(key, value)
}

func (m *identifiedMap) Lookup(key, valueOut any) error {
	if err := m.mapIdentityError(); err != nil {
		return err
	}
	return m.target.Lookup(key, valueOut)
}

func (m *identifiedMap) Delete(key any) error {
	if err := m.mapIdentityError(); err != nil {
		return err
	}
	return m.target.Delete(key)
}

func (m *identifiedMap) resourceMapIdentity() (resourceMapIdentity, bool) {
	if m.mapIdentityError() != nil {
		return resourceMapIdentity{}, false
	}
	return m.identity, true
}

func (m *identifiedMap) mapIdentityError() error {
	if m == nil {
		return errMapIdentityUnknown
	}
	if m.identityErr != nil {
		return m.identityErr
	}
	if m.identity.kernelID == 0 {
		return errMapIdentityUnknown
	}
	return nil
}

type hostPIDResolver func(app.PID) (uint32, error)

type processKey struct {
	pid app.PID
	ns  uint32
}

type cleanupDebtKind uint8

const (
	cleanupDebtSampler cleanupDebtKind = 1 << iota
	cleanupDebtAutoSDK
)

type cleanupDebt struct {
	hostPID     uint32
	startTime   uint64
	kind        cleanupDebtKind
	unknownHost bool
}

type resourceOwnershipKey struct {
	target  resourceMapIdentity
	hostPID uint32
}

type resourceOwnership struct {
	managerID uint64
	startTime uint64
}

const cleanupAttempts = 2

var (
	autoSDKActivationEpoch  uint32
	samplerPublicationEpoch uint32
	errMapIdentityUnknown   = errors.New("stable BPF map identity is unavailable")
	managerIDSequence       uint64
	lifecycleMu             sync.Mutex
	// resourceOwners is userspace-only and serialized with BPF map lifecycle changes.
	resourceOwners = map[resourceOwnershipKey]resourceOwnership{}
)

type Manager struct {
	id        uint64
	log       *slog.Logger
	global    bpfMap
	overrides bpfMap
	ready     bpfMap
	autoReady bpfMap
	config    BPFConfig
	sampler   services.CanonicalSampler
	resolve   hostPIDResolver

	mu           sync.RWMutex
	globalReady  bool
	hostPIDs     map[processKey]uint32
	startTimes   map[processKey]uint64
	hostOwners   map[uint32]processKey
	readyPIDs    map[uint32]BPFProcessReadiness
	cleanupDebts map[processKey]map[cleanupDebt]struct{}
}

func NewManager(
	log *slog.Logger,
	global *ebpf.Map,
	overrides *ebpf.Map,
	ready *ebpf.Map,
	autoReady *ebpf.Map,
	config services.CanonicalSampler,
) *Manager {
	return newManager(
		log,
		optionalMap(global),
		optionalMap(overrides),
		optionalMap(ready),
		optionalMap(autoReady),
		config,
		resolveHostPID,
	)
}

func optionalMap(target *ebpf.Map) bpfMap {
	if target == nil {
		return nil
	}
	identified := &identifiedMap{target: target}
	info, err := target.Info()
	if err != nil {
		identified.identityErr = fmt.Errorf("%w: %w", errMapIdentityUnknown, err)
		return identified
	}
	id, ok := info.ID()
	if !ok || id == 0 {
		identified.identityErr = errMapIdentityUnknown
		return identified
	}
	identified.identity.kernelID = id
	return identified
}

func newManager(
	log *slog.Logger,
	global bpfMap,
	overrides bpfMap,
	ready bpfMap,
	autoReady bpfMap,
	config services.CanonicalSampler,
	resolve hostPIDResolver,
) *Manager {
	return &Manager{
		id:           atomic.AddUint64(&managerIDSequence, 1),
		log:          log,
		global:       global,
		overrides:    overrides,
		ready:        ready,
		autoReady:    autoReady,
		config:       toBPFConfig(config),
		sampler:      config,
		resolve:      resolve,
		hostPIDs:     map[processKey]uint32{},
		startTimes:   map[processKey]uint64{},
		hostOwners:   map[uint32]processKey{},
		readyPIDs:    map[uint32]BPFProcessReadiness{},
		cleanupDebts: map[processKey]map[cleanupDebt]struct{}{},
	}
}

func (m *Manager) InstallGlobal() bool {
	if m == nil {
		return false
	}
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()

	if m.global == nil {
		m.logError("installing global sampler failed",
			"sampler", m.sampler, "error", errors.New("sampler map is unavailable"))
		return false
	}
	if m.config.Type == uint8(services.SamplerTypeInvalid) {
		m.logError("installing global sampler failed",
			"sampler", m.sampler, "error", errors.New("invalid canonical sampler"))
		return false
	}

	const key uint32 = 0
	var existing BPFConfig
	if err := m.global.Lookup(key, &existing); err == nil {
		if existing.Type != uint8(services.SamplerTypeInvalid) &&
			existing.PublicationEpoch != 0 {
			config := m.config
			config.PublicationEpoch = existing.PublicationEpoch
			if existing != config {
				m.logError("installing global sampler failed",
					"sampler", m.sampler,
					"error", errors.New("a different global sampler is already published"))
				return false
			}
			m.mu.Lock()
			m.config = existing
			m.globalReady = true
			m.mu.Unlock()
			return true
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		m.logError("installing global sampler failed", "sampler", m.sampler, "error", err)
		return false
	}

	epoch, ok := nextSamplerPublicationEpoch()
	if !ok {
		m.logError("installing global sampler failed",
			"sampler", m.sampler,
			"error", errors.New("sampler publication epoch exhausted"))
		return false
	}
	config := m.config
	config.PublicationEpoch = epoch
	if err := m.global.Put(key, config); err != nil {
		m.logError("installing global sampler failed", "sampler", m.sampler, "error", err)
		return false
	}

	m.mu.Lock()
	m.config = config
	m.globalReady = true
	m.mu.Unlock()
	return true
}

// FallbackSafeForProcess conservatively checks all known incarnations of a process key.
func (m *Manager) FallbackSafeForProcess(pid app.PID, ns uint32) bool {
	return m.FallbackSafeForProcessIncarnation(pid, ns, 0)
}

// FallbackSafeForProcessIncarnation reports whether primary instrumentation can
// use userspace sampling without stale eBPF or Auto SDK state for this process.
func (m *Manager) FallbackSafeForProcessIncarnation(
	pid app.PID,
	ns uint32,
	startTime uint64,
) bool {
	if m == nil {
		return true
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for debt := range m.cleanupDebts[processKey{pid: pid, ns: ns}] {
		if startTime == 0 || debt.startTime == 0 || debt.startTime == startTime {
			return false
		}
	}
	return true
}

func (m *Manager) AllowPID(
	pid app.PID,
	ns uint32,
	override *services.CanonicalSampler,
	enableAutoSDK bool,
) bool {
	return m.AllowPIDForProcess(pid, ns, 0, override, enableAutoSDK)
}

func (m *Manager) AllowPIDForProcess(
	pid app.PID,
	ns uint32,
	startTime uint64,
	override *services.CanonicalSampler,
	enableAutoSDK bool,
) bool {
	if m == nil || !m.isGlobalReady() {
		return false
	}
	key := processKey{pid: pid, ns: ns}
	if startTime == 0 {
		m.mu.RLock()
		hostPID, tracked := m.hostPIDs[key]
		trackedStartTime := m.startTimes[key]
		m.mu.RUnlock()
		if tracked {
			m.addCleanupDebt(key, cleanupDebt{
				hostPID:   hostPID,
				startTime: trackedStartTime,
				kind:      cleanupDebtSampler | cleanupDebtAutoSDK,
			})
		}
		m.logError("enabling PID sampler failed",
			"pid", pid, "namespace", ns, "error", errors.New("process start time is unavailable"))
		return false
	}
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()

	m.mu.RLock()
	previousHostPID, previouslyAllowed := m.hostPIDs[key]
	previousStartTime := m.startTimes[key]
	m.mu.RUnlock()

	hostPID, err := m.resolve(pid)
	if err != nil {
		if previouslyAllowed {
			m.disableProcess(key, previousHostPID, previousStartTime)
			m.addCleanupDebt(key, cleanupDebt{
				startTime:   startTime,
				kind:        cleanupDebtSampler | cleanupDebtAutoSDK,
				unknownHost: true,
			})
		}
		m.logError("resolving sampler PID failed", "pid", pid, "namespace", ns, "error", err)
		return false
	}

	if previouslyAllowed && previousHostPID != hostPID {
		_, cleanupComplete := m.cleanupHostPID(previousHostPID, previousStartTime)
		if !cleanupComplete {
			m.addCleanupDebt(key, cleanupDebt{
				hostPID:   previousHostPID,
				startTime: previousStartTime,
				kind:      cleanupDebtSampler | cleanupDebtAutoSDK,
			})
			m.addCleanupDebt(key, cleanupDebt{
				hostPID:   hostPID,
				startTime: startTime,
				kind:      cleanupDebtSampler | cleanupDebtAutoSDK,
			})
			m.addCleanupDebt(key, cleanupDebt{
				startTime:   startTime,
				kind:        cleanupDebtSampler | cleanupDebtAutoSDK,
				unknownHost: true,
			})
			m.logError("cleaning remapped PID sampler failed",
				"pid", pid, "old_host_pid", previousHostPID, "host_pid", hostPID, "namespace", ns)
			return false
		}
		m.forgetHostPID(key, previousHostPID)
		m.clearCleanupDebtsForKeyHost(
			key,
			previousHostPID,
			previousStartTime,
			cleanupDebtSampler|cleanupDebtAutoSDK,
		)
	}
	m.claimProcessOwnership(hostPID, startTime)
	m.trackHostPID(key, hostPID, startTime)

	if !m.unpublishProcess(hostPID, startTime) {
		m.disableProcess(key, hostPID, startTime)
		return false
	}

	epoch, ok := nextSamplerPublicationEpoch()
	if !ok {
		m.disableProcess(key, hostPID, startTime)
		m.logError("enabling PID sampler failed",
			"pid", pid, "host_pid", hostPID, "namespace", ns,
			"sampler", m.effectiveSampler(override),
			"error", errors.New("sampler publication epoch exhausted"))
		return false
	}
	configEpoch := m.config.PublicationEpoch
	if override != nil {
		configEpoch = epoch
	}
	if configEpoch == 0 {
		m.disableProcess(key, hostPID, startTime)
		m.logError("enabling PID sampler failed",
			"pid", pid, "host_pid", hostPID, "namespace", ns,
			"sampler", m.effectiveSampler(override),
			"error", errors.New("global sampler publication is unavailable"))
		return false
	}
	if err := m.installOverride(hostPID, startTime, override, configEpoch); err != nil {
		m.disableProcess(key, hostPID, startTime)
		m.logError("installing PID sampler failed",
			"pid", pid, "host_pid", hostPID, "namespace", ns,
			"sampler", m.effectiveSampler(override), "error", err)
		return false
	}

	if m.ready == nil {
		m.disableProcess(key, hostPID, startTime)
		m.logError("enabling PID sampler failed",
			"pid", pid, "host_pid", hostPID, "namespace", ns,
			"sampler", m.effectiveSampler(override),
			"error", errors.New("sampler readiness map is unavailable"))
		return false
	}
	readiness := BPFProcessReadiness{
		StartTime:   startTime,
		Epoch:       epoch,
		ConfigEpoch: configEpoch,
		Ready:       1,
	}
	if err := m.ready.Put(hostPID, readiness); err != nil {
		m.disableProcess(key, hostPID, startTime)
		m.logError("enabling PID sampler failed",
			"pid", pid, "host_pid", hostPID, "namespace", ns,
			"sampler", m.effectiveSampler(override), "error", err)
		return false
	}
	m.claimResourceOwnership(m.ready, hostPID, startTime)

	m.mu.Lock()
	m.readyPIDs[hostPID] = readiness
	m.mu.Unlock()
	m.clearCleanupDebtsForKeyHost(
		key,
		hostPID,
		startTime,
		cleanupDebtSampler|cleanupDebtAutoSDK,
	)
	m.clearUnknownCleanupDebts(
		key,
		startTime,
		cleanupDebtSampler|cleanupDebtAutoSDK,
	)

	if !enableAutoSDK {
		return true
	}

	return m.enableAutoSDK(pid, ns, true, nil)
}

func (m *Manager) EnableAutoSDK(pid app.PID, ns uint32) bool {
	return m.EnableAutoSDKWithSetup(pid, ns, nil)
}

func (m *Manager) EnableAutoSDKWithSetup(
	pid app.PID,
	ns uint32,
	beforePublish func(hostPID uint32, startTime uint64, epoch uint32) bool,
) bool {
	return m.EnableAutoSDKWithSetupMode(pid, ns, true, beforePublish)
}

func (m *Manager) EnableAutoSDKWithSetupMode(
	pid app.PID,
	ns uint32,
	globalProtocol bool,
	beforePublish func(hostPID uint32, startTime uint64, epoch uint32) bool,
) bool {
	if m == nil {
		return false
	}
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	return m.enableAutoSDK(pid, ns, globalProtocol, beforePublish)
}

func (m *Manager) DisableAutoSDK(pid app.PID, ns uint32) bool {
	if m == nil {
		return false
	}
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()

	key := processKey{pid: pid, ns: ns}
	m.mu.RLock()
	hostPID, ok := m.hostPIDs[key]
	startTime := m.startTimes[key]
	m.mu.RUnlock()
	if !ok {
		return false
	}

	return m.deleteAutoReady(hostPID, startTime)
}

func (m *Manager) QuiesceAutoSDKForProcess(
	pid app.PID,
	ns uint32,
	startTime uint64,
) bool {
	if m == nil {
		return false
	}
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()

	key := processKey{pid: pid, ns: ns}
	if m.autoReady == nil {
		m.clearUnknownCleanupDebts(key, startTime, cleanupDebtAutoSDK)
		return true
	}

	m.mu.RLock()
	hostPID, tracked := m.hostPIDs[key]
	trackedStartTime := m.startTimes[key]
	m.mu.RUnlock()
	if tracked {
		if startTime != 0 && startTime != trackedStartTime {
			return true
		}
		startTime = trackedStartTime
	} else {
		var err error
		hostPID, err = m.resolve(pid)
		if err != nil {
			m.addCleanupDebt(key, cleanupDebt{
				startTime:   startTime,
				kind:        cleanupDebtAutoSDK,
				unknownHost: true,
			})
			m.logError("resolving Go Auto SDK PID failed",
				"pid", pid, "namespace", ns, "error", err)
			return false
		}
	}
	m.mu.RLock()
	owner, owned := m.hostOwners[hostPID]
	m.mu.RUnlock()
	if owned && owner != key {
		m.addCleanupDebt(key, cleanupDebt{
			hostPID:   hostPID,
			startTime: startTime,
			kind:      cleanupDebtAutoSDK,
		})
		return false
	}
	quiesced := m.deleteAutoReady(hostPID, startTime)
	if quiesced {
		m.clearCleanupDebtsForKeyHost(
			key,
			hostPID,
			startTime,
			cleanupDebtAutoSDK,
		)
		m.clearUnknownCleanupDebts(key, startTime, cleanupDebtAutoSDK)
	} else {
		m.addCleanupDebt(key, cleanupDebt{
			hostPID:   hostPID,
			startTime: startTime,
			kind:      cleanupDebtAutoSDK,
		})
	}
	return quiesced
}

func (m *Manager) enableAutoSDK(
	pid app.PID,
	ns uint32,
	globalProtocol bool,
	beforePublish func(hostPID uint32, startTime uint64, epoch uint32) bool,
) bool {
	key := processKey{pid: pid, ns: ns}
	m.mu.RLock()
	hostPID, ok := m.hostPIDs[key]
	var readiness BPFProcessReadiness
	if ok {
		readiness, ok = m.readyPIDs[hostPID]
	}
	m.mu.RUnlock()
	if !ok {
		return false
	}

	if m.autoReady == nil {
		return false
	}
	if !m.ownsResource(m.ready, hostPID, readiness.StartTime) {
		return false
	}
	epoch, ok := nextAutoSDKActivationEpoch()
	if !ok {
		m.logError("enabling Go Auto SDK failed",
			"pid", pid, "host_pid", hostPID, "namespace", ns,
			"error", errors.New("activation epoch exhausted"))
		return false
	}
	if beforePublish != nil &&
		!beforePublish(hostPID, readiness.StartTime, epoch) {
		m.logError("enabling Go Auto SDK failed",
			"pid", pid, "host_pid", hostPID, "namespace", ns,
			"error", errors.New("preparing Go Auto SDK in-flight state failed"))
		return false
	}
	m.claimResourceOwnership(m.autoReady, hostPID, readiness.StartTime)
	readiness.Epoch = epoch
	readiness.AutoSDKGlobalReady = 0
	if globalProtocol {
		readiness.AutoSDKGlobalReady = 1
	}
	if err := m.autoReady.Put(hostPID, readiness); err != nil {
		quiesced := m.deleteAutoReady(hostPID, readiness.StartTime)
		if quiesced {
			m.clearCleanupDebtsForKeyHost(
				key,
				hostPID,
				readiness.StartTime,
				cleanupDebtAutoSDK,
			)
			m.clearUnknownCleanupDebts(
				key,
				readiness.StartTime,
				cleanupDebtAutoSDK,
			)
		} else {
			m.addCleanupDebt(key, cleanupDebt{
				hostPID:   hostPID,
				startTime: readiness.StartTime,
				kind:      cleanupDebtAutoSDK,
			})
		}
		m.logError("enabling Go Auto SDK failed",
			"pid", pid, "host_pid", hostPID, "namespace", ns, "error", err)
		return false
	}
	m.clearCleanupDebtsForKeyHost(
		key,
		hostPID,
		readiness.StartTime,
		cleanupDebtAutoSDK,
	)
	m.clearUnknownCleanupDebts(key, readiness.StartTime, cleanupDebtAutoSDK)
	return true
}

func nextAutoSDKActivationEpoch() (uint32, bool) {
	for {
		current := atomic.LoadUint32(&autoSDKActivationEpoch)
		// The maximal value is reserved for the pre-readiness NewSpan
		// admission counter and must never be published as a live epoch.
		if current >= ^uint32(0)-1 {
			return 0, false
		}
		next := current + 1
		if atomic.CompareAndSwapUint32(&autoSDKActivationEpoch, current, next) {
			return next, true
		}
	}
}

func nextSamplerPublicationEpoch() (uint32, bool) {
	for {
		current := atomic.LoadUint32(&samplerPublicationEpoch)
		if current == ^uint32(0) {
			return 0, false
		}
		next := current + 1
		if atomic.CompareAndSwapUint32(&samplerPublicationEpoch, current, next) {
			return next, true
		}
	}
}

func (m *Manager) BlockPID(pid app.PID, ns uint32) bool {
	return m.BlockPIDForProcess(pid, ns, 0)
}

func (m *Manager) BlockPIDForProcess(pid app.PID, ns uint32, startTime uint64) bool {
	if m == nil {
		return false
	}
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()

	key := processKey{pid: pid, ns: ns}
	m.mu.RLock()
	hostPID, ok := m.hostPIDs[key]
	trackedStartTime := m.startTimes[key]
	m.mu.RUnlock()
	if ok && startTime != 0 && startTime != trackedStartTime {
		return true
	}

	autoSDKQuiesced, debtsCleared := m.retryCleanupDebts(key, startTime)
	if !debtsCleared {
		return autoSDKQuiesced
	}

	if !ok {
		if m.autoReady == nil {
			return true
		}
		hostPID, err := m.resolve(pid)
		if err != nil {
			m.addCleanupDebt(key, cleanupDebt{
				startTime:   startTime,
				kind:        cleanupDebtAutoSDK,
				unknownHost: true,
			})
			return false
		}
		m.mu.RLock()
		owner, owned := m.hostOwners[hostPID]
		m.mu.RUnlock()
		if owned && owner != key {
			m.addCleanupDebt(key, cleanupDebt{
				hostPID:   hostPID,
				startTime: startTime,
				kind:      cleanupDebtAutoSDK,
			})
			return false
		}
		if startTime == 0 {
			m.addCleanupDebt(key, cleanupDebt{
				hostPID: hostPID,
				kind:    cleanupDebtAutoSDK,
			})
			return false
		}
		quiesced := m.deleteAutoReady(hostPID, startTime)
		if quiesced {
			m.clearCleanupDebtsForKeyHost(
				key,
				hostPID,
				startTime,
				cleanupDebtAutoSDK,
			)
			m.clearUnknownCleanupDebts(key, startTime, cleanupDebtAutoSDK)
		} else {
			m.addCleanupDebt(key, cleanupDebt{
				hostPID:   hostPID,
				startTime: startTime,
				kind:      cleanupDebtAutoSDK,
			})
		}
		return quiesced
	}

	autoSDKQuiesced, cleanupComplete := m.cleanupHostPID(hostPID, trackedStartTime)
	if cleanupComplete {
		m.forgetHostPID(key, hostPID)
		m.clearCleanupDebtsForKeyHost(
			key,
			hostPID,
			trackedStartTime,
			cleanupDebtSampler|cleanupDebtAutoSDK,
		)
	} else {
		m.addCleanupDebt(key, cleanupDebt{
			hostPID:   hostPID,
			startTime: trackedStartTime,
			kind:      cleanupDebtSampler | cleanupDebtAutoSDK,
		})
	}
	return autoSDKQuiesced
}

func (m *Manager) trackHostPID(key processKey, hostPID uint32, startTime uint64) {
	m.mu.Lock()
	if owner, ok := m.hostOwners[hostPID]; ok && owner != key {
		delete(m.hostPIDs, owner)
		delete(m.startTimes, owner)
	}
	m.hostPIDs[key] = hostPID
	m.startTimes[key] = startTime
	m.hostOwners[hostPID] = key
	m.mu.Unlock()
}

func (m *Manager) claimProcessOwnership(hostPID uint32, startTime uint64) {
	m.claimResourceOwnership(m.ready, hostPID, startTime)
	m.claimResourceOwnership(m.autoReady, hostPID, startTime)
}

func (m *Manager) claimResourceOwnership(
	target bpfMap,
	hostPID uint32,
	startTime uint64,
) {
	if target == nil {
		return
	}
	identity, ok := mapIdentity(target)
	if !ok {
		return
	}
	resourceOwners[resourceOwnershipKey{target: identity, hostPID: hostPID}] = resourceOwnership{
		managerID: m.id,
		startTime: startTime,
	}
}

func (m *Manager) ownsResource(target bpfMap, hostPID uint32, startTime uint64) bool {
	if target == nil {
		return false
	}
	identity, ok := mapIdentity(target)
	if !ok {
		return false
	}
	owner, ok := resourceOwners[resourceOwnershipKey{target: identity, hostPID: hostPID}]
	return ok && owner == (resourceOwnership{managerID: m.id, startTime: startTime})
}

func (m *Manager) canModifyResource(
	target bpfMap,
	hostPID uint32,
	startTime uint64,
) (bool, bool) {
	if target == nil {
		return true, true
	}
	identity, known := mapIdentity(target)
	if !known {
		return false, false
	}
	owner, ok := resourceOwners[resourceOwnershipKey{target: identity, hostPID: hostPID}]
	return !ok || owner == (resourceOwnership{managerID: m.id, startTime: startTime}), true
}

func (m *Manager) releaseResourceOwnership(
	target bpfMap,
	hostPID uint32,
	startTime uint64,
) {
	if !m.ownsResource(target, hostPID, startTime) {
		return
	}
	identity, ok := mapIdentity(target)
	if !ok {
		return
	}
	delete(resourceOwners, resourceOwnershipKey{target: identity, hostPID: hostPID})
}

func mapIdentity(target bpfMap) (resourceMapIdentity, bool) {
	if target == nil {
		return resourceMapIdentity{}, false
	}
	if provider, ok := target.(resourceMapIdentityProvider); ok {
		return provider.resourceMapIdentity()
	}
	return resourceMapIdentity{fallback: target}, true
}

func (m *Manager) forgetHostPID(key processKey, hostPID uint32) {
	m.mu.Lock()
	if currentHostPID, exists := m.hostPIDs[key]; exists && currentHostPID == hostPID {
		delete(m.hostPIDs, key)
		delete(m.startTimes, key)
	}
	if owner, exists := m.hostOwners[hostPID]; exists && owner == key {
		delete(m.hostOwners, hostPID)
	}
	m.mu.Unlock()
}

func (m *Manager) installOverride(
	hostPID uint32,
	startTime uint64,
	override *services.CanonicalSampler,
	publicationEpoch uint32,
) error {
	if m.overrides == nil {
		if override == nil {
			return nil
		}
		return errors.New("sampler override map is unavailable")
	}
	if override == nil {
		err := m.overrides.Delete(hostPID)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("removing stale override: %w", err)
		}
		m.claimResourceOwnership(m.overrides, hostPID, startTime)
		return nil
	}
	config := toBPFConfig(*override)
	if config.Type == uint8(services.SamplerTypeInvalid) {
		return errors.New("invalid canonical sampler")
	}
	config.PublicationEpoch = publicationEpoch
	if err := m.overrides.Put(hostPID, config); err != nil {
		return err
	}
	m.claimResourceOwnership(m.overrides, hostPID, startTime)
	return nil
}

func (m *Manager) effectiveSampler(override *services.CanonicalSampler) services.CanonicalSampler {
	if override != nil {
		return *override
	}
	return m.sampler
}

func (m *Manager) disableProcess(key processKey, hostPID uint32, startTime uint64) bool {
	_, cleanupComplete := m.cleanupHostPID(hostPID, startTime)
	if cleanupComplete {
		m.forgetHostPID(key, hostPID)
		m.clearCleanupDebtsForKeyHost(
			key,
			hostPID,
			startTime,
			cleanupDebtSampler|cleanupDebtAutoSDK,
		)
	} else {
		m.addCleanupDebt(key, cleanupDebt{
			hostPID:   hostPID,
			startTime: startTime,
			kind:      cleanupDebtSampler | cleanupDebtAutoSDK,
		})
	}
	return cleanupComplete
}

func (m *Manager) addCleanupDebt(key processKey, debt cleanupDebt) {
	m.mu.Lock()
	if m.cleanupDebts[key] == nil {
		m.cleanupDebts[key] = map[cleanupDebt]struct{}{}
	}
	m.cleanupDebts[key][debt] = struct{}{}
	m.mu.Unlock()
}

func (m *Manager) clearUnknownCleanupDebts(
	key processKey,
	startTime uint64,
	kind cleanupDebtKind,
) {
	m.mu.Lock()
	defer m.mu.Unlock()

	debts := m.cleanupDebts[key]
	for debt := range debts {
		if startTime != 0 && debt.startTime != 0 && debt.startTime != startTime {
			continue
		}
		if !debt.unknownHost {
			continue
		}
		remaining := debt.kind &^ kind
		if remaining == debt.kind {
			continue
		}
		delete(debts, debt)
		if remaining != 0 {
			debt.kind = remaining
			debts[debt] = struct{}{}
		}
	}
	if len(debts) == 0 {
		delete(m.cleanupDebts, key)
	}
}

func (m *Manager) clearCleanupDebtsForKeyHost(
	key processKey,
	hostPID uint32,
	startTime uint64,
	kind cleanupDebtKind,
) {
	m.mu.Lock()
	defer m.mu.Unlock()

	debts := m.cleanupDebts[key]
	for debt := range debts {
		if debt.unknownHost || debt.hostPID != hostPID ||
			(startTime != 0 && debt.startTime != 0 && debt.startTime != startTime) {
			continue
		}
		remaining := debt.kind &^ kind
		if remaining == debt.kind {
			continue
		}
		delete(debts, debt)
		if remaining != 0 {
			debt.kind = remaining
			debts[debt] = struct{}{}
		}
	}
	if len(debts) == 0 {
		delete(m.cleanupDebts, key)
	}
}

func (m *Manager) cleanupDebtsForIncarnation(
	key processKey,
	startTime uint64,
) []cleanupDebt {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var debts []cleanupDebt
	for debt := range m.cleanupDebts[key] {
		if startTime == 0 || debt.startTime == 0 || debt.startTime == startTime {
			debts = append(debts, debt)
		}
	}
	return debts
}

func (m *Manager) removeCleanupDebt(key processKey, debt cleanupDebt) {
	m.mu.Lock()
	debts := m.cleanupDebts[key]
	delete(debts, debt)
	if len(debts) == 0 {
		delete(m.cleanupDebts, key)
	}
	m.mu.Unlock()
}

func (m *Manager) retryCleanupDebts(
	key processKey,
	startTime uint64,
) (bool, bool) {
	autoSDKQuiesced := true
	cleanupComplete := true
	for _, debt := range m.cleanupDebtsForIncarnation(key, startTime) {
		hostPID := debt.hostPID
		if debt.unknownHost {
			resolvedHostPID, err := m.resolve(key.pid)
			if err != nil {
				autoSDKQuiesced = false
				cleanupComplete = false
				continue
			}
			hostPID = resolvedHostPID
		}

		m.mu.RLock()
		owner, owned := m.hostOwners[hostPID]
		m.mu.RUnlock()
		if owned && owner != key {
			autoSDKQuiesced = false
			cleanupComplete = false
			continue
		}

		debtAutoSDKQuiesced := true
		debtCleanupComplete := true
		if debt.kind&cleanupDebtSampler != 0 {
			debtAutoSDKQuiesced, debtCleanupComplete = m.cleanupHostPID(
				hostPID,
				debt.startTime,
			)
		} else if debt.kind&cleanupDebtAutoSDK != 0 {
			debtAutoSDKQuiesced = m.deleteAutoReady(hostPID, debt.startTime)
			debtCleanupComplete = debtAutoSDKQuiesced
		}
		autoSDKQuiesced = autoSDKQuiesced && debtAutoSDKQuiesced
		cleanupComplete = cleanupComplete && debtCleanupComplete
		if !debtCleanupComplete {
			if debt.unknownHost {
				m.addCleanupDebt(key, cleanupDebt{
					hostPID:   hostPID,
					startTime: debt.startTime,
					kind:      debt.kind,
				})
			}
			continue
		}

		m.removeCleanupDebt(key, debt)
		m.clearCleanupDebtsForKeyHost(
			key,
			hostPID,
			debt.startTime,
			debt.kind,
		)
	}

	return autoSDKQuiesced,
		cleanupComplete && m.FallbackSafeForProcessIncarnation(
			key.pid,
			key.ns,
			startTime,
		)
}

func (m *Manager) unpublishProcess(hostPID uint32, startTime uint64) bool {
	m.mu.Lock()
	delete(m.readyPIDs, hostPID)
	m.mu.Unlock()

	autoReadyCleared := m.deleteAutoReady(hostPID, startTime)
	readyCleared := m.deleteReady(hostPID, startTime)
	return autoReadyCleared && readyCleared
}

func (m *Manager) cleanupHostPID(hostPID uint32, startTime uint64) (bool, bool) {
	m.mu.Lock()
	delete(m.readyPIDs, hostPID)
	m.mu.Unlock()

	autoReadyCleared := false
	for range cleanupAttempts {
		overrideOwned, overrideOwnershipVerified := m.overrideOwnedByProcess(hostPID, startTime)
		if !autoReadyCleared {
			autoReadyCleared = m.deleteAutoReady(hostPID, startTime)
		}
		readyCleared := m.deleteReady(hostPID, startTime)
		overrideCleared := overrideOwnershipVerified
		if overrideOwned {
			overrideCleared = m.deleteOverride(hostPID, startTime)
		}
		if autoReadyCleared && readyCleared && overrideCleared {
			return true, true
		}
	}
	return autoReadyCleared, false
}

func (m *Manager) deleteAutoReady(hostPID uint32, startTime uint64) bool {
	if m.autoReady == nil {
		return true
	}
	canModify, identityKnown := m.canModifyResource(m.autoReady, hostPID, startTime)
	if !identityKnown {
		return false
	}
	if !canModify {
		return true
	}
	stale, verified := m.mapEntryStale(m.autoReady, hostPID, startTime)
	if !verified {
		return false
	}
	if stale {
		m.releaseResourceOwnership(m.autoReady, hostPID, startTime)
		return true
	}
	if err := m.autoReady.Delete(hostPID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		m.logError("disabling Go Auto SDK failed", "host_pid", hostPID, "error", err)
		if !m.failClosed(m.autoReady, hostPID, startTime, "disabling Go Auto SDK") {
			return false
		}
	}
	m.releaseResourceOwnership(m.autoReady, hostPID, startTime)
	return true
}

func (m *Manager) deleteReady(hostPID uint32, startTime uint64) bool {
	if m.ready == nil {
		return true
	}
	canModify, identityKnown := m.canModifyResource(m.ready, hostPID, startTime)
	if !identityKnown {
		return false
	}
	if !canModify {
		return true
	}
	stale, verified := m.mapEntryStale(m.ready, hostPID, startTime)
	if !verified {
		return false
	}
	if stale {
		m.releaseResourceOwnership(m.ready, hostPID, startTime)
		return true
	}
	if err := m.ready.Delete(hostPID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		m.logError("disabling PID sampler failed", "host_pid", hostPID, "error", err)
		if !m.failClosed(m.ready, hostPID, startTime, "disabling PID sampler") {
			return false
		}
	}
	m.releaseResourceOwnership(m.ready, hostPID, startTime)
	return true
}

func (m *Manager) overrideOwnedByProcess(
	hostPID uint32,
	startTime uint64,
) (bool, bool) {
	if m.overrides == nil {
		return false, true
	}
	canModify, identityKnown := m.canModifyResource(m.overrides, hostPID, startTime)
	if !identityKnown {
		return false, false
	}
	if !canModify {
		return false, true
	}
	if m.ownsResource(m.overrides, hostPID, startTime) {
		return true, true
	}
	if m.ready == nil {
		return true, true
	}
	stale, verified := m.mapEntryStale(m.ready, hostPID, startTime)
	return !stale, verified
}

func (m *Manager) mapEntryStale(
	target bpfMap,
	hostPID uint32,
	startTime uint64,
) (bool, bool) {
	var readiness BPFProcessReadiness
	err := target.Lookup(hostPID, &readiness)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, true
	}
	if err != nil {
		m.logError("checking process readiness before cleanup failed",
			"host_pid", hostPID, "error", err)
		return false, false
	}
	return startTime != 0 &&
		readiness.StartTime != 0 &&
		readiness.StartTime != startTime, true
}

func (m *Manager) deleteOverride(hostPID uint32, startTime uint64) bool {
	if m.overrides == nil {
		return true
	}
	canModify, identityKnown := m.canModifyResource(m.overrides, hostPID, startTime)
	if !identityKnown {
		return false
	}
	if !canModify {
		return true
	}
	if err := m.overrides.Delete(hostPID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		m.logError("deleting PID sampler failed", "host_pid", hostPID, "error", err)
		return false
	}
	m.releaseResourceOwnership(m.overrides, hostPID, startTime)
	return true
}

func (m *Manager) failClosed(
	target bpfMap,
	hostPID uint32,
	startTime uint64,
	operation string,
) bool {
	disabled := BPFProcessReadiness{StartTime: startTime}
	if err := target.Put(hostPID, disabled); err != nil {
		m.logError(operation+" fail-closed write failed",
			"host_pid", hostPID, "error", err)
		return false
	}
	return true
}

func (m *Manager) isGlobalReady() bool {
	m.mu.RLock()
	ready := m.globalReady
	m.mu.RUnlock()
	return ready
}

func (m *Manager) logError(message string, args ...any) {
	if m.log != nil {
		m.log.Error(message, args...)
	}
}

func resolveHostPID(pid app.PID) (uint32, error) {
	pids, err := procs.FindNamespacedPids(pid)
	if err != nil {
		return 0, fmt.Errorf("reading namespaced PIDs: %w", err)
	}
	if len(pids) == 0 {
		return uint32(pid), nil
	}
	return uint32(pids[0]), nil
}
