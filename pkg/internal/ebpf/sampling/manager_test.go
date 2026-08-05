// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sampling

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
)

const testProcessStartTime = uint64(10000000)

var testProcessReadiness = BPFProcessReadiness{
	StartTime: testProcessStartTime,
	Ready:     1,
}

type fakeMap struct {
	values     map[any]any
	putErr     error
	putErrs    map[any]error
	deleteErr  error
	deleteErrs []error
	actions    *[]string
	name       string
	putValues  []any
	putHook    func(key, value any)
}

func newFakeMap(name string, actions *[]string) *fakeMap {
	return &fakeMap{values: map[any]any{}, actions: actions, name: name}
}

func identifiedFakeMap(target *fakeMap, id ebpf.MapID) *identifiedMap {
	return &identifiedMap{
		target:   target,
		identity: resourceMapIdentity{kernelID: id},
	}
}

func unidentifiedFakeMap(target *fakeMap) *identifiedMap {
	return &identifiedMap{
		target:      target,
		identityErr: errMapIdentityUnknown,
	}
}

func (m *fakeMap) Put(key, value any) error {
	if m.actions != nil {
		*m.actions = append(*m.actions, m.name+":put")
	}
	if m.putHook != nil {
		m.putHook(key, value)
	}
	m.putValues = append(m.putValues, value)
	if m.putErr != nil {
		return m.putErr
	}
	if err := m.putErrs[key]; err != nil {
		return err
	}
	m.values[key] = value
	return nil
}

func (m *fakeMap) Lookup(key, valueOut any) error {
	value, ok := m.values[key]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	switch out := valueOut.(type) {
	case *BPFProcessReadiness:
		readiness, ok := value.(BPFProcessReadiness)
		if !ok {
			return errors.New("unexpected fake map value type")
		}
		*out = readiness
		return nil
	case *BPFConfig:
		config, ok := value.(BPFConfig)
		if !ok {
			return errors.New("unexpected fake map value type")
		}
		*out = config
		return nil
	default:
		return errors.New("unexpected fake map output type")
	}
}

func (m *fakeMap) Delete(key any) error {
	if m.actions != nil {
		*m.actions = append(*m.actions, m.name+":delete")
	}
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if len(m.deleteErrs) > 0 {
		err := m.deleteErrs[0]
		m.deleteErrs = m.deleteErrs[1:]
		if err != nil {
			return err
		}
	}
	if _, ok := m.values[key]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.values, key)
	return nil
}

func requireAutoReadiness(
	t *testing.T,
	autoReady *fakeMap,
	hostPID uint32,
) BPFProcessReadiness {
	t.Helper()

	value, ok := autoReady.values[hostPID]
	require.True(t, ok)
	readiness := value.(BPFProcessReadiness)
	assert.Equal(t, testProcessStartTime, readiness.StartTime)
	assert.NotZero(t, readiness.Epoch)
	assert.NotZero(t, readiness.ConfigEpoch)
	assert.Equal(t, uint8(1), readiness.Ready)
	assert.Equal(t, uint8(1), readiness.AutoSDKGlobalReady)
	return readiness
}

func requireSamplerReadiness(
	t *testing.T,
	ready *fakeMap,
	hostPID uint32,
	startTime uint64,
) BPFProcessReadiness {
	t.Helper()

	value, ok := ready.values[hostPID]
	require.True(t, ok)
	readiness := value.(BPFProcessReadiness)
	assert.Equal(t, startTime, readiness.StartTime)
	assert.NotZero(t, readiness.Epoch)
	assert.NotZero(t, readiness.ConfigEpoch)
	assert.Equal(t, uint8(1), readiness.Ready)
	return readiness
}

func TestManagerLifecycle(t *testing.T) {
	actions := []string{}
	global := newFakeMap("global", &actions)
	overrides := newFakeMap("overrides", &actions)
	ready := newFakeMap("sampler-ready", &actions)
	autoReady := newFakeMap("ready", &actions)
	globalConfig, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	override, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)

	manager := newManager(nil, global, overrides, ready, autoReady, globalConfig,
		func(app.PID) (uint32, error) { return 9001, nil })
	require.True(t, manager.InstallGlobal())
	actions = actions[:0]
	require.True(t, manager.AllowPIDForProcess(
		101, 7, testProcessStartTime, &override, true,
	))
	assert.Equal(t, []string{
		"ready:delete",
		"sampler-ready:delete",
		"overrides:put",
		"sampler-ready:put",
		"ready:put",
	}, actions)

	assert.Contains(t, global.values, uint32(0))
	require.Contains(t, overrides.values, uint32(9001))
	assert.Equal(t, uint8(services.SamplerTypeAlwaysOff),
		overrides.values[uint32(9001)].(BPFConfig).Type)
	requireAutoReadiness(t, autoReady, 9001)
	requireSamplerReadiness(t, ready, 9001, testProcessStartTime)

	actions = actions[:0]
	manager.BlockPID(101, 7)
	assert.Equal(t, []string{"ready:delete", "sampler-ready:delete", "overrides:delete"}, actions)
	assert.NotContains(t, autoReady.values, uint32(9001))
	assert.NotContains(t, overrides.values, uint32(9001))
	assert.NotContains(t, ready.values, uint32(9001))
}

func TestManagerGlobalSamplerPublicationIsImmutable(t *testing.T) {
	global := newFakeMap("global", nil)
	alwaysOn, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	alwaysOff, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)

	first := newManager(nil, global, nil, nil, nil, alwaysOn,
		func(app.PID) (uint32, error) { return 1, nil })
	same := newManager(nil, global, nil, nil, nil, alwaysOn,
		func(app.PID) (uint32, error) { return 1, nil })
	different := newManager(nil, global, nil, nil, nil, alwaysOff,
		func(app.PID) (uint32, error) { return 1, nil })

	require.True(t, first.InstallGlobal())
	published := global.values[uint32(0)].(BPFConfig)
	require.NotZero(t, published.PublicationEpoch)
	require.True(t, same.InstallGlobal())
	assert.Equal(t, published, global.values[uint32(0)])
	assert.Equal(t, published.PublicationEpoch, same.config.PublicationEpoch)

	assert.False(t, different.InstallGlobal())
	assert.Equal(t, published, global.values[uint32(0)])
	assert.False(t, different.isGlobalReady())
}

func TestManagerRefreshRepublishesReadiness(t *testing.T) {
	actions := []string{}
	global := newFakeMap("global", &actions)
	overrides := newFakeMap("overrides", &actions)
	ready := newFakeMap("sampler-ready", &actions)
	autoReady := newFakeMap("auto-ready", &actions)
	globalConfig, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	alwaysOff, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)
	alwaysOn, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)

	manager := newManager(nil, global, overrides, ready, autoReady, globalConfig,
		func(app.PID) (uint32, error) { return 9001, nil })
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(
		101, 7, testProcessStartTime, &alwaysOff, true,
	))
	firstSamplerReadiness := requireSamplerReadiness(
		t, ready, 9001, testProcessStartTime,
	)
	firstAutoReadiness := requireAutoReadiness(t, autoReady, 9001)

	actions = actions[:0]
	require.True(t, manager.AllowPIDForProcess(
		101, 7, testProcessStartTime, &alwaysOn, true,
	))
	assert.Equal(t, []string{
		"auto-ready:delete",
		"sampler-ready:delete",
		"overrides:put",
		"sampler-ready:put",
		"auto-ready:put",
	}, actions)
	secondSamplerReadiness := requireSamplerReadiness(
		t, ready, 9001, testProcessStartTime,
	)
	assert.NotEqual(t, firstSamplerReadiness.Epoch, secondSamplerReadiness.Epoch)
	secondAutoReadiness := requireAutoReadiness(t, autoReady, 9001)
	assert.NotEqual(t, firstAutoReadiness.Epoch, secondAutoReadiness.Epoch)
	assert.Equal(t, uint8(services.SamplerTypeAlwaysOn),
		overrides.values[uint32(9001)].(BPFConfig).Type)

	actions = actions[:0]
	require.True(t, manager.AllowPIDForProcess(
		101, 7, testProcessStartTime, &alwaysOff, false,
	))
	assert.Equal(t, []string{
		"auto-ready:delete",
		"sampler-ready:delete",
		"overrides:put",
		"sampler-ready:put",
	}, actions)
	thirdSamplerReadiness := requireSamplerReadiness(
		t, ready, 9001, testProcessStartTime,
	)
	assert.NotEqual(t, secondSamplerReadiness.Epoch, thirdSamplerReadiness.Epoch)
	assert.NotContains(t, autoReady.values, uint32(9001))

	actions = actions[:0]
	require.True(t, manager.AllowPIDForProcess(
		101, 7, testProcessStartTime, nil, false,
	))
	assert.Equal(t, []string{
		"auto-ready:delete",
		"sampler-ready:delete",
		"overrides:delete",
		"sampler-ready:put",
	}, actions)
	fourthSamplerReadiness := requireSamplerReadiness(
		t, ready, 9001, testProcessStartTime,
	)
	assert.NotEqual(t, thirdSamplerReadiness.Epoch, fourthSamplerReadiness.Epoch)
	assert.NotContains(t, autoReady.values, uint32(9001))

	actions = actions[:0]
	require.True(t, manager.DisableAutoSDK(101, 7))
	assert.Equal(t, []string{"auto-ready:delete"}, actions)
	assert.Equal(t, fourthSamplerReadiness, ready.values[uint32(9001)])
	assert.NotContains(t, autoReady.values, uint32(9001))
}

func TestManagerRefreshDoesNotAffectAnotherProcess(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	globalConfig, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	alwaysOff, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)
	alwaysOn, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)

	manager := newManager(nil, global, overrides, ready, autoReady, globalConfig,
		func(pid app.PID) (uint32, error) { return uint32(pid), nil })
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(
		101, 7, testProcessStartTime, &alwaysOff, true,
	))
	require.True(t, manager.AllowPIDForProcess(
		202, 7, testProcessStartTime, &alwaysOff, true,
	))

	firstRefreshedReadiness := requireSamplerReadiness(
		t, ready, 101, testProcessStartTime,
	)
	firstRefreshedAutoReadiness := requireAutoReadiness(t, autoReady, 101)
	otherOverride := overrides.values[uint32(202)].(BPFConfig)
	otherReadiness := requireSamplerReadiness(t, ready, 202, testProcessStartTime)
	otherAutoReadiness := requireAutoReadiness(t, autoReady, 202)

	require.True(t, manager.AllowPIDForProcess(
		101, 7, testProcessStartTime, &alwaysOn, true,
	))

	refreshedReadiness := requireSamplerReadiness(
		t, ready, 101, testProcessStartTime,
	)
	refreshedAutoReadiness := requireAutoReadiness(t, autoReady, 101)
	assert.NotEqual(t, firstRefreshedReadiness.Epoch, refreshedReadiness.Epoch)
	assert.NotEqual(t, firstRefreshedAutoReadiness.Epoch, refreshedAutoReadiness.Epoch)
	assert.Equal(t, uint8(services.SamplerTypeAlwaysOn),
		overrides.values[uint32(101)].(BPFConfig).Type)

	unchangedOverride := overrides.values[uint32(202)].(BPFConfig)
	unchangedReadiness := ready.values[uint32(202)].(BPFProcessReadiness)
	unchangedAutoReadiness := autoReady.values[uint32(202)].(BPFProcessReadiness)
	assert.Equal(t, otherOverride, unchangedOverride)
	assert.Equal(t, otherOverride.PublicationEpoch, unchangedOverride.PublicationEpoch)
	assert.Equal(t, otherReadiness, unchangedReadiness)
	assert.Equal(t, otherReadiness.Epoch, unchangedReadiness.Epoch)
	assert.Equal(t, otherReadiness.ConfigEpoch, unchangedReadiness.ConfigEpoch)
	assert.Equal(t, otherAutoReadiness, unchangedAutoReadiness)
	assert.Equal(t, otherAutoReadiness.Epoch, unchangedAutoReadiness.Epoch)
	assert.Equal(t, otherAutoReadiness.ConfigEpoch, unchangedAutoReadiness.ConfigEpoch)
}

func TestManagerRefreshFailureRevokesReadiness(t *testing.T) {
	actions := []string{}
	global := newFakeMap("global", &actions)
	overrides := newFakeMap("overrides", &actions)
	ready := newFakeMap("sampler-ready", &actions)
	autoReady := newFakeMap("auto-ready", &actions)
	globalConfig, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	override, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)

	manager := newManager(nil, global, overrides, ready, autoReady, globalConfig,
		func(app.PID) (uint32, error) { return 9001, nil })
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(
		101, 7, testProcessStartTime, &override, true,
	))

	actions = actions[:0]
	overrides.putErr = errors.New("map full")
	assert.False(t, manager.AllowPIDForProcess(
		101, 7, testProcessStartTime, &override, true,
	))
	assert.Equal(t, []string{
		"auto-ready:delete",
		"sampler-ready:delete",
		"overrides:put",
		"auto-ready:delete",
		"sampler-ready:delete",
		"overrides:delete",
	}, actions)
	assert.NotContains(t, ready.values, uint32(9001))
	assert.NotContains(t, autoReady.values, uint32(9001))
	assert.NotContains(t, manager.readyPIDs, uint32(9001))
	assert.NotContains(t, manager.hostPIDs, processKey{pid: 101, ns: 7})
	assert.NotContains(t, overrides.values, uint32(9001))
}

func TestManagerRefreshDeleteFailureRevokesReadiness(t *testing.T) {
	actions := []string{}
	global := newFakeMap("global", &actions)
	overrides := newFakeMap("overrides", &actions)
	ready := newFakeMap("sampler-ready", &actions)
	autoReady := newFakeMap("auto-ready", &actions)
	globalConfig, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	override, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)

	manager := newManager(nil, global, overrides, ready, autoReady, globalConfig,
		func(app.PID) (uint32, error) { return 9001, nil })
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(
		101, 7, testProcessStartTime, &override, true,
	))

	actions = actions[:0]
	overrides.deleteErrs = []error{errors.New("delete failed")}
	assert.False(t, manager.AllowPIDForProcess(
		101, 7, testProcessStartTime, nil, false,
	))
	assert.Equal(t, []string{
		"auto-ready:delete",
		"sampler-ready:delete",
		"overrides:delete",
		"auto-ready:delete",
		"sampler-ready:delete",
		"overrides:delete",
	}, actions)
	assert.NotContains(t, ready.values, uint32(9001))
	assert.NotContains(t, autoReady.values, uint32(9001))
	assert.NotContains(t, overrides.values, uint32(9001))
	assert.NotContains(t, manager.hostPIDs, processKey{pid: 101, ns: 7})
}

func TestManagerChangedIncarnationUsesColdActivation(t *testing.T) {
	actions := []string{}
	global := newFakeMap("global", &actions)
	overrides := newFakeMap("overrides", &actions)
	ready := newFakeMap("sampler-ready", &actions)
	autoReady := newFakeMap("auto-ready", &actions)
	globalConfig, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	override, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)

	manager := newManager(nil, global, overrides, ready, autoReady, globalConfig,
		func(app.PID) (uint32, error) { return 9001, nil })
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(
		101, 7, testProcessStartTime, &override, true,
	))
	firstAutoReadiness := requireAutoReadiness(t, autoReady, 9001)

	const nextStartTime = testProcessStartTime + 10000000
	actions = actions[:0]
	require.True(t, manager.AllowPIDForProcess(
		101, 7, nextStartTime, &override, false,
	))
	assert.Equal(t, []string{
		"overrides:put",
		"sampler-ready:put",
	}, actions)
	requireSamplerReadiness(t, ready, 9001, nextStartTime)
	assert.Equal(t, firstAutoReadiness, autoReady.values[uint32(9001)])
}

func TestManagerCleanupHandlesMixedIncarnationsPerMap(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	globalConfig, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	override, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)
	const (
		hostPID      = uint32(9001)
		oldStartTime = testProcessStartTime
		newStartTime = testProcessStartTime + 10000000
	)

	manager := newManager(nil, global, overrides, ready, autoReady, globalConfig,
		func(app.PID) (uint32, error) { return hostPID, nil })
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(
		101, 7, newStartTime, &override, true,
	))

	oldAutoReadiness := BPFProcessReadiness{
		StartTime: oldStartTime,
		Epoch:     9,
		Ready:     1,
	}
	autoReady.values[hostPID] = oldAutoReadiness

	require.True(t, manager.BlockPIDForProcess(101, 7, newStartTime))

	assert.Equal(t, oldAutoReadiness, autoReady.values[hostPID])
	assert.NotContains(t, ready.values, hostPID)
	assert.NotContains(t, overrides.values, hostPID)
	assert.NotContains(t, manager.hostPIDs, processKey{pid: 101, ns: 7})
	assert.NotContains(t, manager.hostOwners, hostPID)
}

func TestManagerGlobalFallbackRemovesStaleOverride(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	overrides.values[uint32(42)] = BPFConfig{Type: uint8(services.SamplerTypeAlwaysOff)}

	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) { return 42, nil })
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(42, 0, 10000000, nil, false))

	assert.NotContains(t, overrides.values, uint32(42))
	assert.NotContains(t, autoReady.values, uint32(42))
}

func TestManagerUnpublishesReadinessBeforeSamplerConfiguration(t *testing.T) {
	actions := []string{}
	global := newFakeMap("global", &actions)
	overrides := newFakeMap("overrides", &actions)
	ready := newFakeMap("sampler-ready", &actions)
	autoReady := newFakeMap("auto-ready", &actions)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	autoReady.values[uint32(42)] = testProcessReadiness

	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) { return 42, nil })
	require.True(t, manager.InstallGlobal())
	actions = actions[:0]

	require.True(t, manager.AllowPIDForProcess(42, 0, 10000000, nil, false))
	assert.Equal(t, []string{
		"auto-ready:delete",
		"sampler-ready:delete",
		"overrides:delete",
		"sampler-ready:put",
	}, actions)
}

func TestManagerAutoReadinessFailClosedWritePermitsSamplerActivation(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	autoReady.values[uint32(43)] = testProcessReadiness
	autoReady.deleteErr = errors.New("delete failed")

	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) { return 43, nil })
	require.True(t, manager.InstallGlobal())

	assert.True(t, manager.AllowPIDForProcess(43, 0, 10000000, nil, false))
	samplerReadiness := requireSamplerReadiness(
		t, ready, 43, testProcessStartTime,
	)
	assert.NotContains(t, overrides.values, uint32(43))
	assert.Equal(t,
		BPFProcessReadiness{StartTime: testProcessStartTime},
		autoReady.values[uint32(43)])
	assert.Equal(t, samplerReadiness, manager.readyPIDs[uint32(43)])
}

func TestManagerRemappingCleansPreviousHostPID(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	override, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)
	hostPID := uint32(100)

	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) { return hostPID, nil })
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(42, 7, 10000000, &override, true))
	require.Contains(t, autoReady.values, uint32(100))

	hostPID = 200
	require.True(t, manager.AllowPIDForProcess(42, 7, 10000000, &override, false))

	assert.NotContains(t, autoReady.values, uint32(100))
	assert.NotContains(t, ready.values, uint32(100))
	assert.NotContains(t, overrides.values, uint32(100))
	assert.NotContains(t, manager.readyPIDs, uint32(100))
	assert.Contains(t, ready.values, uint32(200))
	assert.Contains(t, overrides.values, uint32(200))
	assert.Equal(t, uint32(200), manager.hostPIDs[processKey{pid: 42, ns: 7}])
}

func TestManagerRemapCleanupRetryRevalidatesCurrentHost(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	hostPID := uint32(100)

	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) { return hostPID, nil })
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(
		42, 7, testProcessStartTime, nil, true,
	))

	hostPID = 200
	ready.deleteErr = errors.New("readiness delete failed")
	ready.putErr = errors.New("readiness fail-closed write failed")
	assert.False(t, manager.AllowPIDForProcess(
		42, 7, testProcessStartTime, nil, false,
	))
	assert.False(t, manager.FallbackSafeForProcessIncarnation(
		42, 7, testProcessStartTime,
	))

	ready.deleteErr = nil
	ready.putErr = nil
	assert.True(t, manager.BlockPIDForProcess(42, 7, testProcessStartTime))
	assert.True(t, manager.FallbackSafeForProcessIncarnation(
		42, 7, testProcessStartTime,
	))
	assert.NotContains(t, ready.values, uint32(100))
	assert.NotContains(t, ready.values, uint32(200))
}

func TestManagerRemapCleanupRetryRetainsUnknownHostDebt(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	hostPID := uint32(100)
	var resolveErr error

	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) {
			if resolveErr != nil {
				return 0, resolveErr
			}
			return hostPID, nil
		})
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(
		42, 7, testProcessStartTime, nil, true,
	))

	hostPID = 200
	ready.deleteErr = errors.New("readiness delete failed")
	ready.putErr = errors.New("readiness fail-closed write failed")
	assert.False(t, manager.AllowPIDForProcess(
		42, 7, testProcessStartTime, nil, false,
	))

	ready.deleteErr = nil
	ready.putErr = nil
	resolveErr = errors.New("resolver unavailable")
	assert.False(t, manager.BlockPIDForProcess(42, 7, testProcessStartTime))
	assert.False(t, manager.FallbackSafeForProcessIncarnation(
		42, 7, testProcessStartTime,
	))
	require.NotEmpty(t, manager.cleanupDebts[processKey{pid: 42, ns: 7}])
	assert.Condition(t, func() bool {
		for debt := range manager.cleanupDebts[processKey{pid: 42, ns: 7}] {
			if debt.unknownHost {
				return true
			}
		}
		return false
	})

	resolveErr = nil
	assert.True(t, manager.BlockPIDForProcess(42, 7, testProcessStartTime))
	assert.True(t, manager.FallbackSafeForProcessIncarnation(
		42, 7, testProcessStartTime,
	))
}

func TestManagerRemapCleanupRetryRejectsConflictingHostOwner(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	hostPIDs := map[app.PID]uint32{42: 100, 43: 200}

	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(pid app.PID) (uint32, error) { return hostPIDs[pid], nil })
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(
		42, 7, testProcessStartTime, nil, true,
	))
	require.True(t, manager.AllowPIDForProcess(
		43, 8, testProcessStartTime, nil, true,
	))
	expectedReadiness := ready.values[uint32(200)]

	hostPIDs[42] = 200
	ready.deleteErr = errors.New("readiness delete failed")
	ready.putErr = errors.New("readiness fail-closed write failed")
	assert.False(t, manager.AllowPIDForProcess(
		42, 7, testProcessStartTime, nil, false,
	))

	ready.deleteErr = nil
	ready.putErr = nil
	assert.False(t, manager.BlockPIDForProcess(42, 7, testProcessStartTime))
	assert.False(t, manager.FallbackSafeForProcessIncarnation(
		42, 7, testProcessStartTime,
	))
	assert.Equal(t, expectedReadiness, ready.values[uint32(200)])

	assert.True(t, manager.BlockPIDForProcess(43, 8, testProcessStartTime))
	assert.True(t, manager.BlockPIDForProcess(42, 7, testProcessStartTime))
	assert.True(t, manager.FallbackSafeForProcessIncarnation(
		42, 7, testProcessStartTime,
	))
}

func TestManagerKeepsOldDebtSeparateFromReplacementIncarnation(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	const replacementStartTime = testProcessStartTime + 100

	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) { return 100, nil })
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(
		42, 7, testProcessStartTime, nil, true,
	))

	ready.deleteErr = errors.New("readiness delete failed")
	ready.putErr = errors.New("readiness fail-closed write failed")
	assert.True(t, manager.BlockPIDForProcess(42, 7, testProcessStartTime))
	assert.False(t, manager.FallbackSafeForProcessIncarnation(
		42, 7, testProcessStartTime,
	))

	ready.deleteErr = nil
	ready.putErr = nil
	require.True(t, manager.AllowPIDForProcess(
		42, 7, replacementStartTime, nil, false,
	))
	assert.False(t, manager.FallbackSafeForProcessIncarnation(
		42, 7, testProcessStartTime,
	))
	assert.True(t, manager.FallbackSafeForProcessIncarnation(
		42, 7, replacementStartTime,
	))
	expectedReadiness := requireSamplerReadiness(
		t, ready, 100, replacementStartTime,
	)
	assert.Equal(t, expectedReadiness, ready.values[uint32(100)])

	assert.True(t, manager.BlockPIDForProcess(42, 7, testProcessStartTime))
	assert.Equal(t, expectedReadiness, ready.values[uint32(100)])
	assert.Equal(t, replacementStartTime,
		manager.startTimes[processKey{pid: 42, ns: 7}])
}

func TestManagersSerializeSharedMapPublicationAndStaleCleanup(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	oldOverride, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)
	newOverride, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	const (
		hostPID              = uint32(100)
		replacementStartTime = testProcessStartTime + 100
	)
	resolve := func(app.PID) (uint32, error) { return hostPID, nil }
	oldManager := newManager(nil, global, overrides, ready, autoReady, config, resolve)
	newManager := newManager(nil, global, overrides, ready, autoReady, config, resolve)
	require.True(t, oldManager.InstallGlobal())
	require.True(t, newManager.InstallGlobal())
	require.True(t, oldManager.AllowPIDForProcess(
		42, 7, testProcessStartTime, &oldOverride, true,
	))

	overridePutStarted := make(chan struct{})
	releaseOverridePut := make(chan struct{})
	overrides.putHook = func(any, any) {
		close(overridePutStarted)
		<-releaseOverridePut
	}
	allowDone := make(chan bool)
	go func() {
		allowDone <- newManager.AllowPIDForProcess(
			42, 7, replacementStartTime, &newOverride, false,
		)
	}()
	<-overridePutStarted

	blockDone := make(chan bool)
	go func() {
		blockDone <- oldManager.BlockPIDForProcess(
			42, 7, testProcessStartTime,
		)
	}()
	select {
	case <-blockDone:
		t.Fatal("stale cleanup interleaved override publication")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseOverridePut)
	require.True(t, <-allowDone)
	require.True(t, <-blockDone)

	requireSamplerReadiness(t, ready, hostPID, replacementStartTime)
	publishedOverride := overrides.values[hostPID].(BPFConfig)
	assert.Equal(t, toBPFConfig(newOverride).Type, publishedOverride.Type)
	assert.Equal(t,
		ready.values[hostPID].(BPFProcessReadiness).ConfigEpoch,
		publishedOverride.PublicationEpoch)
	assert.NotContains(t, autoReady.values, hostPID)
}

func TestManagerReadinessFailureRollsBackReplacementOverride(t *testing.T) {
	actions := []string{}
	global := newFakeMap("global", &actions)
	overrides := newFakeMap("overrides", &actions)
	ready := newFakeMap("sampler-ready", &actions)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	oldOverride, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)
	newOverride, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	const (
		hostPID              = uint32(100)
		replacementStartTime = testProcessStartTime + 100
		globalMapID          = ebpf.MapID(0x7f100001)
		overridesMapID       = ebpf.MapID(0x7f100002)
		readyMapID           = ebpf.MapID(0x7f100003)
	)
	resolve := func(app.PID) (uint32, error) { return hostPID, nil }
	oldManager := newManager(
		nil,
		identifiedFakeMap(global, globalMapID),
		identifiedFakeMap(overrides, overridesMapID),
		identifiedFakeMap(ready, readyMapID),
		nil,
		config,
		resolve,
	)
	newOverrides := identifiedFakeMap(overrides, overridesMapID)
	newManager := newManager(
		nil,
		identifiedFakeMap(global, globalMapID),
		newOverrides,
		identifiedFakeMap(ready, readyMapID),
		nil,
		config,
		resolve,
	)
	require.True(t, oldManager.InstallGlobal())
	require.True(t, newManager.InstallGlobal())
	require.True(t, oldManager.AllowPIDForProcess(
		42, 7, testProcessStartTime, &oldOverride, false,
	))
	oldReadiness := requireSamplerReadiness(t, ready, hostPID, testProcessStartTime)

	actions = actions[:0]
	ready.putErr = errors.New("readiness publication failed")
	assert.False(t, newManager.AllowPIDForProcess(
		42, 7, replacementStartTime, &newOverride, false,
	))

	assert.Equal(t,
		[]string{"overrides:put", "sampler-ready:put", "overrides:delete"},
		actions)
	assert.Equal(t, oldReadiness, ready.values[hostPID])
	assert.NotContains(t, overrides.values, hostPID)
	identity, ok := mapIdentity(newOverrides)
	require.True(t, ok)
	assert.NotContains(t, resourceOwners, resourceOwnershipKey{
		target:  identity,
		hostPID: hostPID,
	})
	assert.NotContains(t, newManager.hostPIDs, processKey{pid: 42, ns: 7})
	assert.NotContains(t, newManager.cleanupDebts, processKey{pid: 42, ns: 7})

	ready.putErr = nil
	require.True(t, oldManager.BlockPIDForProcess(42, 7, testProcessStartTime))
}

func TestManagerOverrideFailurePreservesPreviousIncarnation(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	oldOverride, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)
	newOverride, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	const (
		hostPID              = uint32(100)
		replacementStartTime = testProcessStartTime + 100
		globalMapID          = ebpf.MapID(0x7f100011)
		overridesMapID       = ebpf.MapID(0x7f100012)
		readyMapID           = ebpf.MapID(0x7f100013)
	)
	resolve := func(app.PID) (uint32, error) { return hostPID, nil }
	oldOverrides := identifiedFakeMap(overrides, overridesMapID)
	oldManager := newManager(
		nil,
		identifiedFakeMap(global, globalMapID),
		oldOverrides,
		identifiedFakeMap(ready, readyMapID),
		nil,
		config,
		resolve,
	)
	newManager := newManager(
		nil,
		identifiedFakeMap(global, globalMapID),
		identifiedFakeMap(overrides, overridesMapID),
		identifiedFakeMap(ready, readyMapID),
		nil,
		config,
		resolve,
	)
	require.True(t, oldManager.InstallGlobal())
	require.True(t, newManager.InstallGlobal())
	require.True(t, oldManager.AllowPIDForProcess(
		42, 7, testProcessStartTime, &oldOverride, false,
	))
	oldConfig := overrides.values[hostPID]
	oldReadiness := ready.values[hostPID]

	overrides.putErr = errors.New("override publication failed")
	assert.False(t, newManager.AllowPIDForProcess(
		42, 7, replacementStartTime, &newOverride, false,
	))

	assert.Equal(t, oldConfig, overrides.values[hostPID])
	assert.Equal(t, oldReadiness, ready.values[hostPID])
	identity, ok := mapIdentity(oldOverrides)
	require.True(t, ok)
	assert.Equal(t,
		resourceOwnership{managerID: oldManager.id, startTime: testProcessStartTime},
		resourceOwners[resourceOwnershipKey{target: identity, hostPID: hostPID}])

	overrides.putErr = nil
	require.True(t, oldManager.BlockPIDForProcess(42, 7, testProcessStartTime))
}

func TestManagerReplacementWithSameStartTimeOwnsCleanup(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	oldOverride, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)
	newOverride, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	const (
		hostPID        = uint32(100)
		globalMapID    = ebpf.MapID(0x7f000001)
		overridesMapID = ebpf.MapID(0x7f000002)
		readyMapID     = ebpf.MapID(0x7f000003)
		autoReadyMapID = ebpf.MapID(0x7f000004)
	)
	resolve := func(app.PID) (uint32, error) { return hostPID, nil }

	oldGlobal := identifiedFakeMap(global, globalMapID)
	oldOverrides := identifiedFakeMap(overrides, overridesMapID)
	oldReady := identifiedFakeMap(ready, readyMapID)
	oldAutoReady := identifiedFakeMap(autoReady, autoReadyMapID)
	newGlobal := identifiedFakeMap(global, globalMapID)
	newOverrides := identifiedFakeMap(overrides, overridesMapID)
	newReady := identifiedFakeMap(ready, readyMapID)
	newAutoReady := identifiedFakeMap(autoReady, autoReadyMapID)
	require.NotSame(t, oldOverrides, newOverrides)
	require.NotSame(t, oldReady, newReady)
	require.NotSame(t, oldAutoReady, newAutoReady)

	oldManager := newManager(
		nil, oldGlobal, oldOverrides, oldReady, oldAutoReady, config, resolve,
	)
	newManager := newManager(
		nil, newGlobal, newOverrides, newReady, newAutoReady, config, resolve,
	)
	require.True(t, oldManager.InstallGlobal())
	require.True(t, newManager.InstallGlobal())
	require.True(t, oldManager.AllowPIDForProcess(
		42, 7, testProcessStartTime, &oldOverride, true,
	))
	require.True(t, newManager.AllowPIDForProcess(
		42, 7, testProcessStartTime, &newOverride, true,
	))
	expectedAutoReadiness := requireAutoReadiness(t, autoReady, hostPID)

	require.True(t, oldManager.BlockPIDForProcess(42, 7, testProcessStartTime))

	requireSamplerReadiness(t, ready, hostPID, testProcessStartTime)
	publishedOverride := overrides.values[hostPID].(BPFConfig)
	assert.Equal(t, toBPFConfig(newOverride).Type, publishedOverride.Type)
	assert.Equal(t,
		ready.values[hostPID].(BPFProcessReadiness).ConfigEpoch,
		publishedOverride.PublicationEpoch)
	assert.Equal(t, expectedAutoReadiness, autoReady.values[hostPID])
	assert.NotContains(t, oldManager.hostPIDs, processKey{pid: 42, ns: 7})

	require.True(t, newManager.BlockPIDForProcess(42, 7, testProcessStartTime))
	assert.NotContains(t, ready.values, hostPID)
	assert.NotContains(t, overrides.values, hostPID)
	assert.NotContains(t, autoReady.values, hostPID)
}

func TestManagerUnknownMapIdentityFailsClosed(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	override, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)
	const hostPID = uint32(101)
	originalOverride := BPFConfig{Type: uint8(services.SamplerTypeAlwaysOn)}
	originalAutoReadiness := BPFProcessReadiness{
		StartTime: testProcessStartTime,
		Epoch:     1,
		Ready:     1,
	}
	overrides.values[hostPID] = originalOverride
	ready.values[hostPID] = testProcessReadiness
	autoReady.values[hostPID] = originalAutoReadiness

	manager := newManager(
		nil,
		global,
		unidentifiedFakeMap(overrides),
		unidentifiedFakeMap(ready),
		unidentifiedFakeMap(autoReady),
		config,
		func(app.PID) (uint32, error) { return hostPID, nil },
	)
	require.True(t, manager.InstallGlobal())

	assert.False(t, manager.AllowPIDForProcess(
		42, 7, testProcessStartTime, &override, true,
	))
	assert.False(t, manager.FallbackSafeForProcessIncarnation(
		42, 7, testProcessStartTime,
	))
	assert.False(t, manager.BlockPIDForProcess(42, 7, testProcessStartTime))
	assert.Equal(t, originalOverride, overrides.values[hostPID])
	assert.Equal(t, testProcessReadiness, ready.values[hostPID])
	assert.Equal(t, originalAutoReadiness, autoReady.values[hostPID])
}

func TestManagerHostPIDTakeoverIgnoresDelayedBlock(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)

	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) { return 100, nil })
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(42, 7, 10000000, nil, true))
	require.True(t, manager.AllowPIDForProcess(42, 8, 10000000, nil, true))

	assert.NotContains(t, manager.hostPIDs, processKey{pid: 42, ns: 7})
	assert.Equal(t, uint32(100), manager.hostPIDs[processKey{pid: 42, ns: 8}])
	assert.Equal(t, processKey{pid: 42, ns: 8}, manager.hostOwners[100])

	assert.False(t, manager.BlockPID(42, 7))
	requireSamplerReadiness(t, ready, 100, testProcessStartTime)
	requireAutoReadiness(t, autoReady, 100)

	assert.True(t, manager.BlockPID(42, 8))
	assert.NotContains(t, ready.values, uint32(100))
	assert.NotContains(t, autoReady.values, uint32(100))
}

func TestManagerResolutionFailureDisablesPreviousAuthority(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	override, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)
	resolveErr := error(nil)

	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) {
			if resolveErr != nil {
				return 0, resolveErr
			}
			return 303, nil
		})
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(42, 7, 10000000, &override, true))

	resolveErr = errors.New("process disappeared")
	assert.False(t, manager.AllowPIDForProcess(42, 7, 10000000, &override, true))

	assert.NotContains(t, autoReady.values, uint32(303))
	assert.NotContains(t, ready.values, uint32(303))
	assert.NotContains(t, overrides.values, uint32(303))
	assert.NotContains(t, manager.readyPIDs, uint32(303))
	assert.NotContains(t, manager.hostPIDs, processKey{pid: 42, ns: 7})
}

func TestManagerOverrideFailureDisablesAuthorityAndActivation(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	override, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)
	overrides.putErr = errors.New("map full")
	autoReady.values[uint32(77)] = testProcessReadiness

	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) { return 77, nil })
	require.True(t, manager.InstallGlobal())
	assert.False(t, manager.AllowPIDForProcess(77, 0, 10000000, &override, true))
	assert.NotContains(t, autoReady.values, uint32(77))
	assert.NotContains(t, ready.values, uint32(77))
	assert.True(t, manager.FallbackSafeForProcess(77, 0))
}

func TestManagerOverrideFailureDoesNotAffectAnotherProcess(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	override, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)

	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(pid app.PID) (uint32, error) { return uint32(pid), nil })
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(88, 0, testProcessStartTime, &override, true))

	overrides.putErrs = map[any]error{uint32(77): errors.New("map full")}
	assert.False(t, manager.AllowPIDForProcess(77, 0, testProcessStartTime, &override, true))

	assert.Equal(t, uint8(services.SamplerTypeAlwaysOff),
		overrides.values[uint32(88)].(BPFConfig).Type)
	requireSamplerReadiness(t, ready, 88, testProcessStartTime)
	requireAutoReadiness(t, autoReady, 88)
	assert.Equal(t, uint32(88), manager.hostPIDs[processKey{pid: 88}])
}

func TestManagerRetainsFailedInstallCleanupForBlockRetry(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	override, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)
	hostPID := uint32(404)
	overrides.values[hostPID] = BPFConfig{Type: uint8(services.SamplerTypeAlwaysOn)}
	overrides.putErr = errors.New("map full")
	overrides.deleteErr = errors.New("delete failed")

	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) { return hostPID, nil })
	require.True(t, manager.InstallGlobal())
	assert.False(t, manager.AllowPIDForProcess(42, 7, 10000000, &override, true))
	assert.Equal(t, hostPID, manager.hostPIDs[processKey{pid: 42, ns: 7}])
	assert.False(t, manager.FallbackSafeForProcess(42, 7))

	overrides.putErr = nil
	overrides.deleteErr = nil
	manager.BlockPID(42, 7)

	assert.NotContains(t, overrides.values, hostPID)
	assert.NotContains(t, manager.hostPIDs, processKey{pid: 42, ns: 7})
	assert.True(t, manager.FallbackSafeForProcess(42, 7))
}

func TestManagerMarksFailedSamplerRevocationIndeterminate(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	alwaysOff, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)
	alwaysOn, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)

	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) { return 405, nil })
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(
		42, 7, testProcessStartTime, &alwaysOff, false,
	))

	overrides.putErr = errors.New("override update failed")
	ready.deleteErr = errors.New("readiness delete failed")
	ready.putErr = errors.New("readiness fail-closed write failed")
	assert.False(t, manager.AllowPIDForProcess(
		42, 7, testProcessStartTime, &alwaysOn, false,
	))
	assert.False(t, manager.FallbackSafeForProcess(42, 7))
	assert.Contains(t, manager.hostPIDs, processKey{pid: 42, ns: 7})

	overrides.putErr = nil
	ready.deleteErr = nil
	ready.putErr = nil
	assert.True(t, manager.BlockPIDForProcess(42, 7, testProcessStartTime))
	assert.True(t, manager.FallbackSafeForProcess(42, 7))
	assert.NotContains(t, manager.hostPIDs, processKey{pid: 42, ns: 7})
}

func TestManagerReadinessFailureKeepsSamplingAuthority(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)

	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) { return 88, nil })
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(
		88, 0, testProcessStartTime, nil, false,
	))
	autoReady.putErr = errors.New("map full")

	assert.False(t, manager.EnableAutoSDK(88, 0))
	requireSamplerReadiness(t, ready, 88, testProcessStartTime)
	assert.NotContains(t, autoReady.values, uint32(88))
	failedReadiness := autoReady.putValues[len(autoReady.putValues)-1].(BPFProcessReadiness)

	autoReady.putErr = nil
	require.True(t, manager.EnableAutoSDK(88, 0))
	enabledReadiness := requireAutoReadiness(t, autoReady, 88)
	assert.NotEqual(t, failedReadiness.Epoch, enabledReadiness.Epoch)
}

func TestManagerPreparesAutoSDKStateBeforePublishingReadiness(t *testing.T) {
	actions := []string{}
	global := newFakeMap("global", &actions)
	overrides := newFakeMap("overrides", &actions)
	ready := newFakeMap("sampler-ready", &actions)
	autoReady := newFakeMap("auto-ready", &actions)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	manager := newManager(
		nil,
		global,
		overrides,
		ready,
		autoReady,
		config,
		func(app.PID) (uint32, error) { return 9001, nil },
	)
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(
		101,
		7,
		testProcessStartTime,
		nil,
		false,
	))
	actions = nil

	require.True(t, manager.EnableAutoSDKWithSetup(
		101,
		7,
		func(hostPID uint32, startTime uint64, epoch uint32) bool {
			assert.Equal(t, uint32(9001), hostPID)
			assert.Equal(t, testProcessStartTime, startTime)
			assert.NotZero(t, epoch)
			assert.NotContains(t, autoReady.values, hostPID)
			actions = append(actions, "inflight:prepare")
			return true
		},
	))

	assert.Equal(t, []string{"inflight:prepare", "auto-ready:put"}, actions)
	requireAutoReadiness(t, autoReady, 9001)
}

func TestManagerPublishesDirectOnlyAutoSDKReadiness(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	manager := newManager(
		nil,
		global,
		overrides,
		ready,
		autoReady,
		config,
		func(app.PID) (uint32, error) { return 9002, nil },
	)
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(
		102,
		7,
		testProcessStartTime,
		nil,
		false,
	))

	require.True(t, manager.EnableAutoSDKWithSetupMode(
		102,
		7,
		false,
		nil,
	))

	readiness := autoReady.values[uint32(9002)].(BPFProcessReadiness)
	assert.Equal(t, uint8(1), readiness.Ready)
	assert.Zero(t, readiness.AutoSDKGlobalReady)
}

func TestManagerPreparationFailurePreventsAutoSDKPublication(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	manager := newManager(
		nil,
		global,
		overrides,
		ready,
		autoReady,
		config,
		func(app.PID) (uint32, error) { return 9001, nil },
	)
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(
		101,
		7,
		testProcessStartTime,
		nil,
		false,
	))

	assert.False(t, manager.EnableAutoSDKWithSetup(
		101,
		7,
		func(uint32, uint64, uint32) bool {
			return false
		},
	))

	assert.NotContains(t, autoReady.values, uint32(9001))
	assert.Empty(t, autoReady.putValues)
}

func TestManagerQuiesceAutoSDKForUntrackedProcess(t *testing.T) {
	autoReady := newFakeMap("auto-ready", nil)
	autoReady.values[uint32(89)] = BPFProcessReadiness{
		StartTime: testProcessStartTime,
		Epoch:     7,
		Ready:     1,
	}
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	manager := newManager(
		nil, nil, nil, nil, autoReady, config,
		func(app.PID) (uint32, error) { return 89, nil },
	)

	assert.True(t, manager.QuiesceAutoSDKForProcess(89, 0, testProcessStartTime))
	assert.NotContains(t, autoReady.values, uint32(89))
}

func TestManagerQuiesceAutoSDKUsesTrackedHostPIDAfterProcessExit(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	resolveCalls := 0
	resolveErr := error(nil)
	manager := newManager(
		nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) {
			resolveCalls++
			if resolveErr != nil {
				return 0, resolveErr
			}
			return 89, nil
		},
	)
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(
		89, 0, testProcessStartTime, nil, true,
	))
	requireAutoReadiness(t, autoReady, 89)
	require.Equal(t, 1, resolveCalls)

	resolveErr = errors.New("process exited")
	assert.True(t, manager.QuiesceAutoSDKForProcess(89, 0, testProcessStartTime))

	assert.Equal(t, 1, resolveCalls)
	assert.NotContains(t, autoReady.values, uint32(89))
	requireSamplerReadiness(t, ready, 89, testProcessStartTime)
	assert.True(t, manager.FallbackSafeForProcessIncarnation(
		89, 0, testProcessStartTime,
	))
}

func TestManagerStaleQuiescePreservesReplacementIncarnation(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	manager := newManager(
		nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) { return 89, nil },
	)
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(
		89, 0, testProcessStartTime, nil, true,
	))

	const replacementStartTime = testProcessStartTime + 100
	require.True(t, manager.AllowPIDForProcess(
		89, 0, replacementStartTime, nil, true,
	))
	replacementReadiness, ok := autoReady.values[uint32(89)].(BPFProcessReadiness)
	require.True(t, ok)
	require.NotZero(t, replacementReadiness.Epoch)
	require.Equal(t, uint8(1), replacementReadiness.Ready)

	assert.True(t, manager.QuiesceAutoSDKForProcess(
		89, 0, testProcessStartTime,
	))

	assert.Equal(t, replacementStartTime, replacementReadiness.StartTime)
	assert.Equal(t, replacementReadiness, autoReady.values[uint32(89)])
	requireSamplerReadiness(t, ready, 89, replacementStartTime)
}

func TestManagerQuiesceAutoSDKRequiresFailClosedWrite(t *testing.T) {
	autoReady := newFakeMap("auto-ready", nil)
	readiness := BPFProcessReadiness{
		StartTime: testProcessStartTime,
		Epoch:     8,
		Ready:     1,
	}
	autoReady.values[uint32(90)] = readiness
	autoReady.deleteErr = errors.New("delete failed")
	autoReady.putErr = errors.New("fail-closed write failed")
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	manager := newManager(
		nil, nil, nil, nil, autoReady, config,
		func(app.PID) (uint32, error) { return 90, nil },
	)

	assert.False(t, manager.QuiesceAutoSDKForProcess(90, 0, testProcessStartTime))
	assert.Equal(t, readiness, autoReady.values[uint32(90)])
	assert.False(t, manager.FallbackSafeForProcess(90, 0))

	autoReady.deleteErr = nil
	autoReady.putErr = nil
	assert.True(t, manager.BlockPIDForProcess(90, 0, testProcessStartTime))
	assert.True(t, manager.FallbackSafeForProcess(90, 0))
}

func TestManagerBlockUntrackedProcessRequiresIncarnation(t *testing.T) {
	autoReady := newFakeMap("auto-ready", nil)
	autoReady.values[uint32(91)] = BPFProcessReadiness{
		StartTime: testProcessStartTime,
		Epoch:     9,
		Ready:     1,
	}
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	manager := newManager(
		nil, nil, nil, nil, autoReady, config,
		func(app.PID) (uint32, error) { return 91, nil },
	)

	assert.False(t, manager.BlockPID(91, 0))
	assert.True(t, manager.BlockPIDForProcess(91, 0, testProcessStartTime))
	assert.NotContains(t, autoReady.values, uint32(91))
}

func TestManagerSamplingReadinessFailureDisablesAuthority(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	override, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)
	ready.putErr = errors.New("map full")

	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) { return 99, nil })
	require.True(t, manager.InstallGlobal())
	assert.False(t, manager.AllowPIDForProcess(99, 0, 10000000, &override, true))
	assert.NotContains(t, overrides.values, uint32(99))
	assert.NotContains(t, autoReady.values, uint32(99))
}

func TestManagerSamplerPublicationEpochIsNotReusedAfterFailure(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	ready.putErr = errors.New("map full")

	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) { return 99, nil })
	require.True(t, manager.InstallGlobal())
	assert.False(t, manager.AllowPIDForProcess(
		99, 0, testProcessStartTime, nil, false,
	))
	require.NotEmpty(t, ready.putValues)
	failed := ready.putValues[0].(BPFProcessReadiness)
	assert.NotZero(t, failed.Epoch)

	ready.putErr = nil
	require.True(t, manager.AllowPIDForProcess(
		99, 0, testProcessStartTime, nil, false,
	))
	published := requireSamplerReadiness(t, ready, 99, testProcessStartTime)
	assert.NotEqual(t, failed.Epoch, published.Epoch)
}

func TestManagerSamplerPublicationEpochExhaustionFailsClosed(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	override, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOff}).Canonical()
	require.NoError(t, err)

	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) { return 99, nil })
	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(
		99, 0, testProcessStartTime, &override, true,
	))

	previous := atomic.SwapUint32(&samplerPublicationEpoch, ^uint32(0))
	t.Cleanup(func() {
		atomic.StoreUint32(&samplerPublicationEpoch, previous)
	})

	assert.False(t, manager.AllowPIDForProcess(
		99, 0, testProcessStartTime, nil, false,
	))
	assert.NotContains(t, ready.values, uint32(99))
	assert.NotContains(t, overrides.values, uint32(99))
	assert.NotContains(t, autoReady.values, uint32(99))
	assert.NotContains(t, manager.readyPIDs, uint32(99))
	assert.NotContains(t, manager.hostPIDs, processKey{pid: 99})
}

func TestManagerWithoutAutoOwnershipDoesNotClearAutoReadiness(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	resolve := func(app.PID) (uint32, error) { return 101, nil }

	autoOwner := newManager(nil, global, overrides, ready, autoReady, config, resolve)
	nonOwner := newManager(nil, global, overrides, ready, nil, config, resolve)
	require.True(t, autoOwner.InstallGlobal())
	require.True(t, nonOwner.InstallGlobal())
	require.True(t, autoOwner.AllowPIDForProcess(101, 0, 10000000, nil, false))
	require.True(t, autoOwner.EnableAutoSDK(101, 0))
	require.True(t, nonOwner.AllowPIDForProcess(101, 0, 10000000, nil, false))
	expectedAutoReadiness := requireAutoReadiness(t, autoReady, 101)

	assert.Equal(t, expectedAutoReadiness, autoReady.values[uint32(101)])

	assert.True(t, nonOwner.BlockPID(101, 0))
	assert.Equal(t, expectedAutoReadiness, autoReady.values[uint32(101)])

	assert.True(t, autoOwner.BlockPID(101, 0))
	assert.NotContains(t, autoReady.values, uint32(101))
}

func TestManagerBlockRetriesFailedCleanup(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) { return 202, nil })

	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(202, 0, 10000000, nil, true))
	ready.deleteErr = errors.New("delete failed")
	ready.putErr = errors.New("fail-closed write failed")

	assert.True(t, manager.BlockPID(202, 0))
	assert.Contains(t, ready.values, uint32(202))
	assert.Contains(t, manager.hostPIDs, processKey{pid: 202, ns: 0})
	assert.False(t, manager.FallbackSafeForProcess(202, 0))

	ready.deleteErr = nil
	ready.putErr = nil
	assert.True(t, manager.BlockPID(202, 0))
	assert.NotContains(t, ready.values, uint32(202))
	assert.NotContains(t, manager.hostPIDs, processKey{pid: 202, ns: 0})
	assert.True(t, manager.FallbackSafeForProcess(202, 0))
}

func TestManagerBlockReportsAutoSDKQuiescenceFailure(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)
	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) { return 203, nil })

	require.True(t, manager.InstallGlobal())
	require.True(t, manager.AllowPIDForProcess(203, 0, testProcessStartTime, nil, true))
	expectedAutoReadiness := requireAutoReadiness(t, autoReady, 203)
	autoReady.deleteErr = errors.New("delete failed")
	autoReady.putErr = errors.New("fail-closed write failed")

	assert.False(t, manager.BlockPID(203, 0))
	assert.Equal(t, expectedAutoReadiness, autoReady.values[uint32(203)])
	assert.Contains(t, manager.hostPIDs, processKey{pid: 203, ns: 0})
	assert.False(t, manager.FallbackSafeForProcess(203, 0))

	autoReady.deleteErr = nil
	autoReady.putErr = nil
	assert.True(t, manager.BlockPID(203, 0))
	assert.NotContains(t, autoReady.values, uint32(203))
	assert.NotContains(t, manager.hostPIDs, processKey{pid: 203, ns: 0})
	assert.True(t, manager.FallbackSafeForProcess(203, 0))
}

func TestNewManagerHandlesUnavailableMaps(t *testing.T) {
	manager := NewManager(nil, nil, nil, nil, nil, services.CanonicalSampler{})

	assert.False(t, manager.InstallGlobal())
	assert.False(t, manager.AllowPIDForProcess(1, 1, 10000000, nil, false))
	assert.False(t, manager.EnableAutoSDK(1, 1))
	assert.False(t, manager.DisableAutoSDK(1, 1))
	assert.True(t, manager.QuiesceAutoSDKForProcess(1, 1, 10000000))
	assert.True(t, manager.FallbackSafeForProcess(1, 1))
	assert.NotPanics(t, func() {
		manager.BlockPID(1, 1)
	})
}

func TestManagerRejectsProcessWithoutIncarnation(t *testing.T) {
	global := newFakeMap("global", nil)
	overrides := newFakeMap("overrides", nil)
	ready := newFakeMap("sampler-ready", nil)
	autoReady := newFakeMap("auto-ready", nil)
	config, err := (&services.SamplerConfig{Name: services.SamplerAlwaysOn}).Canonical()
	require.NoError(t, err)

	manager := newManager(nil, global, overrides, ready, autoReady, config,
		func(app.PID) (uint32, error) { return 101, nil })
	require.True(t, manager.InstallGlobal())

	assert.False(t, manager.AllowPIDForProcess(101, 0, 0, nil, true))
	assert.Empty(t, overrides.values)
	assert.Empty(t, ready.values)
	assert.Empty(t, autoReady.values)
	assert.Empty(t, manager.hostPIDs)
	assert.True(t, manager.FallbackSafeForProcess(101, 0))
}
