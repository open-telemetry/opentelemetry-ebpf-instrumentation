// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gotracer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
)

func TestGoAutoSDKInflightABI(t *testing.T) {
	assert.Equal(t, uintptr(24), unsafe.Sizeof(goAutoSDKReadinessValue{}))
	assert.Equal(
		t,
		uintptr(17),
		unsafe.Offsetof(goAutoSDKReadinessValue{}.AutoSDKGlobalReady),
	)
	assert.Equal(t, uintptr(32), unsafe.Sizeof(goAutoSDKInflightKey{}))
	assert.Equal(t, uintptr(8), unsafe.Sizeof(goAutoSDKInflightValue{}))
	assert.Equal(t, uintptr(0), unsafe.Offsetof(goAutoSDKInflightValue{}.State))
	assert.Equal(t, uintptr(32), unsafe.Sizeof(goAutoSDKOuterCallValue{}))
	assert.Equal(t, uintptr(29), unsafe.Offsetof(goAutoSDKOuterCallValue{}.DirectEntryKind))
	assert.Equal(t, uintptr(30), unsafe.Offsetof(goAutoSDKOuterCallValue{}.DirectDepth))
	assert.Equal(t, uintptr(31), unsafe.Offsetof(goAutoSDKOuterCallValue{}.RejectedReturns))
	assert.Equal(t, uint8(1), goAutoSDKOuterCallCapture)
	assert.Equal(t, uint8(2), goAutoSDKOuterCallActive)
	assert.Equal(t, uint8(3), goAutoSDKOuterCallConsumedActive)
	assert.Equal(t, uint8(4), goAutoSDKOuterCallDirectActive)
	assert.Equal(t, uint8(5), goAutoSDKOuterCallDirectConsumed)
	assert.Equal(t, uint8(6), goAutoSDKOuterCallPre)
	assert.Equal(t, uint64(0), goAutoSDKPendingPID)
}

func goAutoSDKInflightTestValue(
	activeCalls, poisonGeneration uint32,
) goAutoSDKInflightValue {
	return goAutoSDKInflightValue{
		State: uint64(poisonGeneration)<<goAutoSDKInflightPoisonShift |
			uint64(activeCalls),
	}
}

func setGoAutoSDKInflightActiveCalls(
	value *goAutoSDKInflightValue,
	activeCalls uint32,
) {
	*value = goAutoSDKInflightTestValue(activeCalls, value.poisonGeneration())
}

func setGoAutoSDKInflightPoisonGeneration(
	value *goAutoSDKInflightValue,
	poisonGeneration uint32,
) {
	*value = goAutoSDKInflightTestValue(value.activeCalls(), poisonGeneration)
}

func TestGoAutoSDKInflightPackedStateFailsClosed(t *testing.T) {
	state := goAutoSDKFlagState{
		key:       goProcessKey{PID: 42, Generation: 7},
		startTime: 100,
		epoch:     3,
	}
	key := goAutoSDKInflightKeyForState(state)
	inflight := &fakeGoAutoSDKInflightMap{
		values: map[goAutoSDKInflightKey]goAutoSDKInflightValue{
			key: goAutoSDKInflightTestValue(goAutoSDKMaxInflightCalls+1, 0),
		},
	}
	tracer := &Tracer{goAutoSDKInflight: inflight}

	_, err := tracer.goAutoSDKInflightCount(state)
	require.EqualError(t, err, "in-flight state is corrupt")

	inflight.values[key] = goAutoSDKInflightTestValue(0, 1)
	_, err = tracer.goAutoSDKInflightCount(state)
	require.EqualError(t, err, "in-flight state is poisoned")
}

func TestGoAutoSDKNewSpanAcquiresPREBeforeAdmissionSnapshots(t *testing.T) {
	source, err := os.ReadFile("../../../../bpf/gotracer/go_sdk.c")
	require.NoError(t, err)
	text := string(source)
	start := strings.Index(
		text,
		"int obi_uprobe_tracer_NewSpan(struct pt_regs *ctx)",
	)
	require.NotEqual(t, -1, start)
	end := strings.Index(
		text[start:],
		"SEC(\"uprobe/tracer_new_span_return\")",
	)
	require.NotEqual(t, -1, end)
	body := text[start : start+end]

	acquirePRE := strings.Index(
		body,
		"register_go_auto_sdk_pending_outer_call(",
	)
	readiness := strings.Index(body, "go_auto_sdk_global_activation_epoch()")
	generation := strings.Index(body, "go_process_generation(host_pid)")
	migrate := strings.Index(
		body,
		"migrate_go_auto_sdk_pending_capture(",
	)
	for _, position := range []int{acquirePRE, readiness, generation, migrate} {
		require.NotEqual(t, -1, position)
	}
	assert.Less(t, acquirePRE, readiness)
	assert.Less(t, acquirePRE, generation)
	assert.Less(t, generation, migrate)
	assert.Contains(t, body, ".state = k_go_auto_sdk_outer_pre")
	assert.NotContains(t, body, "finish_go_auto_sdk_active_call(",
		"only the owning NewSpan return may retire migrated ownership")
}

func TestGoAutoSDKStartWritesUnsampledOnlyAfterExactAdmission(t *testing.T) {
	source, err := os.ReadFile("../../../../bpf/gotracer/go_sdk.c")
	require.NoError(t, err)

	start := strings.Index(
		string(source),
		"int obi_uprobe_auto_sdk_tracer_Start(struct pt_regs *ctx)",
	)
	require.NotEqual(t, -1, start)
	end := strings.Index(
		string(source[start:]),
		"static __noinline void read_go_span_end_timestamp",
	)
	require.NotEqual(t, -1, end)
	body := string(source[start : start+end])

	forceUnsampled := strings.Index(
		body,
		"if (!force_go_auto_sdk_unsampled(sampled_ptr))",
	)
	require.NotEqual(t, -1, forceUnsampled)
	authorization := strings.Index(
		body,
		"if (owner == k_go_auto_sdk_handoff_none)",
	)
	require.NotEqual(t, -1, authorization)
	assert.Less(t, authorization, forceUnsampled,
		"ownerless private SDK calls must remain untouched")
	legacyReturn := strings.Index(
		body[authorization:],
		"return 0;",
	)
	require.NotEqual(t, -1, legacyReturn)
	ownerlessBlock := body[authorization : authorization+legacyReturn]
	assert.Contains(
		t,
		ownerlessBlock,
		"outer_call.generation != generation",
		"ownerless calls may clean a distinct stale generation but must preserve the current handoff",
	)
	assert.NotContains(
		t,
		ownerlessBlock,
		"delete_auto_sdk_span_infos",
		"ownerless calls must not delete current-generation legacy state",
	)
	assert.Equal(t, 1, strings.Count(ownerlessBlock, "delete_span_info_for_generation"))
	for _, validation := range []string{
		"if (!g_bpf_header_propagation || !span_context_offsets_available())",
		"go_auto_sdk_process_quiescing(",
		"if (!span_ptr)",
	} {
		position := strings.Index(body, validation)
		require.NotEqual(t, -1, position, validation)
		assert.Less(t, forceUnsampled, position, validation)
	}

	publish := strings.Index(
		body,
		"if (!publish_span_trace_parent(stored_span, &g_key, &s_key))",
	)
	result := strings.Index(
		body,
		"sampled = stored_span->tp.flags & k_flag_sampled",
	)
	require.NotEqual(t, -1, publish)
	require.NotEqual(t, -1, result)
	assert.Less(t, publish, result)
	assert.Equal(t, 1, strings.Count(body, "bpf_probe_write_user(sampled_ptr"))
}

func TestGoAutoSDKDirectAdmissionRequiresExactGlobalOwnership(t *testing.T) {
	source, err := os.ReadFile("../../../../bpf/gotracer/go_sdk.c")
	require.NoError(t, err)
	text := string(source)
	start := strings.Index(text, "static __always_inline int tracer_start(")
	require.NotEqual(t, -1, start)
	end := strings.Index(text[start:], "SEC(\"uprobe/tracer_Start\")")
	require.NotEqual(t, -1, end)
	body := text[start : start+end]

	exactGlobal := strings.Index(
		body,
		"go_auto_sdk_outer_call_is_exact_counted_global",
	)
	retireStale := strings.Index(
		body,
		"go_auto_sdk_outer_call_is_global(&outer)",
	)
	directCount := strings.Index(
		body,
		"mark_go_auto_sdk_direct_outer_call",
	)
	revalidateEpoch := strings.LastIndex(
		body,
		"current_auto_sdk_epoch != auto_sdk_epoch",
	)
	publishSpanInfo := strings.Index(body, "update_span_info(&g_key, &span_info)")

	for _, position := range []int{
		exactGlobal,
		retireStale,
		directCount,
		revalidateEpoch,
		publishSpanInfo,
	} {
		require.NotEqual(t, -1, position)
	}
	assert.Less(t, exactGlobal, retireStale)
	assert.Less(t, retireStale, directCount)
	assert.Less(t, directCount, revalidateEpoch)
	assert.Less(t, revalidateEpoch, publishSpanInfo)
	assert.NotContains(
		t,
		body,
		"if (existing && existing->global_handoff) {\n            return 0;",
	)
	assert.NotContains(
		t,
		body,
		"!generation || !start_time || !auto_sdk_epoch ||",
		"invalid direct entries must still record their matching return",
	)
	assert.NotContains(t, body, "retire_go_auto_sdk_outer_call")
}

type fakeGoAutoSDKFlagMap struct {
	values     map[goProcessKey]goAutoSDKFlagValue
	putErrors  []error
	deleteErr  error
	operations *[]string
}

func (m *fakeGoAutoSDKFlagMap) Lookup(key, valueOut any) error {
	value, ok := m.values[key.(goProcessKey)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*valueOut.(*goAutoSDKFlagValue) = value
	return nil
}

func (m *fakeGoAutoSDKFlagMap) Put(key, value any) error {
	if m.operations != nil {
		*m.operations = append(*m.operations,
			fmt.Sprintf("flag:%d", value.(goAutoSDKFlagValue).Activated))
	}
	if len(m.putErrors) != 0 {
		err := m.putErrors[0]
		m.putErrors = m.putErrors[1:]
		if err != nil {
			return err
		}
	}
	m.values[key.(goProcessKey)] = value.(goAutoSDKFlagValue)
	return nil
}

func (m *fakeGoAutoSDKFlagMap) Delete(key any) error {
	if m.operations != nil {
		*m.operations = append(*m.operations, "flag:delete")
	}
	if m.deleteErr != nil {
		return m.deleteErr
	}
	processKey := key.(goProcessKey)
	if _, ok := m.values[processKey]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.values, processKey)
	return nil
}

type fakeGoAutoSDKReadinessMap struct {
	values map[uint32]goAutoSDKReadinessValue
	err    error
}

func (m *fakeGoAutoSDKReadinessMap) Lookup(key, valueOut any) error {
	if m.err != nil {
		return m.err
	}
	value, ok := m.values[key.(uint32)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*valueOut.(*goAutoSDKReadinessValue) = value
	return nil
}

type fakeGoAutoSDKOuterCallMap struct {
	values     map[goAddrKey]goAutoSDKOuterCallValue
	operations *[]string
	deleteErr  error
}

type fakeGoAutoSDKInflightMap struct {
	values     map[goAutoSDKInflightKey]goAutoSDKInflightValue
	lookupErr  error
	updateErr  error
	deleteErr  error
	operations *[]string
	lookupHook func(goAutoSDKInflightKey)
}

func (m *fakeGoAutoSDKInflightMap) Lookup(key, valueOut any) error {
	if m.operations != nil {
		*m.operations = append(*m.operations, "inflight:lookup")
	}
	if m.lookupErr != nil {
		return m.lookupErr
	}
	inflightKey := key.(goAutoSDKInflightKey)
	if m.lookupHook != nil {
		m.lookupHook(inflightKey)
	}
	value, ok := m.values[inflightKey]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*valueOut.(*goAutoSDKInflightValue) = value
	return nil
}

func (m *fakeGoAutoSDKInflightMap) Update(
	key, value any,
	flags ebpf.MapUpdateFlags,
) error {
	if m.operations != nil {
		*m.operations = append(*m.operations, "inflight:provision")
	}
	if m.updateErr != nil {
		return m.updateErr
	}
	inflightKey := key.(goAutoSDKInflightKey)
	if flags == ebpf.UpdateNoExist {
		if _, ok := m.values[inflightKey]; ok {
			return ebpf.ErrKeyExist
		}
	}
	m.values[inflightKey] = value.(goAutoSDKInflightValue)
	return nil
}

func (m *fakeGoAutoSDKInflightMap) Delete(key any) error {
	if m.operations != nil {
		*m.operations = append(*m.operations, "inflight:delete")
	}
	if m.deleteErr != nil {
		return m.deleteErr
	}
	inflightKey := key.(goAutoSDKInflightKey)
	if _, ok := m.values[inflightKey]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.values, inflightKey)
	return nil
}

func (m *fakeGoAutoSDKOuterCallMap) Lookup(key, valueOut any) error {
	value, ok := m.values[key.(goAddrKey)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*valueOut.(*goAutoSDKOuterCallValue) = value
	return nil
}

func (m *fakeGoAutoSDKOuterCallMap) NextKey(key, nextKeyOut any) error {
	if m.operations != nil {
		*m.operations = append(*m.operations, "outer:scan")
	}
	keys := make([]goAddrKey, 0, len(m.values))
	for candidate := range m.values {
		keys = append(keys, candidate)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].PID != keys[j].PID {
			return keys[i].PID < keys[j].PID
		}
		return keys[i].Addr < keys[j].Addr
	})
	if len(keys) == 0 {
		return ebpf.ErrKeyNotExist
	}
	if key == nil {
		*nextKeyOut.(*goAddrKey) = keys[0]
		return nil
	}
	previous := key.(*goAddrKey)
	for i := range keys {
		if keys[i] == *previous && i+1 < len(keys) {
			*nextKeyOut.(*goAddrKey) = keys[i+1]
			return nil
		}
	}
	return ebpf.ErrKeyNotExist
}

func (m *fakeGoAutoSDKOuterCallMap) Delete(key any) error {
	if m.operations != nil {
		*m.operations = append(*m.operations, "outer:delete")
	}
	if m.deleteErr != nil {
		return m.deleteErr
	}
	outerKey := key.(goAddrKey)
	if _, ok := m.values[outerKey]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.values, outerKey)
	return nil
}

type fakeGoAutoSDKReadResult struct {
	value byte
	err   error
}

type fakeGoAutoSDKWriteResult struct {
	err   error
	apply bool
}

type fakeGoAutoSDKStartResult struct {
	startTime uint64
	err       error
}

type fakeGoAutoSDKProcessAccess struct {
	mu               sync.Mutex
	startTimes       map[uint32]uint64
	startErr         error
	sessionErr       error
	startResults     []fakeGoAutoSDKStartResult
	pinErr           error
	memory           map[uint64]byte
	readResults      []fakeGoAutoSDKReadResult
	writeResults     []fakeGoAutoSDKWriteResult
	memoryByFileInfo map[*exec.FileInfo]map[uint64]byte
	openCalls        int
	readCalls        int
	writeCalls       int
	closeCalls       int
	operations       *[]string
}

type fakeGoAutoSDKProcessSession struct {
	access    *fakeGoAutoSDKProcessAccess
	startTime uint64
	startErr  error
	memory    map[uint64]byte
	closed    bool
}

func (a *fakeGoAutoSDKProcessAccess) Open(
	_ *os.File,
	fileInfo *exec.FileInfo,
) (goAutoSDKProcessSession, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.openCalls++
	if a.pinErr != nil {
		return nil, a.pinErr
	}
	memory := a.memory
	if exact := a.memoryByFileInfo[fileInfo]; exact != nil {
		memory = exact
	}
	return &fakeGoAutoSDKProcessSession{
		access:    a,
		startTime: a.startTimes[uint32(fileInfo.Pid())],
		startErr:  a.startErr,
		memory:    memory,
	}, nil
}

func (s *fakeGoAutoSDKProcessSession) Read(addr uint64) (byte, error) {
	s.access.mu.Lock()
	defer s.access.mu.Unlock()
	s.access.readCalls++
	if s.access.operations != nil {
		*s.access.operations = append(*s.access.operations, "memory:read")
	}
	if len(s.access.readResults) != 0 {
		result := s.access.readResults[0]
		s.access.readResults = s.access.readResults[1:]
		return result.value, result.err
	}
	return s.memory[addr], nil
}

func (s *fakeGoAutoSDKProcessSession) Write(addr uint64, value byte) error {
	s.access.mu.Lock()
	defer s.access.mu.Unlock()
	s.access.writeCalls++
	if s.access.operations != nil {
		*s.access.operations = append(*s.access.operations,
			fmt.Sprintf("memory:write:%d", value))
	}
	if len(s.access.writeResults) != 0 {
		result := s.access.writeResults[0]
		s.access.writeResults = s.access.writeResults[1:]
		if result.apply {
			s.memory[addr] = value
		}
		return result.err
	}
	s.memory[addr] = value
	return nil
}

func (s *fakeGoAutoSDKProcessSession) StartTime() (uint64, error) {
	s.access.mu.Lock()
	defer s.access.mu.Unlock()
	if len(s.access.startResults) != 0 {
		result := s.access.startResults[0]
		s.access.startResults = s.access.startResults[1:]
		return result.startTime, result.err
	}
	if s.access.sessionErr != nil {
		return 0, s.access.sessionErr
	}
	if s.startErr != nil {
		return 0, s.startErr
	}
	return s.startTime, nil
}

func (s *fakeGoAutoSDKProcessSession) Close() error {
	s.access.mu.Lock()
	defer s.access.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.access.closeCalls++
	return nil
}

type fakeGoAutoSDKSamplerManager struct {
	quiesceOK    bool
	fallbackSafe bool
	blockOK      bool
	enableFails  bool
	publishFails bool
	blockResults []bool
	quiesceCalls int
	enableCalls  int
	blockCalls   int
	globalModes  []bool
	autoReady    bool
	startTime    uint64
	epoch        uint32
	operations   *[]string
}

func (*fakeGoAutoSDKSamplerManager) InstallGlobal() bool {
	return true
}

func (*fakeGoAutoSDKSamplerManager) AllowPIDForProcess(
	app.PID,
	uint32,
	uint64,
	*services.CanonicalSampler,
	bool,
) bool {
	return true
}

func (m *fakeGoAutoSDKSamplerManager) FallbackSafeForProcessIncarnation(
	app.PID,
	uint32,
	uint64,
) bool {
	return m.fallbackSafe
}

func (m *fakeGoAutoSDKSamplerManager) EnableAutoSDK(pid app.PID, ns uint32) bool {
	return m.EnableAutoSDKWithSetup(pid, ns, nil)
}

func (m *fakeGoAutoSDKSamplerManager) EnableAutoSDKWithSetup(
	pid app.PID,
	ns uint32,
	beforePublish func(hostPID uint32, startTime uint64, epoch uint32) bool,
) bool {
	return m.EnableAutoSDKWithSetupMode(pid, ns, true, beforePublish)
}

func (m *fakeGoAutoSDKSamplerManager) EnableAutoSDKWithSetupMode(
	pid app.PID,
	_ uint32,
	globalProtocol bool,
	beforePublish func(hostPID uint32, startTime uint64, epoch uint32) bool,
) bool {
	m.enableCalls++
	m.globalModes = append(m.globalModes, globalProtocol)
	if m.enableFails {
		return false
	}
	startTime := m.startTime
	if startTime == 0 {
		startTime = 90000000
	}
	epoch := m.epoch
	if epoch == 0 {
		epoch = 5
	}
	if beforePublish != nil &&
		!beforePublish(uint32(pid), startTime, epoch) {
		return false
	}
	if m.operations != nil {
		*m.operations = append(*m.operations, "readiness:publish")
	}
	if m.publishFails {
		return false
	}
	m.autoReady = true
	return true
}

func (m *fakeGoAutoSDKSamplerManager) QuiesceAutoSDKForProcess(
	app.PID,
	uint32,
	uint64,
) bool {
	m.quiesceCalls++
	m.autoReady = false
	if m.operations != nil {
		*m.operations = append(*m.operations, "readiness:quiesce")
	}
	return m.quiesceOK
}

func (m *fakeGoAutoSDKSamplerManager) BlockPIDForProcess(
	app.PID,
	uint32,
	uint64,
) bool {
	m.blockCalls++
	blockOK := m.blockOK
	if len(m.blockResults) != 0 {
		blockOK = m.blockResults[0]
		m.blockResults = m.blockResults[1:]
	}
	if blockOK {
		m.autoReady = false
	}
	return blockOK
}

type blockingEnableGoAutoSDKSamplerManager struct {
	*fakeGoAutoSDKSamplerManager
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (m *blockingEnableGoAutoSDKSamplerManager) EnableAutoSDKWithSetup(
	pid app.PID,
	ns uint32,
	beforePublish func(hostPID uint32, startTime uint64, epoch uint32) bool,
) bool {
	return m.EnableAutoSDKWithSetupMode(pid, ns, true, beforePublish)
}

func (m *blockingEnableGoAutoSDKSamplerManager) EnableAutoSDKWithSetupMode(
	pid app.PID,
	ns uint32,
	globalProtocol bool,
	beforePublish func(hostPID uint32, startTime uint64, epoch uint32) bool,
) bool {
	m.once.Do(func() {
		close(m.entered)
	})
	<-m.release
	return m.fakeGoAutoSDKSamplerManager.EnableAutoSDKWithSetupMode(
		pid,
		ns,
		globalProtocol,
		beforePublish,
	)
}

type blockingQuiesceGoAutoSDKSamplerManager struct {
	*fakeGoAutoSDKSamplerManager
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (m *blockingQuiesceGoAutoSDKSamplerManager) QuiesceAutoSDKForProcess(
	pid app.PID,
	ns uint32,
	startTime uint64,
) bool {
	m.once.Do(func() {
		close(m.entered)
	})
	<-m.release
	return m.fakeGoAutoSDKSamplerManager.QuiesceAutoSDKForProcess(
		pid,
		ns,
		startTime,
	)
}

type fakeGoTracerCloser struct {
	closed     int
	operation  string
	operations *[]string
	closeErrs  []error
}

func (c *fakeGoTracerCloser) Close() error {
	c.closed++
	if c.operations != nil {
		operation := c.operation
		if operation == "" {
			operation = "links:close"
		}
		*c.operations = append(*c.operations, operation)
	}
	if len(c.closeErrs) != 0 {
		err := c.closeErrs[0]
		c.closeErrs = c.closeErrs[1:]
		return err
	}
	return nil
}

type blockingGoTracerCloser struct {
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (c *blockingGoTracerCloser) Close() error {
	c.once.Do(func() {
		close(c.entered)
	})
	<-c.release
	return nil
}

func TestGoAutoSDKAdmissionEntryAttachmentGatePublishesSuccess(t *testing.T) {
	tracer := &Tracer{}
	fileInfo := exec.New(exec.Init{Ino: 1})
	closer := &fakeGoTracerCloser{}
	symbol := goAutoSDKStartProbeSymbols[0]

	require.True(
		t,
		tracer.BeginGoAutoSDKAdmissionEntryAttachment(fileInfo, symbol),
	)
	assert.Equal(t, 1, tracer.goAutoSDKDirectEntryAttaching)

	tracer.FinishGoAutoSDKAdmissionEntryAttachment(
		fileInfo,
		symbol,
		closer,
		nil,
	)

	assert.Zero(t, tracer.goAutoSDKDirectEntryAttaching)
	assert.Zero(t, closer.closed)
	assert.Equal(t, []io.Closer{closer}, tracer.goAutoSDKDirectEntryClosers)
}

func TestGoAutoSDKAdmissionEntryAttachmentGateRejectsAfterBarrier(t *testing.T) {
	tracer := &Tracer{goAutoSDKDirectEntryBarrierClosed: true}
	fileInfo := exec.New(exec.Init{Ino: 1})

	assert.False(
		t,
		tracer.BeginGoAutoSDKAdmissionEntryAttachment(
			fileInfo,
			goAutoSDKStartProbeSymbols[0],
		),
	)
	assert.Zero(t, tracer.goAutoSDKDirectEntryAttaching)
}

func TestGoAutoSDKAdmissionEntryAttachmentTokenBlocksSafeShutdown(
	t *testing.T,
) {
	tracer := &Tracer{}
	fileInfo := exec.New(exec.Init{Ino: 1})
	symbol := goAutoSDKStartProbeSymbols[0]
	closeErr := errors.New("late close failed")
	closer := &fakeGoTracerCloser{closeErrs: []error{closeErr, nil}}

	require.True(
		t,
		tracer.BeginGoAutoSDKAdmissionEntryAttachment(fileInfo, symbol),
	)
	assert.False(t, tracer.shutdownGoAutoSDK())
	assert.False(t, tracer.goAutoSDKShutdownComplete)

	tracer.FinishGoAutoSDKAdmissionEntryAttachment(
		fileInfo,
		symbol,
		closer,
		nil,
	)

	assert.Zero(t, tracer.goAutoSDKDirectEntryAttaching)
	assert.Zero(t, tracer.goAutoSDKDirectEntryClosing)
	assert.Equal(t, []io.Closer{closer}, tracer.goAutoSDKDirectEntryClosers)
	assert.False(t, tracer.goAutoSDKShutdownComplete)
	require.True(t, tracer.shutdownGoAutoSDK())
	assert.Equal(t, 2, closer.closed)
	assert.Empty(t, tracer.goAutoSDKDirectEntryClosers)
	assert.True(t, tracer.goAutoSDKShutdownComplete)
}

func TestGoAutoSDKShutdownBeforeRunClosesRetainedProcessRoot(t *testing.T) {
	processRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	fileInfo := exec.New(exec.Init{Pid: 42, Ns: 17, StartTime: 100})
	process := runtimeMetricTargetKey{pid: fileInfo.Pid(), ns: fileInfo.Ns()}
	tracer := &Tracer{
		goProcessAdmissions: map[runtimeMetricTargetKey]goProcessAdmissionState{
			process: {
				startTime:   fileInfo.StartTime(),
				fileInfo:    fileInfo,
				processRoot: newGoAutoSDKProcessRoot(processRoot),
			},
		},
		goProcessGenerationByPID: map[runtimeMetricTargetKey]goProcessGenerationState{},
		goAutoSDKRestoreRetries:  map[goAutoSDKRestoreRetryKey]bool{},
	}

	require.True(t, tracer.shutdownGoAutoSDK())

	_, err = processRoot.Stat()
	require.Error(t, err)
	assert.Empty(t, tracer.goProcessAdmissions)
}

func TestGoAutoSDKAdmissionEntryLateCloseDoesNotHoldProcessLock(t *testing.T) {
	tracer := &Tracer{}
	fileInfo := exec.New(exec.Init{Ino: 1})
	symbol := goAutoSDKStartProbeSymbols[0]
	closeEntered := make(chan struct{})
	closeRelease := make(chan struct{})
	closer := &blockingGoTracerCloser{
		entered: closeEntered,
		release: closeRelease,
	}

	require.True(
		t,
		tracer.BeginGoAutoSDKAdmissionEntryAttachment(fileInfo, symbol),
	)
	tracer.processMu.Lock()
	tracer.goAutoSDKDirectEntryBarrierClosed = true
	tracer.goAutoSDKShuttingDown = true
	tracer.processMu.Unlock()

	finished := make(chan struct{})
	go func() {
		tracer.FinishGoAutoSDKAdmissionEntryAttachment(
			fileInfo,
			symbol,
			closer,
			nil,
		)
		close(finished)
	}()
	select {
	case <-closeEntered:
	case <-time.After(time.Second):
		t.Fatal("late admission-entry close did not start")
	}

	lockAcquired := make(chan struct{})
	go func() {
		tracer.processMu.Lock()
		defer tracer.processMu.Unlock()
		close(lockAcquired)
	}()
	select {
	case <-lockAcquired:
	case <-time.After(time.Second):
		t.Fatal("late admission-entry close held processMu")
	}

	close(closeRelease)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("late admission-entry close did not finish")
	}
}

func TestGoAutoSDKPartialAdmissionEntryRollbackRetainsFailure(t *testing.T) {
	tracer := &Tracer{}
	fileInfo := exec.New(exec.Init{Ino: 1})
	symbol := goAutoSDKStartProbeSymbols[0]
	attachmentErr := errors.New("return attachment failed")
	closeErr := errors.New("entry rollback failed")
	closer := &fakeGoTracerCloser{closeErrs: []error{closeErr, nil}}

	require.True(
		t,
		tracer.BeginGoAutoSDKAdmissionEntryAttachment(fileInfo, symbol),
	)
	tracer.FinishGoAutoSDKAdmissionEntryAttachment(
		fileInfo,
		symbol,
		closer,
		attachmentErr,
	)

	assert.Equal(t, 1, closer.closed)
	assert.Equal(t, []io.Closer{closer}, tracer.goAutoSDKDirectEntryClosers)
	assert.Zero(t, tracer.goAutoSDKDirectEntryAttaching)
	assert.Zero(t, tracer.goAutoSDKDirectEntryClosing)
	require.True(t, tracer.shutdownGoAutoSDK())
	assert.Equal(t, 2, closer.closed)
}

type fakeGoAutoSDKEventReader struct {
	mu         sync.Mutex
	readErr    error
	closed     chan struct{}
	closeOnce  sync.Once
	closeCalls int
	closeErrs  []error
}

func newFakeGoAutoSDKEventReader(readErr error) *fakeGoAutoSDKEventReader {
	return &fakeGoAutoSDKEventReader{
		readErr: readErr,
		closed:  make(chan struct{}),
	}
}

func (r *fakeGoAutoSDKEventReader) Read() (ringbuf.Record, error) {
	if r.readErr != nil {
		return ringbuf.Record{}, r.readErr
	}
	<-r.closed
	return ringbuf.Record{}, ringbuf.ErrClosed
}

func (r *fakeGoAutoSDKEventReader) Close() error {
	r.mu.Lock()
	r.closeCalls++
	if len(r.closeErrs) != 0 {
		err := r.closeErrs[0]
		r.closeErrs = r.closeErrs[1:]
		if err != nil {
			r.mu.Unlock()
			return err
		}
	}
	r.mu.Unlock()
	r.closeOnce.Do(func() {
		close(r.closed)
	})
	return nil
}

func (r *fakeGoAutoSDKEventReader) CloseCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closeCalls
}

func newGoAutoSDKLifecycleTestTracer(
	t *testing.T,
) (*Tracer, runtimeMetricTargetKey, goProcessKey, uint64, *fakeGoAutoSDKFlagMap,
	*fakeGoAutoSDKProcessAccess, *fakeGoAutoSDKSamplerManager,
) {
	t.Helper()

	const (
		hostPID    = uint32(123)
		startTime  = uint64(90000000)
		generation = uint64(17)
		epoch      = uint32(5)
		flagPtr    = uint64(0x123400)
	)
	process := runtimeMetricTargetKey{pid: app.PID(hostPID), ns: 7}
	key := goProcessKey{PID: uint64(hostPID), Generation: generation}
	flagMap := &fakeGoAutoSDKFlagMap{
		values: map[goProcessKey]goAutoSDKFlagValue{
			key: {
				FlagPtr:   flagPtr,
				StartTime: startTime,
				Epoch:     epoch,
			},
		},
	}
	access := &fakeGoAutoSDKProcessAccess{
		startTimes: map[uint32]uint64{hostPID: startTime},
		memory:     map[uint64]byte{flagPtr: 0},
	}
	sampler := &fakeGoAutoSDKSamplerManager{
		quiesceOK:    true,
		fallbackSafe: true,
		blockOK:      true,
		autoReady:    true,
	}
	fileInfo := exec.New(exec.Init{
		Pid:       app.PID(hostPID),
		Ns:        process.ns,
		StartTime: startTime,
	})
	tracer := &Tracer{
		log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		goAutoSDKFlags: flagMap,
		goAutoSDKReadiness: &fakeGoAutoSDKReadinessMap{values: map[uint32]goAutoSDKReadinessValue{
			hostPID: {
				StartTime:          startTime,
				Epoch:              epoch,
				Ready:              1,
				AutoSDKGlobalReady: 1,
			},
		}},
		goAutoSDKOuterCalls:     &fakeGoAutoSDKOuterCallMap{values: map[goAddrKey]goAutoSDKOuterCallValue{}},
		goAutoSDKInflight:       &fakeGoAutoSDKInflightMap{values: map[goAutoSDKInflightKey]goAutoSDKInflightValue{}},
		goAutoSDKProcessAccess:  access,
		goAutoSDKDiscoveryReady: true,
		goAutoSDKTailCallsReady: true,
		goAutoSDKGlobalReadyByExecutable: map[goExecutableKey]bool{
			testGoExecutableKeyFor(fileInfo): true,
		},
		goAutoSDKAdmissions: map[runtimeMetricTargetKey]goAutoSDKAdmissionState{
			process: {
				startTime:        startTime,
				executable:       testGoExecutableKeyFor(fileInfo),
				globalReady:      true,
				globalPatchReady: true,
				authorityActive:  true,
				fileInfo:         fileInfo,
			},
		},
		goAutoSDKFlagStates: map[runtimeMetricTargetKey]goAutoSDKFlagState{},
		goAutoSDKQuiescing:  map[runtimeMetricTargetKey]bool{},
		goAutoSDKDrainPause: func() {},
		goProcessGenerationByPID: map[runtimeMetricTargetKey]goProcessGenerationState{
			process: {
				hostPID:    hostPID,
				generation: generation,
				fileInfo:   fileInfo,
			},
		},
		goProcessAdmissions: map[runtimeMetricTargetKey]goProcessAdmissionState{
			process: {
				startTime:   startTime,
				fileInfo:    fileInfo,
				processRoot: newGoAutoSDKProcessRoot(nil),
			},
		},
		goProcessOwnerByHostPID: map[uint32]runtimeMetricTargetKey{hostPID: process},
		samplerManager:          sampler,
	}
	require.True(
		t,
		tracer.provisionGoAutoSDKInflight(goAutoSDKPendingState()),
	)
	tracer.goAutoSDKPreAdmissionReady = true
	require.True(
		t,
		tracer.prepareGoAutoSDKDirectAdmission(
			process,
			hostPID,
			startTime,
			epoch,
			true,
		),
	)
	return tracer, process, key, flagPtr, flagMap, access, sampler
}

func TestGoAutoSDKAdmissionBeforeRunStaysQuiescent(t *testing.T) {
	const flagPtr = uint64(0x123400)
	filter := &recordingServiceFilter{}
	access := &fakeGoAutoSDKProcessAccess{
		startTimes: map[uint32]uint64{123: 90000000},
		memory:     map[uint64]byte{flagPtr: 0},
	}
	sampler := &fakeGoAutoSDKSamplerManager{
		quiesceOK:    true,
		fallbackSafe: true,
		blockOK:      true,
	}
	readerCreations := 0
	tracer := &Tracer{
		log:                           slog.New(slog.NewTextHandler(io.Discard, nil)),
		pidsFilter:                    filter,
		samplerManager:                sampler,
		goAutoSDKProcessAccess:        access,
		goProcessGenerationByPID:      map[runtimeMetricTargetKey]goProcessGenerationState{},
		goProcessOwnerByHostPID:       map[uint32]runtimeMetricTargetKey{},
		goAutoSDKQuiescing:            map[runtimeMetricTargetKey]bool{},
		goAutoSDKAdmissions:           map[runtimeMetricTargetKey]goAutoSDKAdmissionState{},
		goAutoSDKRestoreRetries:       map[goAutoSDKRestoreRetryKey]bool{},
		goSpanOptionFuncsByExecutable: map[goExecutableKey][]goSpanOptionFunction{},
		goSpanOptionKeysByProcess:     map[runtimeMetricTargetKey][]goSpanOptionFunctionKey{},
		goAutoSDKTypesByExecutable:    map[goExecutableKey]goexec.GoAutoSDKTypeInfo{},
		goAutoSDKTypeInfoKeys:         map[runtimeMetricTargetKey]goProcessKey{},
		newGoAutoSDKEventReader: func(*ebpf.Map) (goAutoSDKEventReader, error) {
			readerCreations++
			return newFakeGoAutoSDKEventReader(nil), nil
		},
	}
	tracer.bpfObjects.GoAutoSdkFlagEvents = &ebpf.Map{}
	tracer.SetEventContext(ebpfcommon.NewEBPFEventContext())

	admitted := tracer.AllowPIDForProcess(123, 0, exec.New(exec.Init{
		Pid:       123,
		StartTime: 90000000,
	}))

	assert.True(t, admitted)
	assert.False(t, tracer.goAutoSDKRunStarted)
	assert.False(t, tracer.goAutoSDKDiscoveryReady)
	assert.Nil(t, tracer.goAutoSDKEventReader)
	assert.Zero(t, readerCreations)
	assert.Zero(t, sampler.enableCalls)
	assert.False(t, sampler.autoReady)
	assert.Zero(t, access.writeCalls)
	assert.Zero(t, access.memory[flagPtr])
}

func TestGoAutoSDKRunStartEnablesTrackedAdmissions(t *testing.T) {
	tracer, process, _, _, _, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	const ino = uint64(55)
	tracer.goAutoSDKDiscoveryReady = false
	tracer.goAutoSDKTailCallsReady = true
	tracer.goAutoSDKReadyByExecutable = map[goExecutableKey]bool{testGoExecutableKey(ino): true}
	tracer.goAutoSDKGlobalReadyByExecutable = map[goExecutableKey]bool{testGoExecutableKey(ino): true}
	tracer.goAutoSDKAdmissions = map[runtimeMetricTargetKey]goAutoSDKAdmissionState{
		process: {
			startTime:            tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
			executable:           testGoExecutableKey(ino),
			samplerReady:         true,
			generationReady:      true,
			optionFunctionsReady: true,
			typeInfoReady:        true,
			globalReady:          true,
			globalPatchReady:     true,
			fileInfo:             tracer.goProcessGenerationByPID[process].fileInfo,
		},
	}
	prepared := tracer.goAutoSDKFlagStates[process]
	prepared.globalProtocol = true
	tracer.goAutoSDKFlagStates[process] = prepared
	rawReader := newFakeGoAutoSDKEventReader(nil)
	tracer.newGoAutoSDKEventReader = func(*ebpf.Map) (goAutoSDKEventReader, error) {
		return rawReader, nil
	}
	tracer.bpfObjects.GoAutoSdkFlagEvents = &ebpf.Map{}

	tracer.startGoAutoSDKRun(context.Background())

	assert.True(t, tracer.goAutoSDKRunStarted)
	assert.True(t, tracer.goAutoSDKDiscoveryReady)
	assert.NotNil(t, tracer.goAutoSDKEventReader)
	assert.Equal(t, 1, sampler.enableCalls)
	assert.True(t, sampler.autoReady)
	assert.Equal(t, []bool{true}, sampler.globalModes)
	assert.Zero(t, access.writeCalls)

	tracer.processMu.Lock()
	tracer.goAutoSDKShuttingDown = true
	reader := tracer.goAutoSDKEventReader
	tracer.processMu.Unlock()
	require.NoError(t, reader.Close())
	tracer.goAutoSDKEventWG.Wait()
	assert.Equal(t, 1, rawReader.CloseCalls())
}

func TestGoAutoSDKRunStartEnablesDirectOnlyWithoutDiscoveryReader(t *testing.T) {
	tracer, process, _, _, _, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	const ino = uint64(55)
	prepared := tracer.goAutoSDKFlagStates[process]
	delete(tracer.goAutoSDKFlagStates, process)
	delete(
		tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap).values,
		goAutoSDKInflightKeyForState(prepared),
	)
	sampler.autoReady = false
	tracer.goAutoSDKDiscoveryReady = false
	tracer.goAutoSDKPreAdmissionReady = false
	tracer.goAutoSDKTailCallsReady = true
	tracer.goAutoSDKReadyByExecutable = map[goExecutableKey]bool{testGoExecutableKey(ino): true}
	tracer.goAutoSDKGlobalReadyByExecutable = map[goExecutableKey]bool{testGoExecutableKey(ino): false}
	tracer.goAutoSDKAdmissions = map[runtimeMetricTargetKey]goAutoSDKAdmissionState{
		process: {
			startTime:            tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
			executable:           testGoExecutableKey(ino),
			samplerReady:         true,
			generationReady:      true,
			optionFunctionsReady: true,
			typeInfoReady:        true,
			fileInfo:             tracer.goProcessGenerationByPID[process].fileInfo,
		},
	}
	readerCreations := 0
	tracer.newGoAutoSDKEventReader = func(*ebpf.Map) (goAutoSDKEventReader, error) {
		readerCreations++
		return nil, errors.New("reader unavailable")
	}
	tracer.bpfObjects.GoAutoSdkFlagEvents = &ebpf.Map{}

	tracer.startGoAutoSDKRun(context.Background())

	assert.True(t, tracer.goAutoSDKRunStarted)
	assert.False(t, tracer.goAutoSDKDiscoveryReady)
	assert.Nil(t, tracer.goAutoSDKEventReader)
	assert.Zero(t, readerCreations)
	assert.Equal(t, 1, sampler.enableCalls)
	assert.True(t, sampler.autoReady)
	assert.Equal(t, []bool{false}, sampler.globalModes)
	assert.Zero(t, access.writeCalls)
	directState, ok := tracer.goAutoSDKFlagStates[process]
	require.True(t, ok)
	assert.False(t, directState.globalProtocol)
}

func TestGoAutoSDKAdmissionPreparesCounterBeforeReadiness(t *testing.T) {
	tracer, process, _, _, _, _, sampler := newGoAutoSDKLifecycleTestTracer(t)
	const ino = uint64(55)
	var operations []string
	inflight := tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap)
	inflight.operations = &operations
	sampler.operations = &operations
	tracer.goAutoSDKTailCallsReady = true
	tracer.goAutoSDKReadyByExecutable = map[goExecutableKey]bool{testGoExecutableKey(ino): true}
	tracer.goAutoSDKGlobalReadyByExecutable = map[goExecutableKey]bool{testGoExecutableKey(ino): true}
	admission := goAutoSDKAdmissionState{
		startTime:            tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
		executable:           testGoExecutableKey(ino),
		samplerReady:         true,
		generationReady:      true,
		optionFunctionsReady: true,
		typeInfoReady:        true,
		globalReady:          true,
		globalPatchReady:     true,
		fileInfo:             tracer.goProcessGenerationByPID[process].fileInfo,
	}
	tracer.goAutoSDKAdmissions[process] = admission

	tracer.processMu.Lock()
	admitted := tracer.reconcileGoAutoSDKAdmission(process, admission)
	tracer.processMu.Unlock()

	require.True(t, admitted)
	assert.Less(
		t,
		operationIndex(t, operations, "inflight:lookup"),
		operationIndex(t, operations, "readiness:publish"),
	)
	assert.True(t, sampler.autoReady)
	assert.Contains(t, tracer.goAutoSDKFlagStates, process)
}

func TestGoAutoSDKPublicationFailureCleansPreparedCounter(t *testing.T) {
	tracer, process, _, _, _, _, sampler := newGoAutoSDKLifecycleTestTracer(t)
	const ino = uint64(55)
	tracer.goAutoSDKTailCallsReady = true
	tracer.goAutoSDKReadyByExecutable = map[goExecutableKey]bool{testGoExecutableKey(ino): true}
	sampler.publishFails = true
	sampler.autoReady = false
	admission := goAutoSDKAdmissionState{
		startTime:            tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
		executable:           testGoExecutableKey(ino),
		samplerReady:         true,
		generationReady:      true,
		optionFunctionsReady: true,
		typeInfoReady:        true,
		fileInfo:             tracer.goProcessGenerationByPID[process].fileInfo,
	}
	tracer.goAutoSDKAdmissions[process] = admission

	tracer.processMu.Lock()
	admitted := tracer.reconcileGoAutoSDKAdmission(process, admission)
	tracer.processMu.Unlock()

	require.True(t, admitted)
	assert.False(t, sampler.autoReady)
	assert.Equal(t, 1, sampler.blockCalls)
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.Equal(
		t,
		map[goAutoSDKInflightKey]goAutoSDKInflightValue{
			goAutoSDKInflightKeyForState(goAutoSDKPendingState()): {},
		},
		tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap).values,
	)
}

func TestGoAutoSDKReadyAdmissionRestoresFallbackAfterEnableFailure(t *testing.T) {
	tracer, process, _, _, _, _, sampler := newGoAutoSDKLifecycleTestTracer(t)
	const ino = uint64(55)
	processRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	processAdmission := tracer.goProcessAdmissions[process]
	processAdmission.processRoot = newGoAutoSDKProcessRoot(processRoot)
	tracer.goProcessAdmissions[process] = processAdmission
	tracer.goAutoSDKTailCallsReady = true
	tracer.goAutoSDKReadyByExecutable = map[goExecutableKey]bool{testGoExecutableKey(ino): true}
	sampler.enableFails = true
	sampler.autoReady = true
	admission := goAutoSDKAdmissionState{
		startTime:            tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
		executable:           testGoExecutableKey(ino),
		samplerReady:         true,
		generationReady:      true,
		optionFunctionsReady: true,
		typeInfoReady:        true,
		fileInfo:             tracer.goProcessGenerationByPID[process].fileInfo,
	}
	tracer.goAutoSDKAdmissions[process] = admission

	tracer.processMu.Lock()
	admitted := tracer.reconcileGoAutoSDKAdmission(process, admission)
	tracer.processMu.Unlock()

	assert.True(t, admitted)
	assert.Equal(t, 1, sampler.enableCalls)
	assert.Equal(t, 1, sampler.blockCalls)
	assert.False(t, sampler.autoReady)
	assert.Empty(t, tracer.goAutoSDKRestoreRetries)
	assert.NotContains(t, tracer.goAutoSDKAdmissions, process)
	assert.Nil(t, tracer.goProcessAdmissions[process].processRoot)
	_, err = processRoot.Stat()
	require.Error(t, err)
}

func TestGoAutoSDKDirectAdmissionDoesNotRequireProcessMemory(t *testing.T) {
	tracer, process, key, _, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	const ino = uint64(55)
	prepared := tracer.goAutoSDKFlagStates[process]
	require.NoError(t, prepared.incarnation.Close())
	delete(tracer.goAutoSDKFlagStates, process)
	delete(
		tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap).values,
		goAutoSDKInflightKeyForState(prepared),
	)
	delete(flagMap.values, key)
	processAdmission := tracer.goProcessAdmissions[process]
	processAdmission.processRoot = nil
	tracer.goProcessAdmissions[process] = processAdmission
	tracer.goAutoSDKReadyByExecutable = map[goExecutableKey]bool{testGoExecutableKey(ino): true}
	access.pinErr = errors.New("exact process executable changed before admission")
	openCalls := access.openCalls
	admission := goAutoSDKAdmissionState{
		startTime:            tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
		executable:           testGoExecutableKey(ino),
		samplerReady:         true,
		generationReady:      true,
		optionFunctionsReady: true,
		typeInfoReady:        true,
		fileInfo:             tracer.goProcessGenerationByPID[process].fileInfo,
	}
	tracer.goAutoSDKAdmissions[process] = admission

	tracer.processMu.Lock()
	admitted := tracer.reconcileGoAutoSDKAdmission(process, admission)
	tracer.processMu.Unlock()

	require.True(t, admitted)
	assert.Equal(t, openCalls, access.openCalls)
	assert.Equal(t, 1, sampler.enableCalls)
	assert.Zero(t, sampler.blockCalls)
	assert.True(t, sampler.autoReady)
	assert.Contains(t, tracer.goAutoSDKAdmissions, process)
	assert.Contains(t, tracer.goAutoSDKFlagStates, process)
	assert.Empty(t, tracer.goAutoSDKRestoreRetries)
	assert.Nil(t, tracer.goProcessAdmissions[process].processRoot)
}

func TestGoAutoSDKProcessPinFailureDowngradesMixedAdmission(t *testing.T) {
	tracer, process, key, _, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	prepared := tracer.goAutoSDKFlagStates[process]
	require.NoError(t, prepared.incarnation.Close())
	delete(tracer.goAutoSDKFlagStates, process)
	delete(
		tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap).values,
		goAutoSDKInflightKeyForState(prepared),
	)
	delete(flagMap.values, key)

	generation := tracer.goProcessGenerationByPID[process]
	ino := generation.fileInfo.Ino()
	tracer.goAutoSDKReadyByExecutable = map[goExecutableKey]bool{testGoExecutableKey(ino): true}
	tracer.goAutoSDKGlobalReadyByExecutable = map[goExecutableKey]bool{testGoExecutableKey(ino): true}
	access.pinErr = errors.New("exact process executable changed before admission")
	openCalls := access.openCalls
	admission := goAutoSDKAdmissionState{
		startTime:            generation.fileInfo.StartTime(),
		executable:           testGoExecutableKey(ino),
		samplerReady:         true,
		generationReady:      true,
		optionFunctionsReady: true,
		typeInfoReady:        true,
		globalReady:          true,
		globalPatchReady:     true,
		fileInfo:             generation.fileInfo,
	}
	tracer.goAutoSDKAdmissions[process] = admission

	tracer.processMu.Lock()
	admitted := tracer.reconcileGoAutoSDKAdmission(process, admission)
	tracer.processMu.Unlock()

	require.True(t, admitted)
	assert.Equal(t, openCalls+1, access.openCalls)
	assert.Equal(t, 2, sampler.enableCalls)
	assert.Equal(t, []bool{true, false}, sampler.globalModes)
	assert.True(t, sampler.autoReady)
	assert.Zero(t, sampler.blockCalls)
	downgraded, ok := tracer.goAutoSDKAdmissions[process]
	require.True(t, ok)
	assert.True(t, downgraded.authorityActive)
	assert.True(t, downgraded.globalReady)
	assert.False(t, downgraded.globalPatchReady)
	directState, ok := tracer.goAutoSDKFlagStates[process]
	require.True(t, ok)
	assert.False(t, directState.globalProtocol)
	assert.Zero(t, directState.flagPtr)
	assert.Nil(t, directState.incarnation)
	assert.Len(t, tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap).values, 2,
		"only PRE and the final direct counter remain")
	assert.Empty(t, tracer.goAutoSDKRestoreRetries)
}

func TestGoAutoSDKUnpreparedAdmissionReleasesRootWhenNotReady(t *testing.T) {
	tracer, process, key, _, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	prepared := tracer.goAutoSDKFlagStates[process]
	require.NoError(t, prepared.incarnation.Close())
	delete(tracer.goAutoSDKFlagStates, process)
	delete(
		tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap).values,
		goAutoSDKInflightKeyForState(prepared),
	)
	delete(flagMap.values, key)
	processRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	processAdmission := tracer.goProcessAdmissions[process]
	processAdmission.processRoot = newGoAutoSDKProcessRoot(processRoot)
	tracer.goProcessAdmissions[process] = processAdmission
	tracer.goAutoSDKTailCallsReady = false
	openCalls := access.openCalls
	admission := goAutoSDKAdmissionState{
		startTime:            tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
		executable:           testGoExecutableKey(55),
		samplerReady:         true,
		generationReady:      true,
		optionFunctionsReady: true,
		typeInfoReady:        true,
		fileInfo:             tracer.goProcessGenerationByPID[process].fileInfo,
	}
	tracer.goAutoSDKAdmissions[process] = admission

	tracer.processMu.Lock()
	admitted := tracer.reconcileGoAutoSDKAdmission(process, admission)
	tracer.processMu.Unlock()

	require.True(t, admitted)
	assert.Equal(t, openCalls, access.openCalls)
	assert.Equal(t, 1, sampler.quiesceCalls)
	assert.Zero(t, sampler.blockCalls)
	assert.NotContains(t, tracer.goAutoSDKAdmissions, process)
	assert.Empty(t, tracer.goAutoSDKRestoreRetries)
	assert.Nil(t, tracer.goProcessAdmissions[process].processRoot)
	_, err = processRoot.Stat()
	require.Error(t, err)
}

func TestGoAutoSDKEstablishedAuthorityWithoutStateFailsClosed(t *testing.T) {
	tracer, process, key, _, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	prepared := tracer.goAutoSDKFlagStates[process]
	require.NoError(t, prepared.incarnation.Close())
	delete(tracer.goAutoSDKFlagStates, process)
	delete(flagMap.values, key)
	counterKey := goAutoSDKInflightKeyForState(prepared)
	inflight := tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap)
	counter := inflight.values[counterKey]
	setGoAutoSDKInflightActiveCalls(&counter, 1)
	inflight.values[counterKey] = counter
	processRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, processRoot.Close())
	})
	processAdmission := tracer.goProcessAdmissions[process]
	processAdmission.processRoot = newGoAutoSDKProcessRoot(processRoot)
	tracer.goProcessAdmissions[process] = processAdmission
	tracer.goAutoSDKTailCallsReady = false
	tracer.goAutoSDKShuttingDown = true
	filter := &recordingServiceFilter{}
	tracer.pidsFilter = filter
	openCalls := access.openCalls
	admission := goAutoSDKAdmissionState{
		startTime:            tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
		executable:           testGoExecutableKey(55),
		samplerReady:         true,
		generationReady:      true,
		optionFunctionsReady: true,
		typeInfoReady:        true,
		globalReady:          true,
		globalPatchReady:     true,
		authorityActive:      true,
		fileInfo:             tracer.goProcessGenerationByPID[process].fileInfo,
	}
	tracer.goAutoSDKAdmissions[process] = admission

	tracer.processMu.Lock()
	admitted := tracer.reconcileGoAutoSDKAdmission(process, admission)
	tracer.processMu.Unlock()

	assert.False(t, admitted)
	assert.Equal(t, openCalls+1, access.openCalls)
	assert.Equal(t, 1, sampler.quiesceCalls)
	assert.Zero(t, sampler.blockCalls)
	assert.Equal(t, 1, filter.blocked)
	assert.Contains(t, tracer.goAutoSDKAdmissions, process)
	assert.Equal(t, processAdmission.processRoot,
		tracer.goProcessAdmissions[process].processRoot)
	assert.Contains(t, inflight.values, counterKey)
	_, err = processRoot.Stat()
	assert.NoError(t, err)
}

func TestGoAutoSDKReadyAdmissionQueuesFailedFallbackRestoration(t *testing.T) {
	tracer, process, _, _, _, _, sampler := newGoAutoSDKLifecycleTestTracer(t)
	const ino = uint64(55)
	filter := &recordingServiceFilter{}
	tracer.pidsFilter = filter
	tracer.goAutoSDKTailCallsReady = true
	tracer.goAutoSDKReadyByExecutable = map[goExecutableKey]bool{testGoExecutableKey(ino): true}
	sampler.enableFails = true
	sampler.autoReady = true
	sampler.blockOK = false
	admission := goAutoSDKAdmissionState{
		startTime:            tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
		executable:           testGoExecutableKey(ino),
		samplerReady:         true,
		generationReady:      true,
		optionFunctionsReady: true,
		typeInfoReady:        true,
		fileInfo:             tracer.goProcessGenerationByPID[process].fileInfo,
	}
	tracer.goAutoSDKAdmissions[process] = admission
	retry := goAutoSDKRestoreRetryKey{
		process:   process,
		startTime: admission.startTime,
		fileInfo:  admission.fileInfo,
	}

	tracer.processMu.Lock()
	admitted := tracer.reconcileGoAutoSDKAdmission(process, admission)
	assert.False(t, admitted)
	assert.Contains(t, tracer.goAutoSDKRestoreRetries, retry)
	assert.True(t, tracer.goAutoSDKRestoreRetries[retry])
	assert.True(t, sampler.autoReady)
	assert.Equal(t, 1, filter.blocked)
	tracer.goAutoSDKShuttingDown = true
	tracer.processMu.Unlock()
	tracer.goAutoSDKRestoreRetryWG.Wait()

	assert.Equal(t, 1, sampler.enableCalls)
	assert.Equal(t, 1, sampler.blockCalls)
}

func TestGoProbeAttachmentsSerializeWithRunAdmissionReconciliation(t *testing.T) {
	const (
		ino    = uint64(55)
		symbol = "go.opentelemetry.io/auto/sdk.(*tracer).Start"
	)
	tracer, process, _, _, _, _, sampler := newGoAutoSDKLifecycleTestTracer(t)
	tracer.goAutoSDKTailCallsReady = true
	tracer.goAutoSDKEligibleByExecutable = map[goExecutableKey]bool{testGoExecutableKey(ino): true}
	tracer.goAutoSDKReadyByExecutable = map[goExecutableKey]bool{testGoExecutableKey(ino): true}
	tracer.goAutoSDKProbesByExecutable = map[goExecutableKey][]string{testGoExecutableKey(ino): {symbol}}
	tracer.goAutoSDKAdmissions = map[runtimeMetricTargetKey]goAutoSDKAdmissionState{
		process: {
			startTime:            tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
			executable:           testGoExecutableKey(ino),
			samplerReady:         true,
			generationReady:      true,
			optionFunctionsReady: true,
			typeInfoReady:        true,
			fileInfo:             tracer.goProcessGenerationByPID[process].fileInfo,
		},
	}
	tracer.goAutoSDKEventReader = newFakeGoAutoSDKEventReader(nil)

	enableEntered := make(chan struct{})
	enableRelease := make(chan struct{})
	var releaseOnce sync.Once
	releaseEnable := func() {
		releaseOnce.Do(func() {
			close(enableRelease)
		})
	}
	defer releaseEnable()
	tracer.samplerManager = &blockingEnableGoAutoSDKSamplerManager{
		fakeGoAutoSDKSamplerManager: sampler,
		entered:                     enableEntered,
		release:                     enableRelease,
	}

	startDone := make(chan struct{})
	go func() {
		tracer.startGoAutoSDKRun(context.Background())
		close(startDone)
	}()
	select {
	case <-enableEntered:
	case <-time.After(time.Second):
		t.Fatal("run did not reach admission reconciliation")
	}

	recordStarted := make(chan struct{})
	recordDone := make(chan struct{})
	fileInfo := exec.New(exec.Init{Ino: ino, Pid: process.pid, Ns: process.ns})
	go func() {
		close(recordStarted)
		tracer.RecordGoProbeAttachments(fileInfo, map[string]bool{symbol: true})
		close(recordDone)
	}()
	<-recordStarted
	select {
	case <-recordDone:
		t.Fatal("probe readiness update bypassed process lifecycle serialization")
	case <-time.After(50 * time.Millisecond):
	}

	releaseEnable()
	select {
	case <-startDone:
	case <-time.After(time.Second):
		t.Fatal("run admission reconciliation deadlocked")
	}
	select {
	case <-recordDone:
	case <-time.After(time.Second):
		t.Fatal("probe readiness update deadlocked")
	}

	assert.True(t, tracer.goAutoSDKRunStarted)
	assert.True(t, tracer.goAutoSDKReadyByExecutable[testGoExecutableKey(ino)])
	assert.Equal(t, 1, sampler.enableCalls)
}

func TestGoAutoSDKCanceledBeforeRunNeverActivates(t *testing.T) {
	readerCreations := 0
	tracer := &Tracer{
		samplerManager: &fakeGoAutoSDKSamplerManager{
			quiesceOK:    true,
			fallbackSafe: true,
			blockOK:      true,
		},
		newGoAutoSDKEventReader: func(*ebpf.Map) (goAutoSDKEventReader, error) {
			readerCreations++
			return newFakeGoAutoSDKEventReader(nil), nil
		},
	}
	tracer.bpfObjects.GoAutoSdkFlagEvents = &ebpf.Map{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tracer.startGoAutoSDKRun(ctx)

	assert.False(t, tracer.goAutoSDKRunStarted)
	assert.False(t, tracer.goAutoSDKDiscoveryReady)
	assert.Zero(t, readerCreations)
}

func TestGoAutoSDKFirstFallbackWaitsForDiscovery(t *testing.T) {
	tracer, _, key, flagPtr, flagMap, access, _ := newGoAutoSDKLifecycleTestTracer(t)
	var operations []string
	flagMap.operations = &operations
	access.operations = &operations

	assert.Zero(t, access.writeCalls)
	assert.Zero(t, access.memory[flagPtr])
	assert.Equal(t, goAutoSDKFlagCaptured, flagMap.values[key].Activated)

	tracer.activateGoAutoSDKFlag(key)

	assert.Equal(t, 1, access.writeCalls)
	assert.Equal(t, byte(1), access.memory[flagPtr])
	assert.Equal(t, goAutoSDKFlagActive, flagMap.values[key].Activated)
	assert.Less(
		t,
		operationIndex(t, operations, "flag:1"),
		operationIndex(t, operations, "memory:write:1"),
	)
}

func TestGoAutoSDKActivationPublishesExactGateBeforeDrainingGlobalPRE(
	t *testing.T,
) {
	tracer, _, key, flagPtr, flagMap, access, _ := newGoAutoSDKLifecycleTestTracer(t)
	inflight := tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap)
	pendingKey := goAutoSDKInflightKeyForState(goAutoSDKPendingState())
	pending := inflight.values[pendingKey]
	setGoAutoSDKInflightActiveCalls(&pending, 1)
	inflight.values[pendingKey] = pending
	drainPauses := 0
	tracer.goAutoSDKDrainPause = func() {
		drainPauses++
		assert.Equal(t, goAutoSDKFlagActive, flagMap.values[key].Activated,
			"exact gate must be visible before PRE can reach zero")
		assert.Zero(t, access.memory[flagPtr],
			"userspace flag must remain false while PRE is nonzero")
		pending := inflight.values[pendingKey]
		setGoAutoSDKInflightActiveCalls(&pending, 0)
		inflight.values[pendingKey] = pending
	}

	tracer.activateGoAutoSDKFlag(key)

	assert.Equal(t, 1, drainPauses)
	assert.Equal(t, byte(1), access.memory[flagPtr])
	assert.Equal(t, goAutoSDKFlagActive, flagMap.values[key].Activated)
}

func TestGoAutoSDKActivationIsIdempotent(t *testing.T) {
	tracer, _, key, _, _, access, _ := newGoAutoSDKLifecycleTestTracer(t)

	tracer.activateGoAutoSDKFlag(key)
	firstReadCalls := access.readCalls
	firstWriteCalls := access.writeCalls
	tracer.activateGoAutoSDKFlag(key)

	assert.Equal(t, firstReadCalls, access.readCalls)
	assert.Equal(t, firstWriteCalls, access.writeCalls)
}

func TestGoAutoSDKActivationRejectsAlreadyTrueForeignFlag(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	access.memory[flagPtr] = 1

	tracer.activateGoAutoSDKFlag(key)

	assert.Equal(t, byte(1), access.memory[flagPtr])
	assert.Zero(t, access.writeCalls)
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.NotContains(t, flagMap.values, key)
	assert.Contains(
		t,
		tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap).values,
		goAutoSDKInflightKeyForState(goAutoSDKPendingState()),
	)
	assert.Equal(t, 1, sampler.quiesceCalls)
}

func TestGoAutoSDKActivationFailuresRestoreBeforeQuiescing(t *testing.T) {
	activationErr := errors.New("activation failed")
	tests := []struct {
		name      string
		configure func(*fakeGoAutoSDKProcessAccess)
	}{
		{
			name: "initial read",
			configure: func(access *fakeGoAutoSDKProcessAccess) {
				access.readResults = []fakeGoAutoSDKReadResult{{err: activationErr}}
			},
		},
		{
			name: "write",
			configure: func(access *fakeGoAutoSDKProcessAccess) {
				access.writeResults = []fakeGoAutoSDKWriteResult{
					{err: activationErr, apply: true},
					{apply: true},
				}
			},
		},
		{
			name: "readback error",
			configure: func(access *fakeGoAutoSDKProcessAccess) {
				access.readResults = []fakeGoAutoSDKReadResult{
					{value: 0},
					{err: activationErr},
				}
			},
		},
		{
			name: "readback mismatch",
			configure: func(access *fakeGoAutoSDKProcessAccess) {
				access.readResults = []fakeGoAutoSDKReadResult{
					{value: 0},
					{value: 0},
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var operations []string
			tracer, process, key, flagPtr, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
			access.operations = &operations
			flagMap.operations = &operations
			sampler.operations = &operations
			tc.configure(access)

			tracer.activateGoAutoSDKFlag(key)

			assert.Zero(t, access.memory[flagPtr])
			assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
			assert.NotContains(t, flagMap.values, key)
			assert.Equal(t, 1, sampler.quiesceCalls)
			if tc.name == "initial read" {
				assert.Less(
					t,
					operationIndex(t, operations, "readiness:quiesce"),
					operationIndex(t, operations, "flag:delete"),
				)
			} else {
				assert.Less(
					t,
					operationIndex(t, operations, "memory:write:0"),
					operationIndex(t, operations, "readiness:quiesce"),
				)
			}
		})
	}
}

func TestGoAutoSDKActivationMapFailureRestores(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	flagMap.putErrors = []error{errors.New("active map update failed"), nil}

	tracer.activateGoAutoSDKFlag(key)

	assert.Zero(t, access.memory[flagPtr])
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.NotContains(t, flagMap.values, key)
	assert.Equal(t, 1, sampler.quiesceCalls)
}

func TestGoAutoSDKActivationFailureRetiresAuthorityBeforeShutdown(t *testing.T) {
	tracer, process, key, _, _, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	fileInfo := tracer.goProcessGenerationByPID[process].fileInfo
	processRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	processAdmission := tracer.goProcessAdmissions[process]
	processAdmission.processRoot = newGoAutoSDKProcessRoot(processRoot)
	tracer.goProcessAdmissions[process] = processAdmission
	tracer.goAutoSDKAdmissions[process] = goAutoSDKAdmissionState{
		startTime:        fileInfo.StartTime(),
		globalReady:      true,
		globalPatchReady: true,
		authorityActive:  true,
		fileInfo:         fileInfo,
	}
	access.readResults = []fakeGoAutoSDKReadResult{{
		err: errors.New("activation read failed"),
	}}

	tracer.activateGoAutoSDKFlag(key)

	assert.Equal(t, 1, sampler.quiesceCalls)
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.NotContains(t, tracer.goAutoSDKAdmissions, process)
	assert.Nil(t, tracer.goProcessAdmissions[process].processRoot)
	assert.Empty(t, tracer.goAutoSDKRestoreRetries)
	_, err = processRoot.Stat()
	require.Error(t, err)

	require.True(t, tracer.shutdownGoAutoSDK())
	assert.True(t, tracer.goAutoSDKShutdownComplete)
}

func TestGoAutoSDKDirectAdmissionDoesNotRequirePreAdmissionLatch(t *testing.T) {
	tracer, process, _, flagPtr, _, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	inflight := tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap)
	delete(tracer.goAutoSDKFlagStates, process)
	clear(inflight.values)
	generation := tracer.goProcessGenerationByPID[process]
	admission := tracer.goAutoSDKAdmissions[process]
	admission.globalReady = false
	admission.globalPatchReady = false
	tracer.goAutoSDKAdmissions[process] = admission

	assert.True(t, tracer.prepareGoAutoSDKDirectAdmission(
		process,
		generation.hostPID,
		generation.fileInfo.StartTime(),
		5,
		false,
	))

	assert.Zero(t, access.memory[flagPtr])
	assert.Zero(t, access.writeCalls)
	assert.Contains(t, tracer.goAutoSDKFlagStates, process)
	assert.Contains(
		t,
		inflight.values,
		goAutoSDKInflightKeyForState(tracer.goAutoSDKFlagStates[process]),
	)
	assert.True(t, sampler.autoReady)
	assert.Zero(t, sampler.quiesceCalls)
}

func TestGoAutoSDKPreAdmissionProvisionFailureDoesNotDisableDirectActivation(t *testing.T) {
	inflight := &fakeGoAutoSDKInflightMap{
		values:    map[goAutoSDKInflightKey]goAutoSDKInflightValue{},
		updateErr: errors.New("counter map full"),
	}
	tracer := &Tracer{
		goAutoSDKInflight:          inflight,
		goAutoSDKTailCallsReady:    true,
		goAutoSDKReadyByExecutable: map[goExecutableKey]bool{testGoExecutableKey(1): true},
		goAutoSDKDiscoveryReady:    true,
	}

	tracer.goAutoSDKPreAdmissionReady = tracer.provisionGoAutoSDKInflight(goAutoSDKPendingState())

	assert.False(t, tracer.goAutoSDKPreAdmissionReady)
	assert.True(t,
		tracer.goAutoSDKActivationReady(testGoExecutableKey(1), true, true, true, true, false))
	assert.Empty(t, inflight.values)
}

func TestGoAutoSDKQuiescingPublicationFailureIsRetrySafe(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	tracer.activateGoAutoSDKFlag(key)
	flagMap.putErrors = []error{errors.New("quiescing update failed")}

	assert.False(t, tracer.restoreGoAutoSDKFlag(process))

	assert.Zero(t, access.memory[flagPtr])
	state, retained := tracer.goAutoSDKFlagStates[process]
	require.True(t, retained)
	assert.False(t, state.restoreRequired)
	assert.Equal(t, goAutoSDKFlagActive, flagMap.values[key].Activated)
	assert.Zero(t, sampler.quiesceCalls)
	assert.Zero(t, access.closeCalls)
	assert.NotEmpty(t,
		tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap).values)
	writesAfterFailure := access.writeCalls

	require.True(t, tracer.restoreGoAutoSDKFlag(process))

	assert.Equal(t, writesAfterFailure, access.writeCalls)
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.NotContains(t, flagMap.values, key)
	assert.Equal(
		t,
		map[goAutoSDKInflightKey]goAutoSDKInflightValue{
			goAutoSDKInflightKeyForState(goAutoSDKPendingState()): {},
		},
		tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap).values,
	)
	assert.Equal(t, 1, sampler.quiesceCalls)
	assert.Equal(t, 1, access.closeCalls)
}

func TestGoAutoSDKActivationFailureRetriesRestoration(t *testing.T) {
	tracer, process, key, flagPtr, _, access, _ := newGoAutoSDKLifecycleTestTracer(t)
	access.writeResults = []fakeGoAutoSDKWriteResult{
		{err: errors.New("activation failed"), apply: true},
		{err: errors.New("transient restore failure")},
		{apply: true},
	}
	tracer.goAutoSDKRestoreRetryPause = func() {}

	tracer.activateGoAutoSDKFlag(key)
	tracer.goAutoSDKRestoreRetryWG.Wait()

	assert.Zero(t, access.memory[flagPtr])
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.False(t, tracer.goAutoSDKRestoreRetrying)
	assert.Empty(t, tracer.goAutoSDKRestoreRetries)
	assert.Equal(t, 3, access.writeCalls)
	assert.Equal(t, 1, access.openCalls)
	assert.Equal(t, 1, access.closeCalls)
}

func TestGoAutoSDKReaderFailureRetriesRestoration(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	generation := tracer.goProcessGenerationByPID[process]
	ino := generation.fileInfo.Ino()
	tracer.goAutoSDKReadyByExecutable = map[goExecutableKey]bool{testGoExecutableKey(ino): true}
	admission := tracer.goAutoSDKAdmissions[process]
	admission.executable = testGoExecutableKey(ino)
	admission.samplerReady = true
	admission.generationReady = true
	admission.optionFunctionsReady = true
	admission.typeInfoReady = true
	admission.globalReady = true
	admission.globalPatchReady = true
	admission.authorityActive = true
	tracer.goAutoSDKAdmissions[process] = admission
	tracer.activateGoAutoSDKFlag(key)
	access.writeResults = []fakeGoAutoSDKWriteResult{
		{err: errors.New("transient restore failure")},
		{apply: true},
	}

	retryPaused := make(chan struct{}, 1)
	resumeRetry := make(chan struct{})
	var resumeOnce sync.Once
	defer resumeOnce.Do(func() {
		close(resumeRetry)
	})
	tracer.goAutoSDKRestoreRetryPause = func() {
		retryPaused <- struct{}{}
		<-resumeRetry
	}
	rawReader := newFakeGoAutoSDKEventReader(errors.New("transient read failure"))
	tracer.newGoAutoSDKEventReader = func(*ebpf.Map) (goAutoSDKEventReader, error) {
		return rawReader, nil
	}
	tracer.bpfObjects.GoAutoSdkFlagEvents = &ebpf.Map{}

	tracer.processMu.Lock()
	tracer.goAutoSDKDiscoveryReady = false
	readerReady := tracer.ensureGoAutoSDKEventReader()
	tracer.processMu.Unlock()
	require.True(t, readerReady)
	tracer.goAutoSDKEventWG.Wait()

	select {
	case <-retryPaused:
	case <-time.After(time.Second):
		t.Fatal("restore retry did not pause after the transient failure")
	}
	assert.Equal(t, byte(1), access.memory[flagPtr])
	assert.Contains(t, tracer.goAutoSDKFlagStates, process)
	assert.Equal(t, 1, rawReader.CloseCalls())

	resumeOnce.Do(func() {
		close(resumeRetry)
	})
	tracer.goAutoSDKRestoreRetryWG.Wait()

	assert.Zero(t, access.memory[flagPtr])
	directState, directReady := tracer.goAutoSDKFlagStates[process]
	require.True(t, directReady)
	assert.Zero(t, directState.flagPtr)
	assert.False(t, directState.globalProtocol)
	assert.False(t, directState.restoreRequired)
	assert.False(t, directState.discardRequired)
	assert.NotContains(t, flagMap.values, key)
	downgraded, admitted := tracer.goAutoSDKAdmissions[process]
	require.True(t, admitted)
	assert.True(t, downgraded.authorityActive)
	assert.False(t, downgraded.globalReady)
	assert.False(t, downgraded.globalPatchReady)
	assert.True(t, sampler.autoReady)
	assert.Equal(t, []bool{false}, sampler.globalModes)
	assert.False(t, tracer.goAutoSDKRestoreRetrying)
	assert.Empty(t, tracer.goAutoSDKRestoreRetries)
	assert.False(t, tracer.goAutoSDKDiscoveryReady)
	assert.Nil(t, tracer.goAutoSDKEventReader)
	assert.Equal(t, 1, rawReader.CloseCalls())
}

func TestGoAutoSDKReaderFailureBeforeActivationDowngradesMixedAdmission(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	delete(flagMap.values, key)
	generation := tracer.goProcessGenerationByPID[process]
	ino := generation.fileInfo.Ino()
	tracer.goAutoSDKReadyByExecutable = map[goExecutableKey]bool{testGoExecutableKey(ino): true}
	admission := tracer.goAutoSDKAdmissions[process]
	admission.executable = testGoExecutableKey(ino)
	admission.samplerReady = true
	admission.generationReady = true
	admission.optionFunctionsReady = true
	admission.typeInfoReady = true
	admission.globalReady = true
	admission.globalPatchReady = true
	admission.authorityActive = true
	tracer.goAutoSDKAdmissions[process] = admission

	rawReader := newFakeGoAutoSDKEventReader(errors.New("pre-activation read failure"))
	tracer.newGoAutoSDKEventReader = func(*ebpf.Map) (goAutoSDKEventReader, error) {
		return rawReader, nil
	}
	tracer.bpfObjects.GoAutoSdkFlagEvents = &ebpf.Map{}

	tracer.processMu.Lock()
	tracer.goAutoSDKDiscoveryReady = false
	readerReady := tracer.ensureGoAutoSDKEventReader()
	tracer.processMu.Unlock()
	require.True(t, readerReady)
	tracer.goAutoSDKEventWG.Wait()
	tracer.goAutoSDKRestoreRetryWG.Wait()

	assert.Zero(t, access.memory[flagPtr])
	assert.Zero(t, access.writeCalls)
	assert.NotContains(t, flagMap.values, key)
	directState, ok := tracer.goAutoSDKFlagStates[process]
	require.True(t, ok)
	assert.Zero(t, directState.flagPtr)
	assert.False(t, directState.globalProtocol)
	assert.False(t, directState.restoreRequired)
	assert.False(t, directState.discardRequired)
	downgraded, ok := tracer.goAutoSDKAdmissions[process]
	require.True(t, ok)
	assert.True(t, downgraded.authorityActive)
	assert.False(t, downgraded.globalReady)
	assert.False(t, downgraded.globalPatchReady)
	assert.True(t, sampler.autoReady)
	assert.Equal(t, []bool{false}, sampler.globalModes)
	assert.False(t, tracer.goAutoSDKRestoreRetrying)
	assert.Empty(t, tracer.goAutoSDKRestoreRetries)
	assert.False(t, tracer.goAutoSDKDiscoveryReady)
	assert.Nil(t, tracer.goAutoSDKEventReader)
	assert.Equal(t, 1, rawReader.CloseCalls())
}

func TestGoAutoSDKReaderFailureRetainsTransientCloseFailure(t *testing.T) {
	rawReader := newFakeGoAutoSDKEventReader(errors.New("read failed"))
	rawReader.closeErrs = []error{errors.New("close failed"), nil}
	tracer := &Tracer{
		log:                      slog.New(slog.NewTextHandler(io.Discard, nil)),
		goProcessGenerationByPID: map[runtimeMetricTargetKey]goProcessGenerationState{},
		goAutoSDKRestoreRetries:  map[goAutoSDKRestoreRetryKey]bool{},
		newGoAutoSDKEventReader: func(*ebpf.Map) (goAutoSDKEventReader, error) {
			return rawReader, nil
		},
	}
	tracer.bpfObjects.GoAutoSdkFlagEvents = &ebpf.Map{}

	tracer.processMu.Lock()
	require.True(t, tracer.ensureGoAutoSDKEventReader())
	tracer.processMu.Unlock()
	tracer.goAutoSDKEventWG.Wait()

	tracer.processMu.Lock()
	retainedReader := tracer.goAutoSDKEventReader
	discoveryReady := tracer.goAutoSDKDiscoveryReady
	tracer.processMu.Unlock()
	assert.NotNil(t, retainedReader)
	assert.False(t, discoveryReady)
	assert.Equal(t, 1, rawReader.CloseCalls())

	require.True(t, tracer.shutdownGoAutoSDK())
	assert.Equal(t, 2, rawReader.CloseCalls())
	assert.True(t, tracer.goAutoSDKShutdownComplete)
	assert.Nil(t, tracer.goAutoSDKEventReader)
}

func TestGoAutoSDKShutdownRetriesTransientReaderClose(t *testing.T) {
	rawReader := newFakeGoAutoSDKEventReader(nil)
	rawReader.closeErrs = []error{errors.New("close failed"), nil}
	tracer := &Tracer{
		log:                      slog.New(slog.NewTextHandler(io.Discard, nil)),
		goProcessGenerationByPID: map[runtimeMetricTargetKey]goProcessGenerationState{},
		goAutoSDKRestoreRetries:  map[goAutoSDKRestoreRetryKey]bool{},
		newGoAutoSDKEventReader: func(*ebpf.Map) (goAutoSDKEventReader, error) {
			return rawReader, nil
		},
	}
	tracer.bpfObjects.GoAutoSdkFlagEvents = &ebpf.Map{}
	tracer.processMu.Lock()
	require.True(t, tracer.ensureGoAutoSDKEventReader())
	tracer.processMu.Unlock()

	resources := newGoTracerResources(tracer)
	require.NoError(t, resources.Close())

	assert.Equal(t, 2, rawReader.CloseCalls())
	assert.True(t, tracer.goAutoSDKShutdownComplete)
	assert.Nil(t, tracer.goAutoSDKEventReader)
}

func TestGoAutoSDKActivationAndRestoreStayBoundAcrossSameTickPIDReuse(
	t *testing.T,
) {
	tracer, process, key, flagPtr, flagMap, access, _ := newGoAutoSDKLifecycleTestTracer(t)
	oldMemory := access.memory
	replacementMemory := map[uint64]byte{flagPtr: 0x5a}
	access.memory = replacementMemory
	openCalls := access.openCalls

	tracer.activateGoAutoSDKFlag(key)

	assert.Equal(t, byte(1), oldMemory[flagPtr])
	assert.Equal(t, byte(0x5a), replacementMemory[flagPtr])
	assert.Equal(t, openCalls, access.openCalls)
	require.True(t, tracer.restoreGoAutoSDKFlag(process))

	assert.Zero(t, oldMemory[flagPtr])
	assert.Equal(t, byte(0x5a), replacementMemory[flagPtr])
	assert.Equal(t, openCalls, access.openCalls)
	assert.Equal(t, 1, access.closeCalls)
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.NotContains(t, flagMap.values, key)
}

func TestGoAutoSDKRestoreRetryStaysBoundAcrossSameTickPIDReuse(t *testing.T) {
	tracer, process, key, flagPtr, _, access, _ := newGoAutoSDKLifecycleTestTracer(t)
	oldMemory := access.memory
	tracer.activateGoAutoSDKFlag(key)
	replacementMemory := map[uint64]byte{flagPtr: 0x5a}
	access.memory = replacementMemory
	access.writeResults = []fakeGoAutoSDKWriteResult{
		{err: errors.New("transient restore failure")},
		{apply: true},
	}
	openCalls := access.openCalls

	assert.False(t, tracer.restoreGoAutoSDKFlag(process))

	assert.Equal(t, byte(1), oldMemory[flagPtr])
	assert.Equal(t, byte(0x5a), replacementMemory[flagPtr])
	assert.Equal(t, openCalls, access.openCalls)
	assert.Zero(t, access.closeCalls)

	require.True(t, tracer.restoreGoAutoSDKFlag(process))

	assert.Zero(t, oldMemory[flagPtr])
	assert.Equal(t, byte(0x5a), replacementMemory[flagPtr])
	assert.Equal(t, openCalls, access.openCalls)
	assert.Equal(t, 1, access.closeCalls)
}

func TestGoAutoSDKDelayedPreparationUsesAdmissionBoundProcessRoot(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, access, _ := newGoAutoSDKLifecycleTestTracer(t)
	fileInfo := tracer.goProcessGenerationByPID[process].fileInfo
	oldMemory := access.memory

	require.True(t, tracer.restoreGoAutoSDKFlag(process))

	replacementMemory := map[uint64]byte{flagPtr: 0x5a}
	access.memory = replacementMemory
	access.memoryByFileInfo = map[*exec.FileInfo]map[uint64]byte{
		fileInfo: oldMemory,
	}
	const epoch = uint32(6)
	flagMap.values[key] = goAutoSDKFlagValue{
		FlagPtr:   flagPtr,
		StartTime: fileInfo.StartTime(),
		Epoch:     epoch,
	}
	readiness := tracer.goAutoSDKReadiness.(*fakeGoAutoSDKReadinessMap)
	readiness.values[uint32(key.PID)] = goAutoSDKReadinessValue{
		StartTime:          fileInfo.StartTime(),
		Epoch:              epoch,
		Ready:              1,
		AutoSDKGlobalReady: 1,
	}

	require.True(t, tracer.prepareGoAutoSDKDirectAdmission(
		process,
		uint32(key.PID),
		fileInfo.StartTime(),
		epoch,
		true,
	))
	tracer.activateGoAutoSDKFlag(key)

	assert.Equal(t, byte(1), oldMemory[flagPtr])
	assert.Equal(t, byte(0x5a), replacementMemory[flagPtr])

	require.True(t, tracer.restoreGoAutoSDKFlag(process))
	assert.Zero(t, oldMemory[flagPtr])
	assert.Equal(t, byte(0x5a), replacementMemory[flagPtr])
}

func TestGoAutoSDKOldAddressSpaceCleanupDisablesAdmission(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	fileInfo := tracer.goProcessGenerationByPID[process].fileInfo
	tracer.goAutoSDKAdmissions = map[runtimeMetricTargetKey]goAutoSDKAdmissionState{
		process: {
			startTime:        fileInfo.StartTime(),
			generationReady:  true,
			globalReady:      true,
			globalPatchReady: true,
			fileInfo:         fileInfo,
		},
	}
	tracer.activateGoAutoSDKFlag(key)
	inflight := tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap)
	counterKey := goAutoSDKInflightKeyForState(tracer.goAutoSDKFlagStates[process])
	access.writeResults = []fakeGoAutoSDKWriteResult{{
		err: errGoAutoSDKProcessMemoryGone,
	}}

	require.True(t, tracer.restoreGoAutoSDKFlag(process))

	assert.Equal(t, byte(1), access.memory[flagPtr])
	assert.Equal(t, 1, sampler.quiesceCalls)
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.NotContains(t, tracer.goAutoSDKAdmissions, process)
	assert.NotContains(t, flagMap.values, key)
	assert.NotContains(t, inflight.values, counterKey)
	assert.Contains(t, inflight.values,
		goAutoSDKInflightKeyForState(goAutoSDKPendingState()))
	assert.Nil(t, tracer.goProcessAdmissions[process].processRoot)
	assert.Equal(t, 1, access.closeCalls)
	assert.Empty(t, tracer.goAutoSDKRestoreRetries)

	tracer.pidsFilter = &recordingServiceFilter{}
	tracer.goProcessGenerations = &fakeGoProcessGenerationMap{
		values: map[uint32]goProcessGenerationValue{
			uint32(key.PID): {
				Generation: key.Generation,
				StartTime:  fileInfo.StartTime(),
			},
		},
	}
	tracer.BlockPIDForProcess(process.pid, process.ns, fileInfo)

	assert.NotContains(t, tracer.goProcessAdmissions, process)
	assert.NotContains(t, tracer.goProcessGenerationByPID, process)
}

func TestGoAutoSDKActivationWithGoneMemoryDisablesAdmission(t *testing.T) {
	tracer, process, key, _, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	fileInfo := tracer.goProcessGenerationByPID[process].fileInfo
	tracer.goAutoSDKAdmissions = map[runtimeMetricTargetKey]goAutoSDKAdmissionState{
		process: {
			startTime:        fileInfo.StartTime(),
			generationReady:  true,
			globalReady:      true,
			globalPatchReady: true,
			fileInfo:         fileInfo,
		},
	}
	access.readResults = []fakeGoAutoSDKReadResult{{
		err: errGoAutoSDKProcessMemoryGone,
	}}

	tracer.activateGoAutoSDKFlag(key)

	assert.Equal(t, 1, sampler.quiesceCalls)
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.NotContains(t, tracer.goAutoSDKAdmissions, process)
	assert.NotContains(t, flagMap.values, key)
	assert.Nil(t, tracer.goProcessAdmissions[process].processRoot)
	assert.Equal(t, 1, access.closeCalls)
	assert.Empty(t, tracer.goAutoSDKRestoreRetries)
	assert.Nil(t, tracer.prepareGoProcessRootLocked(process, fileInfo, true))
	assert.NotContains(t, tracer.goAutoSDKAdmissions, process)
	require.True(t, tracer.shutdownGoAutoSDK())
	assert.True(t, tracer.goAutoSDKShutdownComplete)
}

func TestGoAutoSDKAdmissionRestoresPreviousHostPIDOwner(t *testing.T) {
	tracer, previous, key, flagPtr, _, access, _ := newGoAutoSDKLifecycleTestTracer(t)
	filter := &recordingServiceFilter{}
	tracer.pidsFilter = filter
	processRoot := tracer.goProcessAdmissions[previous].processRoot
	tracer.goProcessAdmissions = map[runtimeMetricTargetKey]goProcessAdmissionState{
		previous: {
			startTime:       tracer.goProcessGenerationByPID[previous].fileInfo.StartTime(),
			generationReady: true,
			fileInfo:        tracer.goProcessGenerationByPID[previous].fileInfo,
			processRoot:     processRoot,
		},
	}
	tracer.goAutoSDKAdmissions = map[runtimeMetricTargetKey]goAutoSDKAdmissionState{
		previous: {
			startTime:        tracer.goProcessGenerationByPID[previous].fileInfo.StartTime(),
			generationReady:  true,
			globalReady:      true,
			globalPatchReady: true,
			fileInfo:         tracer.goProcessGenerationByPID[previous].fileInfo,
		},
	}
	tracer.goProcessGenerations = &fakeGoProcessGenerationMap{
		values: map[uint32]goProcessGenerationValue{
			uint32(key.PID): {
				Generation: key.Generation,
				StartTime:  tracer.goProcessGenerationByPID[previous].fileInfo.StartTime(),
			},
		},
	}
	tracer.goSpanOptionFuncsByExecutable = map[goExecutableKey][]goSpanOptionFunction{}
	tracer.goSpanOptionKeysByProcess = map[runtimeMetricTargetKey][]goSpanOptionFunctionKey{}
	tracer.goAutoSDKTypesByExecutable = map[goExecutableKey]goexec.GoAutoSDKTypeInfo{}
	tracer.goAutoSDKTypeInfoKeys = map[runtimeMetricTargetKey]goProcessKey{}
	tracer.newGoProcessGeneration = func() (uint64, error) {
		return 29, nil
	}
	tracer.resolveGoProcessHostPID = func(app.PID, uint32) (uint32, error) {
		return uint32(key.PID), nil
	}
	tracer.SetEventContext(ebpfcommon.NewEBPFEventContext())
	tracer.activateGoAutoSDKFlag(key)
	require.Equal(t, byte(1), access.memory[flagPtr])

	replacement := exec.New(exec.Init{
		Pid:       previous.pid,
		Ns:        previous.ns + 1,
		StartTime: tracer.goProcessGenerationByPID[previous].fileInfo.StartTime(),
	})
	replacementKey := runtimeMetricTargetKey{
		pid: replacement.Pid(),
		ns:  replacement.Ns(),
	}
	require.True(t, tracer.AllowPIDForProcess(
		replacement.Pid(),
		replacement.Ns(),
		replacement,
	))

	assert.Zero(t, access.memory[flagPtr])
	assert.NotContains(t, tracer.goAutoSDKFlagStates, previous)
	assert.NotContains(t, tracer.goProcessGenerationByPID, previous)
	assert.Equal(t, replacementKey, tracer.goProcessOwnerByHostPID[uint32(key.PID)])
	assert.Equal(t, uint64(29), tracer.goProcessGenerationByPID[replacementKey].generation)
	assert.Equal(t, 1, filter.blocked)
	assert.Equal(t, 1, filter.allowed)
}

func TestGoAutoSDKProcessSessionRemainsBoundToOneIncarnation(t *testing.T) {
	const (
		hostPID      = uint32(123)
		flagPtr      = uint64(0x123400)
		oldStartTime = uint64(90000000)
		newStartTime = uint64(91000000)
	)
	oldMemory := map[uint64]byte{flagPtr: 0}
	access := &fakeGoAutoSDKProcessAccess{
		startTimes: map[uint32]uint64{hostPID: oldStartTime},
		memory:     oldMemory,
	}
	fileInfo := exec.New(exec.Init{
		Pid:       app.PID(hostPID),
		StartTime: oldStartTime,
	})
	session, err := access.Open(nil, fileInfo)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, session.Close())
	})

	newMemory := map[uint64]byte{flagPtr: 1}
	access.startTimes[hostPID] = newStartTime
	access.memory = newMemory

	actualStartTime, err := session.StartTime()
	require.NoError(t, err)
	assert.Equal(t, oldStartTime, actualStartTime)
	value, err := session.Read(flagPtr)
	require.NoError(t, err)
	assert.Zero(t, value)
	require.NoError(t, session.Write(flagPtr, 1))
	assert.Equal(t, byte(1), oldMemory[flagPtr])
	assert.Equal(t, byte(1), newMemory[flagPtr])

	require.NoError(t, session.Write(flagPtr, 0))
	assert.Zero(t, oldMemory[flagPtr])
	assert.Equal(t, byte(1), newMemory[flagPtr])
}

func TestGoAutoSDKBlockPIDRestoresBeforeCleanup(t *testing.T) {
	tracer, process, key, flagPtr, _, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	filter := &recordingServiceFilter{}
	tracer.pidsFilter = filter
	processRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	admission := tracer.goProcessAdmissions[process]
	admission.processRoot = newGoAutoSDKProcessRoot(processRoot)
	tracer.goProcessAdmissions[process] = admission
	tracer.goProcessGenerations = &fakeGoProcessGenerationMap{
		values: map[uint32]goProcessGenerationValue{
			uint32(key.PID): {
				Generation: key.Generation,
				StartTime:  tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
			},
		},
	}
	tracer.activateGoAutoSDKFlag(key)

	tracer.BlockPID(process.pid, process.ns)

	assert.Zero(t, access.memory[flagPtr])
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.Equal(t, 1, filter.blocked)
	assert.Equal(t, 1, sampler.blockCalls)
	assert.NotContains(t, tracer.goProcessGenerationByPID, process)
	_, err = processRoot.Stat()
	require.Error(t, err)
}

func TestGoAutoSDKBlockRetryAcceptsCompletedFlagRestore(t *testing.T) {
	tracer, process, key, flagPtr, _, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	filter := &recordingServiceFilter{}
	tracer.pidsFilter = filter
	processRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	processAdmission := tracer.goProcessAdmissions[process]
	processAdmission.processRoot = newGoAutoSDKProcessRoot(processRoot)
	tracer.goProcessAdmissions[process] = processAdmission
	fileInfo := tracer.goProcessGenerationByPID[process].fileInfo
	tracer.goAutoSDKAdmissions[process] = goAutoSDKAdmissionState{
		startTime:       fileInfo.StartTime(),
		authorityActive: true,
		fileInfo:        fileInfo,
	}
	tracer.goProcessGenerations = &fakeGoProcessGenerationMap{
		values: map[uint32]goProcessGenerationValue{
			uint32(key.PID): {
				Generation: key.Generation,
				StartTime:  fileInfo.StartTime(),
			},
		},
	}
	sampler.blockResults = []bool{false, false, true}
	retryPaused := make(chan struct{})
	resumeRetry := make(chan struct{})
	var pauseOnce sync.Once
	var resumeOnce sync.Once
	t.Cleanup(func() {
		resumeOnce.Do(func() {
			close(resumeRetry)
		})
	})
	tracer.goAutoSDKRestoreRetryPause = func() {
		pauseOnce.Do(func() {
			close(retryPaused)
		})
		<-resumeRetry
	}
	openCalls := access.openCalls
	tracer.activateGoAutoSDKFlag(key)

	tracer.BlockPIDForProcess(process.pid, process.ns, fileInfo)

	select {
	case <-retryPaused:
	case <-time.After(time.Second):
		t.Fatal("restore retry did not pause after the transient cleanup failure")
	}
	assert.NotContains(t, tracer.goAutoSDKAdmissions, process)
	assert.Nil(t, tracer.goProcessAdmissions[process].processRoot)
	_, err = processRoot.Stat()
	require.Error(t, err)

	resumeOnce.Do(func() {
		close(resumeRetry)
	})
	tracer.goAutoSDKRestoreRetryWG.Wait()

	assert.Zero(t, access.memory[flagPtr])
	assert.Equal(t, openCalls, access.openCalls)
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.NotContains(t, tracer.goAutoSDKAdmissions, process)
	assert.NotContains(t, tracer.goProcessAdmissions, process)
	assert.NotContains(t, tracer.goProcessGenerationByPID, process)
	assert.Empty(t, tracer.goAutoSDKRestoreRetries)
	assert.Equal(t, 1, filter.blocked)
	assert.Equal(t, 3, sampler.blockCalls)
}

func TestGoAutoSDKBlockPIDUsesExactCounterNotSharedOuterScan(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	filter := &recordingServiceFilter{}
	tracer.pidsFilter = filter
	startTime := tracer.goProcessGenerationByPID[process].fileInfo.StartTime()
	fileInfo := tracer.goProcessGenerationByPID[process].fileInfo
	tracer.goProcessGenerations = &fakeGoProcessGenerationMap{
		values: map[uint32]goProcessGenerationValue{
			uint32(key.PID): {
				Generation: key.Generation,
				StartTime:  startTime,
			},
		},
	}
	tracer.activateGoAutoSDKFlag(key)
	call := goAutoSDKOuterCallValue{
		StartTime:  startTime,
		Generation: key.Generation,
		FlagPtr:    flagPtr,
		Epoch:      flagMap.values[key].Epoch,
		State:      goAutoSDKOuterCallActive,
	}
	outerCalls := &fakeGoAutoSDKOuterCallMap{
		values: map[goAddrKey]goAutoSDKOuterCallValue{
			{PID: key.PID + 1, Addr: 0x51}: call,
		},
	}
	tracer.goAutoSDKOuterCalls = outerCalls
	drainPauses := 0
	tracer.goAutoSDKDrainPause = func() { drainPauses++ }
	assert.False(t, tracer.ExecutableUnlinkReady(fileInfo))
	assert.True(t, tracer.ExecutableUnlinkReady(exec.New(exec.Init{
		Dev: fileInfo.Dev() + 1,
		Ino: fileInfo.Ino(),
	})))

	tracer.BlockPID(process.pid, process.ns)

	assert.Zero(t, drainPauses)
	assert.Zero(t, access.memory[flagPtr])
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.Equal(t, 1, filter.blocked)
	assert.Equal(t, 1, sampler.blockCalls)
	assert.NotContains(t, tracer.goProcessGenerationByPID, process)
	assert.True(t, tracer.ExecutableUnlinkReady(fileInfo))
}

func TestGoAutoSDKBlockPIDRetriesTransientRestoration(t *testing.T) {
	tracer, process, key, flagPtr, _, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	filter := &recordingServiceFilter{}
	tracer.pidsFilter = filter
	tracer.goProcessGenerations = &fakeGoProcessGenerationMap{
		values: map[uint32]goProcessGenerationValue{
			uint32(key.PID): {
				Generation: key.Generation,
				StartTime:  tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
			},
		},
	}
	tracer.activateGoAutoSDKFlag(key)
	access.writeResults = []fakeGoAutoSDKWriteResult{
		{err: errors.New("transient restore failure")},
		{apply: true},
	}
	tracer.goAutoSDKRestoreRetryPause = func() {}

	tracer.BlockPIDForProcess(
		process.pid,
		process.ns,
		tracer.goProcessGenerationByPID[process].fileInfo,
	)
	tracer.goAutoSDKRestoreRetryWG.Wait()

	assert.Zero(t, access.memory[flagPtr])
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.NotContains(t, tracer.goProcessGenerationByPID, process)
	assert.Empty(t, tracer.goAutoSDKRestoreRetries)
	assert.Equal(t, 1, filter.blocked)
	assert.Equal(t, 1, sampler.blockCalls)
}

func TestGoAutoSDKStaleBlockDoesNotAffectReplacement(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	filter := &recordingServiceFilter{}
	tracer.pidsFilter = filter
	processRoot := tracer.goProcessAdmissions[process].processRoot
	replacementStartTime := tracer.goProcessGenerationByPID[process].fileInfo.StartTime()
	optionKey := goSpanOptionFunctionKey{
		HostPID:    key.PID,
		Generation: key.Generation,
		Function:   99,
	}
	typeInfoKey := key
	optionMap := &fakeGoSpanOptionMap{
		values: map[goSpanOptionFunctionKey]uint8{optionKey: goSpanOptionKind},
	}
	typeInfoMap := &fakeGoAutoSDKTypeInfoMap{
		values: map[goProcessKey]BpfGoAutoSdkTypeInfoT{typeInfoKey: {}},
	}
	processAdmission := goProcessAdmissionState{
		startTime:       replacementStartTime,
		generationReady: true,
		fileInfo:        tracer.goProcessGenerationByPID[process].fileInfo,
		processRoot:     processRoot,
	}
	autoSDKAdmission := goAutoSDKAdmissionState{
		startTime:            replacementStartTime,
		executable:           testGoExecutableKey(55),
		samplerReady:         true,
		generationReady:      true,
		optionFunctionsReady: true,
		typeInfoReady:        true,
		globalReady:          true,
		globalPatchReady:     true,
		fileInfo:             tracer.goProcessGenerationByPID[process].fileInfo,
	}
	tracer.goProcessGenerations = &fakeGoProcessGenerationMap{
		values: map[uint32]goProcessGenerationValue{
			uint32(key.PID): {
				Generation: key.Generation,
				StartTime:  replacementStartTime,
			},
		},
	}
	tracer.goSpanOptionFunctions = optionMap
	tracer.goAutoSDKTypeInfos = typeInfoMap
	tracer.goSpanOptionKeysByProcess = map[runtimeMetricTargetKey][]goSpanOptionFunctionKey{
		process: {optionKey},
	}
	tracer.goAutoSDKTypeInfoKeys = map[runtimeMetricTargetKey]goProcessKey{
		process: typeInfoKey,
	}
	tracer.goProcessAdmissions = map[runtimeMetricTargetKey]goProcessAdmissionState{
		process: processAdmission,
	}
	tracer.goAutoSDKAdmissions = map[runtimeMetricTargetKey]goAutoSDKAdmissionState{
		process: autoSDKAdmission,
	}
	runtimeTarget := BpfPidInfo{
		HostPid: uint32(key.PID),
		UserPid: uint32(process.pid),
		Ns:      process.ns,
	}
	tracer.runtimeMetricTargetKeys = map[runtimeMetricTargetKey]BpfPidInfo{
		process: runtimeTarget,
	}
	tracer.activateGoAutoSDKFlag(key)
	staleFileInfo := exec.New(exec.Init{
		Pid:       process.pid,
		Ns:        process.ns,
		StartTime: replacementStartTime,
	})

	tracer.BlockPIDForProcess(
		process.pid,
		process.ns,
		staleFileInfo,
	)

	assert.Equal(t, byte(1), access.memory[flagPtr])
	assert.Contains(t, tracer.goAutoSDKFlagStates, process)
	assert.Equal(t, goAutoSDKFlagActive, flagMap.values[key].Activated)
	assert.Zero(t, filter.blocked)
	assert.Zero(t, sampler.blockCalls)
	assert.Equal(
		t,
		goProcessGenerationValue{
			Generation: key.Generation,
			StartTime:  replacementStartTime,
		},
		tracer.goProcessGenerations.(*fakeGoProcessGenerationMap).
			values[uint32(key.PID)],
	)
	assert.Contains(t, tracer.goProcessGenerationByPID, process)
	assert.Equal(t, process, tracer.goProcessOwnerByHostPID[uint32(key.PID)])
	assert.Equal(t, processAdmission, tracer.goProcessAdmissions[process])
	assert.Equal(t, autoSDKAdmission, tracer.goAutoSDKAdmissions[process])
	assert.Equal(t, goSpanOptionKind, optionMap.values[optionKey])
	assert.Equal(t, []goSpanOptionFunctionKey{optionKey}, tracer.goSpanOptionKeysByProcess[process])
	assert.Contains(t, typeInfoMap.values, typeInfoKey)
	assert.Equal(t, typeInfoKey, tracer.goAutoSDKTypeInfoKeys[process])
	assert.Equal(t, runtimeTarget, tracer.runtimeMetricTargetKeys[process])
}

func TestGoAutoSDKRestoreDrainsExactCounterBeforeDeletingDiscovery(t *testing.T) {
	var operations []string
	tracer, process, key, _, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	flagMap.operations = &operations
	access.operations = &operations
	sampler.operations = &operations
	inflight := tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap)
	inflight.operations = &operations
	tracer.goAutoSDKDrainPause = func() {
		operations = append(operations, "inflight:complete")
		state := tracer.goAutoSDKFlagStates[process]
		counter := inflight.values[goAutoSDKInflightKeyForState(state)]
		setGoAutoSDKInflightActiveCalls(&counter, 0)
		inflight.values[goAutoSDKInflightKeyForState(state)] = counter
	}
	tracer.activateGoAutoSDKFlag(key)
	state := tracer.goAutoSDKFlagStates[process]
	counter := inflight.values[goAutoSDKInflightKeyForState(state)]
	setGoAutoSDKInflightActiveCalls(&counter, 1)
	inflight.values[goAutoSDKInflightKeyForState(state)] = counter
	operations = nil

	require.True(t, tracer.restoreGoAutoSDKFlag(process))

	assert.Less(
		t,
		operationIndex(t, operations, "memory:write:0"),
		operationIndex(t, operations, "memory:read"),
	)
	assert.Less(
		t,
		operationIndex(t, operations, "memory:read"),
		operationIndex(t, operations, "flag:2"),
	)
	assert.Less(
		t,
		operationIndex(t, operations, "flag:2"),
		operationIndex(t, operations, "readiness:quiesce"),
	)
	assert.Less(
		t,
		operationIndex(t, operations, "readiness:quiesce"),
		operationIndex(t, operations, "inflight:complete"),
	)
	assert.Less(
		t,
		operationIndex(t, operations, "inflight:complete"),
		operationIndex(t, operations, "flag:delete"),
	)
}

func TestGoAutoSDKPoisonedCounterRetainsLiveResources(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	tracer.activateGoAutoSDKFlag(key)
	state := tracer.goAutoSDKFlagStates[process]
	inflight := tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap)
	counterKey := goAutoSDKInflightKeyForState(state)
	counter := inflight.values[counterKey]
	setGoAutoSDKInflightPoisonGeneration(&counter, 1)
	inflight.values[counterKey] = counter

	assert.False(t, tracer.restoreGoAutoSDKFlag(process))

	assert.Zero(t, access.memory[flagPtr])
	assert.Contains(t, tracer.goAutoSDKFlagStates, process)
	assert.Equal(t, goAutoSDKFlagQuiescing, flagMap.values[key].Activated)
	assert.Equal(t, 1, sampler.quiesceCalls)
	assert.Contains(t, inflight.values, counterKey)

	setGoAutoSDKInflightPoisonGeneration(&counter, 0)
	inflight.values[counterKey] = counter
	require.True(t, tracer.restoreGoAutoSDKFlag(process))
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.NotContains(t, inflight.values, counterKey)
}

func TestGoAutoSDKPoisonedPRELatchRetainsAllLiveResources(t *testing.T) {
	tracer, _, key, flagPtr, _, access, _ := newGoAutoSDKLifecycleTestTracer(t)
	tracer.activateGoAutoSDKFlag(key)
	inflight := tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap)
	pendingKey := goAutoSDKInflightKeyForState(goAutoSDKPendingState())
	pending := inflight.values[pendingKey]
	setGoAutoSDKInflightPoisonGeneration(&pending, 1)
	inflight.values[pendingKey] = pending
	closer := &fakeGoTracerCloser{}
	resources := newGoTracerResources(tracer, closer)

	require.Error(t, resources.Close())

	assert.Zero(t, access.memory[flagPtr])
	assert.Zero(t, closer.closed)
	assert.False(t, resources.teardownReady())
	assert.False(t, tracer.goAutoSDKShutdownComplete)
	assert.Contains(t, inflight.values, pendingKey)

	setGoAutoSDKInflightPoisonGeneration(&pending, 0)
	inflight.values[pendingKey] = pending
	require.NoError(t, resources.Close())
	assert.Equal(t, 1, closer.closed)
	assert.Contains(t, inflight.values, pendingKey,
		"the reserved PRE latch is retained until map teardown")
}

func TestGoAutoSDKRestoreTargetZeroIgnoresOtherProcessChurn(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	startTime := tracer.goProcessGenerationByPID[process].fileInfo.StartTime()
	tracer.activateGoAutoSDKFlag(key)
	sampler.autoReady = true
	outerCalls := &fakeGoAutoSDKOuterCallMap{
		values: map[goAddrKey]goAutoSDKOuterCallValue{
			{PID: key.PID + 1, Addr: 0x55}: {
				StartTime:  startTime + 1,
				Generation: key.Generation + 1,
				FlagPtr:    flagPtr + 1,
				Epoch:      flagMap.values[key].Epoch + 1,
				State:      goAutoSDKOuterCallConsumedActive,
			},
		},
	}
	tracer.goAutoSDKOuterCalls = outerCalls
	inflight := tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap)
	otherKey := goAutoSDKInflightKey{
		PID:        key.PID + 1,
		Generation: key.Generation + 1,
		StartTime:  startTime + 1,
		Epoch:      flagMap.values[key].Epoch + 1,
	}
	inflight.values[otherKey] = goAutoSDKInflightTestValue(99, 1)
	churn := uint64(0x100)
	inflight.lookupHook = func(lookedUp goAutoSDKInflightKey) {
		if lookedUp.PID != key.PID {
			return
		}
		delete(outerCalls.values, goAddrKey{PID: key.PID + 1, Addr: churn - 1})
		outerCalls.values[goAddrKey{PID: key.PID + 1, Addr: churn}] = goAutoSDKOuterCallValue{
			StartTime:  startTime + 1,
			Generation: key.Generation + 1,
			Epoch:      otherKey.Epoch,
			State:      goAutoSDKOuterCallActive,
		}
		churn++
	}

	require.True(t, tracer.restoreGoAutoSDKFlag(process))

	assert.Zero(t, access.memory[flagPtr])
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.NotContains(t, flagMap.values, key)
	assert.False(t, sampler.autoReady)
	assert.Equal(t, 1, sampler.quiesceCalls)
	assert.NotEmpty(t, outerCalls.values)
	assert.Equal(t, uint32(99), inflight.values[otherKey].activeCalls())
	assert.Equal(t, uint32(1), inflight.values[otherKey].poisonGeneration())
}

func TestGoAutoSDKShutdownStopsCounterScanAtDeadline(t *testing.T) {
	tracer, _, _, _, _, _, _ := newGoAutoSDKLifecycleTestTracer(t)
	inflight := tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap)
	firstState := goAutoSDKFlagState{
		key:       goProcessKey{PID: 101, Generation: 11},
		startTime: 1001,
		epoch:     21,
	}
	secondState := goAutoSDKFlagState{
		key:       goProcessKey{PID: 102, Generation: 12},
		startTime: 1002,
		epoch:     22,
	}
	inflight.values[goAutoSDKInflightKeyForState(firstState)] = goAutoSDKInflightValue{}
	inflight.values[goAutoSDKInflightKeyForState(secondState)] = goAutoSDKInflightValue{}

	firstLookup := make(chan struct{})
	releaseLookup := make(chan struct{})
	var blockFirst sync.Once
	var lookedUp []goAutoSDKInflightKey
	inflight.lookupHook = func(key goAutoSDKInflightKey) {
		lookedUp = append(lookedUp, key)
		blockFirst.Do(func() {
			close(firstLookup)
			<-releaseLookup
		})
	}

	deadline := time.Now().Add(25 * time.Millisecond)
	result := make(chan bool, 1)
	go func() {
		result <- tracer.waitForGoAutoSDKShutdownTargets(
			[]goAutoSDKRestoreTarget{
				{state: firstState},
				{state: secondState},
			},
			newGoAutoSDKShutdownBudgetUntil(deadline),
		)
	}()

	<-firstLookup
	time.Sleep(time.Until(deadline) + 5*time.Millisecond)
	close(releaseLookup)

	assert.False(t, <-result)
	require.Len(t, lookedUp, 2)
	assert.Equal(t, goAutoSDKInflightKeyForState(firstState), lookedUp[0])
	assert.Equal(t, goAutoSDKInflightKeyForState(firstState), lookedUp[1])
}

func TestGoAutoSDKCleanupDeletesOuterCallAfterProcessExit(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, access, _ := newGoAutoSDKLifecycleTestTracer(t)
	outerKey := goAddrKey{PID: key.PID, Addr: 0x66}
	outerCalls := &fakeGoAutoSDKOuterCallMap{
		values: map[goAddrKey]goAutoSDKOuterCallValue{
			outerKey: {
				StartTime:  tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
				Generation: key.Generation,
				FlagPtr:    flagPtr,
				Epoch:      flagMap.values[key].Epoch,
				State:      goAutoSDKOuterCallActive,
			},
		},
	}
	tracer.goAutoSDKOuterCalls = outerCalls
	access.sessionErr = os.ErrNotExist

	require.True(t, tracer.cleanupCapturedGoAutoSDKFlag(process))

	assert.NotContains(t, outerCalls.values, outerKey)
	assert.NotContains(t, flagMap.values, key)
}

func TestGoAutoSDKStaleCleanupDeletesAllOuterCallStates(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, access, _ := newGoAutoSDKLifecycleTestTracer(t)
	startTime := tracer.goProcessGenerationByPID[process].fileInfo.StartTime()
	tracer.activateGoAutoSDKFlag(key)
	epoch := flagMap.values[key].Epoch
	outerCalls := &fakeGoAutoSDKOuterCallMap{
		values: map[goAddrKey]goAutoSDKOuterCallValue{},
	}
	states := []uint8{
		goAutoSDKOuterCallNone,
		goAutoSDKOuterCallCapture,
		goAutoSDKOuterCallActive,
		goAutoSDKOuterCallConsumedActive,
		goAutoSDKOuterCallDirectActive,
		goAutoSDKOuterCallDirectConsumed,
	}
	for index, state := range states {
		outerCalls.values[goAddrKey{
			PID:  key.PID,
			Addr: uint64(index + 1),
		}] = goAutoSDKOuterCallValue{
			StartTime:  startTime,
			Generation: key.Generation,
			FlagPtr:    flagPtr,
			Epoch:      epoch,
			State:      state,
		}
	}
	otherKey := goAddrKey{PID: key.PID + 1, Addr: 1}
	outerCalls.values[otherKey] = goAutoSDKOuterCallValue{
		StartTime:  startTime,
		Generation: key.Generation,
		FlagPtr:    flagPtr,
		Epoch:      epoch,
		State:      goAutoSDKOuterCallCapture,
	}
	tracer.goAutoSDKOuterCalls = outerCalls
	access.sessionErr = os.ErrNotExist

	require.True(t, tracer.restoreGoAutoSDKFlag(process))

	assert.Equal(
		t,
		map[goAddrKey]goAutoSDKOuterCallValue{
			otherKey: {
				StartTime:  startTime,
				Generation: key.Generation,
				FlagPtr:    flagPtr,
				Epoch:      epoch,
				State:      goAutoSDKOuterCallCapture,
			},
		},
		outerCalls.values,
	)
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.NotContains(t, flagMap.values, key)
	assert.Equal(t, 1, access.closeCalls)
}

func TestGoAutoSDKCleanupRetainsLinksWhenStaleOuterCallDeleteFails(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, access, _ := newGoAutoSDKLifecycleTestTracer(t)
	outerKey := goAddrKey{PID: key.PID, Addr: 0x67}
	outerCalls := &fakeGoAutoSDKOuterCallMap{
		values: map[goAddrKey]goAutoSDKOuterCallValue{
			outerKey: {
				StartTime:  tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
				Generation: key.Generation,
				FlagPtr:    flagPtr,
				Epoch:      flagMap.values[key].Epoch,
				State:      goAutoSDKOuterCallActive,
			},
		},
		deleteErr: errors.New("delete failed"),
	}
	tracer.goAutoSDKOuterCalls = outerCalls
	access.sessionErr = os.ErrNotExist

	assert.False(t, tracer.cleanupCapturedGoAutoSDKFlag(process))

	assert.Contains(t, outerCalls.values, outerKey)
	assert.Contains(t, flagMap.values, key)
}

func TestGoAutoSDKCapturedCleanupReconstructsAndDrainsExactCounter(t *testing.T) {
	var operations []string
	tracer, process, key, flagPtr, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	flagMap.operations = &operations
	access.operations = &operations
	sampler.operations = &operations
	outerCalls := &fakeGoAutoSDKOuterCallMap{
		values: map[goAddrKey]goAutoSDKOuterCallValue{
			{PID: key.PID, Addr: 0x77}: {
				StartTime:  tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
				Generation: key.Generation,
				FlagPtr:    flagPtr,
				Epoch:      flagMap.values[key].Epoch,
				State:      goAutoSDKOuterCallCapture,
			},
		},
		operations: &operations,
	}
	tracer.goAutoSDKOuterCalls = outerCalls
	inflight := tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap)
	inflight.operations = &operations
	state := goAutoSDKFlagState{
		key:       key,
		startTime: tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
		epoch:     flagMap.values[key].Epoch,
	}
	counterKey := goAutoSDKInflightKeyForState(state)
	counter := inflight.values[counterKey]
	setGoAutoSDKInflightActiveCalls(&counter, 1)
	inflight.values[counterKey] = counter
	tracer.goAutoSDKDrainPause = func() {
		counter := inflight.values[counterKey]
		setGoAutoSDKInflightActiveCalls(&counter, 0)
		inflight.values[counterKey] = counter
		operations = append(operations, "inflight:complete")
	}

	require.True(t, tracer.cleanupCapturedGoAutoSDKFlag(process))

	assert.Zero(t, access.writeCalls)
	assert.NotContains(t, flagMap.values, key)
	assert.NotContains(t, inflight.values, counterKey)
	assert.Less(
		t,
		operationIndex(t, operations, "readiness:quiesce"),
		operationIndex(t, operations, "inflight:complete"),
	)
	assert.Less(
		t,
		operationIndex(t, operations, "inflight:complete"),
		operationIndex(t, operations, "flag:delete"),
	)
	assert.NotContains(t, operations, "outer:scan")
	assert.Contains(t, outerCalls.values, goAddrKey{PID: key.PID, Addr: 0x77})
}

func TestGoAutoSDKCapturedCleanupWithoutMetadataRetainsExactResources(
	t *testing.T,
) {
	tracer, process, key, _, flagMap, _, sampler := newGoAutoSDKLifecycleTestTracer(t)
	state := tracer.goAutoSDKFlagStates[process]
	counterKey := goAutoSDKInflightKeyForState(state)
	inflight := tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap)
	counter := inflight.values[counterKey]
	setGoAutoSDKInflightActiveCalls(&counter, 1)
	inflight.values[counterKey] = counter
	delete(tracer.goAutoSDKFlagStates, process)
	delete(flagMap.values, key)
	fileInfo := tracer.goProcessGenerationByPID[process].fileInfo
	tracer.goAutoSDKAdmissions[process] = goAutoSDKAdmissionState{
		startTime:       fileInfo.StartTime(),
		authorityActive: true,
		fileInfo:        fileInfo,
	}

	assert.False(t, tracer.cleanupCapturedGoAutoSDKFlag(process))

	assert.Contains(t, inflight.values, counterKey,
		"a live exact counter cannot be inferred absent captured metadata")
	assert.Equal(t, uint32(1), inflight.values[counterKey].activeCalls())
	assert.Zero(t, sampler.quiesceCalls,
		"readiness and probes must remain while userspace flag ownership is unknown")
}

func TestGoAutoSDKCapturedCleanupClosesSessionAfterStartTimeError(t *testing.T) {
	tracer, process, key, _, flagMap, access, _ := newGoAutoSDKLifecycleTestTracer(t)
	prepared := tracer.goAutoSDKFlagStates[process]
	require.NoError(t, prepared.incarnation.Close())
	delete(tracer.goAutoSDKFlagStates, process)
	delete(flagMap.values, key)
	fileInfo := tracer.goProcessGenerationByPID[process].fileInfo
	startTime := fileInfo.StartTime()
	tracer.goAutoSDKAdmissions[process] = goAutoSDKAdmissionState{
		startTime:       startTime,
		authorityActive: true,
		fileInfo:        fileInfo,
	}
	access.startResults = []fakeGoAutoSDKStartResult{
		{startTime: startTime},
		{err: errors.New("transient stat failure")},
	}

	assert.False(t, tracer.cleanupCapturedGoAutoSDKFlag(process))

	assert.Equal(t, 2, access.closeCalls)
}

func TestGoAutoSDKActiveCleanupWithoutIncarnationFailsClosed(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	tracer.activateGoAutoSDKFlag(key)
	state := tracer.goAutoSDKFlagStates[process]
	delete(tracer.goAutoSDKFlagStates, process)
	fileInfo := tracer.goProcessGenerationByPID[process].fileInfo
	tracer.goAutoSDKAdmissions[process] = goAutoSDKAdmissionState{
		startTime:       fileInfo.StartTime(),
		authorityActive: true,
		fileInfo:        fileInfo,
	}
	t.Cleanup(func() {
		require.NoError(t, state.incarnation.Close())
	})
	openCalls := access.openCalls
	writeCalls := access.writeCalls

	assert.False(t, tracer.cleanupCapturedGoAutoSDKFlag(process))

	assert.Equal(t, openCalls, access.openCalls)
	assert.Equal(t, writeCalls, access.writeCalls)
	assert.Equal(t, byte(1), access.memory[flagPtr])
	assert.Contains(t, flagMap.values, key)
	assert.Zero(t, sampler.quiesceCalls)
}

func TestGoTracerResourcesCloseEntryBarriersInSafePublicationOrder(t *testing.T) {
	var operations []string
	tracer, _, key, flagPtr, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	flagMap.operations = &operations
	access.operations = &operations
	sampler.operations = &operations
	tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap).operations = &operations
	tracer.activateGoAutoSDKFlag(key)
	operations = nil
	directEntry := &fakeGoTracerCloser{
		operation:  "direct-entry:close",
		operations: &operations,
	}
	tracer.goAutoSDKDirectEntryClosers = []io.Closer{directEntry}
	globalEntry := &fakeGoTracerCloser{
		operation:  "global-entry:close",
		operations: &operations,
	}
	tracer.goAutoSDKGlobalEntryClosers = []io.Closer{globalEntry}
	closer := &fakeGoTracerCloser{operations: &operations}
	resources := newGoTracerResources(tracer, closer)

	require.NoError(t, resources.Close())

	assert.Zero(t, access.memory[flagPtr])
	assert.Equal(t, 1, directEntry.closed)
	assert.Equal(t, 1, globalEntry.closed)
	assert.Equal(t, 1, closer.closed)
	assert.Less(
		t,
		operationIndex(t, operations, "direct-entry:close"),
		operationIndex(t, operations, "memory:write:0"),
	)
	assert.Less(
		t,
		operationIndex(t, operations, "memory:write:0"),
		operationIndex(t, operations, "memory:read"),
	)
	assert.Less(
		t,
		operationIndex(t, operations, "memory:read"),
		operationIndex(t, operations, "global-entry:close"),
	)
	assert.Less(
		t,
		operationIndex(t, operations, "global-entry:close"),
		operationIndex(t, operations, "readiness:quiesce"),
	)
	assert.Less(
		t,
		operationIndex(t, operations, "readiness:quiesce"),
		operationIndex(t, operations, "inflight:lookup"),
	)
	assert.Less(
		t,
		operationIndex(t, operations, "inflight:lookup"),
		operationIndex(t, operations, "links:close"),
	)
}

func TestGoTracerResourcesShutdownIgnoresOtherProcessOuterChurn(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	startTime := tracer.goProcessGenerationByPID[process].fileInfo.StartTime()
	tracer.activateGoAutoSDKFlag(key)
	sampler.autoReady = true
	call := goAutoSDKOuterCallValue{
		StartTime:  startTime + 1,
		Generation: key.Generation + 1,
		FlagPtr:    flagPtr + 1,
		Epoch:      flagMap.values[key].Epoch + 1,
		State:      goAutoSDKOuterCallConsumedActive,
	}
	outerCalls := &fakeGoAutoSDKOuterCallMap{
		values: map[goAddrKey]goAutoSDKOuterCallValue{
			{PID: key.PID + 1, Addr: 0x61}: call,
		},
	}
	tracer.goAutoSDKOuterCalls = outerCalls
	inflight := tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap)
	otherKey := goAutoSDKInflightKey{
		PID:        key.PID + 1,
		Generation: call.Generation,
		StartTime:  call.StartTime,
		Epoch:      call.Epoch,
	}
	inflight.values[otherKey] = goAutoSDKInflightTestValue(1, 0)
	closer := &fakeGoTracerCloser{}
	resources := newGoTracerResources(tracer, closer)

	require.NoError(t, resources.Close())

	assert.Zero(t, access.memory[flagPtr])
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.NotContains(t, flagMap.values, key)
	assert.False(t, sampler.autoReady)
	assert.True(t, tracer.goAutoSDKShutdownComplete)
	assert.True(t, resources.teardownReady())
	assert.Equal(t, 1, closer.closed)
	assert.NotEmpty(t, outerCalls.values)
	assert.Equal(t, uint32(1), inflight.values[otherKey].activeCalls())
}

func TestGoTracerResourcesDeleteStaleOuterCallsBeforeClosingLinks(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, access, _ := newGoAutoSDKLifecycleTestTracer(t)
	outerKey := goAddrKey{PID: key.PID, Addr: 0x88}
	outerCalls := &fakeGoAutoSDKOuterCallMap{
		values: map[goAddrKey]goAutoSDKOuterCallValue{
			outerKey: {
				StartTime:  tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
				Generation: key.Generation,
				FlagPtr:    flagPtr,
				Epoch:      flagMap.values[key].Epoch,
				State:      goAutoSDKOuterCallConsumedActive,
			},
		},
	}
	tracer.goAutoSDKOuterCalls = outerCalls
	tracer.goAutoSDKDrainPause = func() {}
	access.sessionErr = os.ErrNotExist
	closer := &fakeGoTracerCloser{}
	resources := newGoTracerResources(tracer, closer)

	require.NoError(t, resources.Close())

	assert.NotContains(t, outerCalls.values, outerKey)
	assert.NotContains(t, flagMap.values, key)
	assert.True(t, tracer.goAutoSDKShutdownComplete)
	assert.True(t, resources.teardownReady())
	assert.Equal(t, 1, closer.closed)
}

func TestGoTracerResourcesDrainConcurrentCaptureAcrossActivation(t *testing.T) {
	var inflightOperations []string
	tracer, process, key, flagPtr, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	require.Equal(t, goAutoSDKFlagCaptured, flagMap.values[key].Activated)
	require.Zero(t, access.memory[flagPtr])

	// Capture A has already published discovery. Capture B starts and owns the
	// exact count before userspace activates the shared flag, then pauses
	// before its bool read / nested auto Start completes.
	state := tracer.goAutoSDKFlagStates[process]
	inflight := tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap)
	counterKey := goAutoSDKInflightKeyForState(state)
	counter := inflight.values[counterKey]
	setGoAutoSDKInflightActiveCalls(&counter, 1)
	inflight.values[counterKey] = counter
	inflight.operations = &inflightOperations
	outerKey := goAddrKey{PID: key.PID, Addr: 0x88}
	outerCalls := &fakeGoAutoSDKOuterCallMap{
		values: map[goAddrKey]goAutoSDKOuterCallValue{
			outerKey: {
				StartTime:  tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
				Generation: key.Generation,
				FlagPtr:    flagPtr,
				Epoch:      flagMap.values[key].Epoch,
				State:      goAutoSDKOuterCallCapture,
			},
		},
	}
	tracer.goAutoSDKOuterCalls = outerCalls
	tracer.activateGoAutoSDKFlag(key)
	require.Equal(t, byte(1), access.memory[flagPtr])
	inflightOperations = nil
	sampler.autoReady = true
	tracer.goAutoSDKDrainPause = nil
	closer := &fakeGoTracerCloser{}
	resources := newGoTracerResources(tracer, closer)

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- resources.Close()
	}()

	var closeErr error
	select {
	case closeErr = <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("resource close did not stop after bounded shutdown attempts")
	}
	require.EqualError(
		t,
		closeErr,
		"shutdown of Go Auto SDK remained unsafe until the shutdown deadline; eBPF resources remain attached",
	)

	assert.NotEmpty(t, inflightOperations)
	assert.LessOrEqual(t, len(inflightOperations), goAutoSDKDrainAttempts+2)
	assert.Zero(t, access.memory[flagPtr])
	state, retained := tracer.goAutoSDKFlagStates[process]
	require.True(t, retained)
	assert.False(t, state.restoreRequired)
	assert.Equal(t, goAutoSDKFlagQuiescing, flagMap.values[key].Activated)
	assert.True(t, tracer.goAutoSDKQuiescing[process])
	assert.True(t, tracer.goAutoSDKShuttingDown)
	assert.False(t, tracer.goAutoSDKShutdownComplete)
	assert.False(t, sampler.autoReady)
	assert.Equal(t, 1, sampler.quiesceCalls)
	assert.Contains(t, outerCalls.values, outerKey)
	assert.Zero(t, closer.closed)

	counter = inflight.values[counterKey]
	setGoAutoSDKInflightActiveCalls(&counter, 0)
	inflight.values[counterKey] = counter
	require.NoError(t, resources.Close())

	assert.True(t, tracer.goAutoSDKShutdownComplete)
	assert.False(t, sampler.autoReady)
	assert.Equal(t, 2, sampler.quiesceCalls)
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.NotContains(t, flagMap.values, key)
	assert.Equal(t, 1, closer.closed)
}

func TestGoTracerResourcesBoundShutdownAcrossManyLiveProcesses(t *testing.T) {
	const processCount = 64

	tracer, _, _, _, flagMap, access, _ := newGoAutoSDKLifecycleTestTracer(t)
	tracer.goProcessGenerationByPID = make(
		map[runtimeMetricTargetKey]goProcessGenerationState,
		processCount,
	)
	tracer.goProcessOwnerByHostPID = make(
		map[uint32]runtimeMetricTargetKey,
		processCount,
	)
	tracer.goAutoSDKFlagStates = make(
		map[runtimeMetricTargetKey]goAutoSDKFlagState,
		processCount,
	)
	tracer.goAutoSDKQuiescing = make(map[runtimeMetricTargetKey]bool, processCount)
	flagMap.values = make(map[goProcessKey]goAutoSDKFlagValue, processCount)
	access.startTimes = make(map[uint32]uint64, processCount)
	access.memory = make(map[uint64]byte, processCount)
	var inflightOperations []string
	outerCalls := &fakeGoAutoSDKOuterCallMap{
		values: make(map[goAddrKey]goAutoSDKOuterCallValue, processCount),
	}
	tracer.goAutoSDKOuterCalls = outerCalls
	inflight := &fakeGoAutoSDKInflightMap{
		values:     make(map[goAutoSDKInflightKey]goAutoSDKInflightValue, processCount),
		operations: &inflightOperations,
	}
	tracer.goAutoSDKInflight = inflight
	tracer.goAutoSDKDrainPause = nil

	for i := range processCount {
		hostPID := uint32(1000 + i)
		startTime := uint64(90000000 + i)
		generation := uint64(100 + i)
		epoch := uint32(10 + i)
		flagPtr := uint64(0x200000 + i)
		process := runtimeMetricTargetKey{pid: app.PID(hostPID), ns: 7}
		key := goProcessKey{PID: uint64(hostPID), Generation: generation}
		fileInfo := exec.New(exec.Init{
			Pid:       app.PID(hostPID),
			Ns:        process.ns,
			StartTime: startTime,
		})
		tracer.goProcessGenerationByPID[process] = goProcessGenerationState{
			hostPID:    hostPID,
			generation: generation,
			fileInfo:   fileInfo,
		}
		tracer.goProcessOwnerByHostPID[hostPID] = process
		access.startTimes[hostPID] = startTime
		access.memory[flagPtr] = 1
		session, err := access.Open(nil, fileInfo)
		require.NoError(t, err)
		tracer.goAutoSDKFlagStates[process] = goAutoSDKFlagState{
			key:             key,
			flagPtr:         flagPtr,
			startTime:       startTime,
			epoch:           epoch,
			original:        0,
			restoreRequired: true,
			incarnation:     newGoAutoSDKProcessIncarnation(session),
			fileInfo:        fileInfo,
		}
		inflight.values[goAutoSDKInflightKey{
			PID:        uint64(hostPID),
			Generation: generation,
			StartTime:  startTime,
			Epoch:      epoch,
		}] = goAutoSDKInflightTestValue(1, 0)
		flagMap.values[key] = goAutoSDKFlagValue{
			FlagPtr:   flagPtr,
			StartTime: startTime,
			Epoch:     epoch,
			Activated: goAutoSDKFlagActive,
		}
		outerCalls.values[goAddrKey{PID: uint64(hostPID), Addr: uint64(i + 1)}] = goAutoSDKOuterCallValue{
			StartTime:  startTime,
			Generation: generation,
			FlagPtr:    flagPtr,
			Epoch:      epoch,
			State:      goAutoSDKOuterCallConsumedActive,
		}
	}

	closer := &fakeGoTracerCloser{}
	resources := newGoTracerResources(tracer, closer)
	started := time.Now()
	err := resources.Close()
	elapsed := time.Since(started)

	require.Error(t, err)
	assert.Less(t, elapsed, time.Second)
	assert.NotEmpty(t, inflightOperations)
	assert.LessOrEqual(
		t,
		len(inflightOperations),
		processCount*(goAutoSDKDrainAttempts+1),
	)
	assert.Zero(t, closer.closed)
	assert.False(t, resources.teardownReady())
	for flagPtr, value := range access.memory {
		assert.Zero(t, value, "flag %#x was not restored", flagPtr)
	}
}

func TestGoTracerResourcesWaitForRestorationBeforeClosingLinks(t *testing.T) {
	tracer, process, key, flagPtr, _, access, _ := newGoAutoSDKLifecycleTestTracer(t)
	tracer.activateGoAutoSDKFlag(key)
	access.writeResults = []fakeGoAutoSDKWriteResult{
		{err: errors.New("restore failed")},
		{err: errors.New("restore failed")},
		{err: errors.New("restore failed")},
	}
	tracer.goAutoSDKDrainPause = func() {}
	closer := &fakeGoTracerCloser{}
	resources := newGoTracerResources(tracer, closer)
	writeCalls := access.writeCalls

	require.NoError(t, resources.Close())

	assert.Zero(t, access.memory[flagPtr])
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.Equal(t, writeCalls+4, access.writeCalls)
	assert.Equal(t, 1, closer.closed)
}

func TestGoTracerResourcesOwnLateClosers(t *testing.T) {
	tracer := &Tracer{}
	first := &fakeGoTracerCloser{}
	resources := newGoTracerResources(tracer)
	resources.Add(first)

	require.NoError(t, resources.Close())
	assert.Equal(t, 1, first.closed)

	late := &fakeGoTracerCloser{}
	resources.Add(late)
	assert.Equal(t, 1, late.closed)

	retryingLate := &fakeGoTracerCloser{
		closeErrs: []error{errors.New("close failed"), nil},
	}
	resources.Add(retryingLate)
	assert.Equal(t, 1, retryingLate.closed)
	assert.False(t, resources.teardownReady())

	require.NoError(t, resources.Close())
	assert.Equal(t, 2, retryingLate.closed)
	assert.True(t, resources.teardownReady())
}

func TestGoTracerResourcesRetryFailedCloserBeforeDeadline(t *testing.T) {
	tracer := &Tracer{
		goAutoSDKDrainPause: func() {},
	}
	closer := &fakeGoTracerCloser{
		closeErrs: []error{errors.New("close failed"), nil},
	}
	resources := newGoTracerResources(tracer, closer)

	require.NoError(t, resources.Close())

	assert.Equal(t, 2, closer.closed)
	assert.True(t, resources.teardownReady())
}

func TestGoTracerResourcesRetainOnlyFailedClosersForRetry(t *testing.T) {
	closeErr := errors.New("close failed")
	var operations []string
	first := &fakeGoTracerCloser{
		operation:  "first:close",
		operations: &operations,
	}
	second := &fakeGoTracerCloser{
		operation:  "second:close",
		operations: &operations,
		closeErrs:  []error{closeErr, nil},
	}
	third := &fakeGoTracerCloser{
		operation:  "third:close",
		operations: &operations,
	}
	tracer := &Tracer{
		shutdownTimeout: 20 * time.Millisecond,
		goAutoSDKDrainPause: func() {
			time.Sleep(25 * time.Millisecond)
		},
	}
	resources := newGoTracerResources(tracer, first, second, third)

	err := resources.Close()

	require.ErrorIs(t, err, closeErr)
	assert.Equal(
		t,
		[]string{"third:close", "second:close", "first:close"},
		operations,
	)
	assert.Equal(t, 1, first.closed)
	assert.Equal(t, 1, second.closed)
	assert.Equal(t, 1, third.closed)
	assert.False(t, resources.teardownReady())
	resources.mu.Lock()
	require.Len(t, resources.closers, 1)
	assert.Same(t, second, resources.closers[0])
	resources.mu.Unlock()

	tracer.goAutoSDKDrainPause = func() {}
	require.NoError(t, resources.Close())

	assert.Equal(
		t,
		[]string{
			"third:close",
			"second:close",
			"first:close",
			"second:close",
		},
		operations,
	)
	assert.Equal(t, 1, first.closed)
	assert.Equal(t, 2, second.closed)
	assert.Equal(t, 1, third.closed)
	assert.True(t, resources.teardownReady())
}

func TestGoAutoSDKShutdownSerializesProbeReadinessWithoutRestart(t *testing.T) {
	const (
		ino    = uint64(55)
		symbol = "go.opentelemetry.io/auto/sdk.(*tracer).Start"
	)
	tracer, process, key, flagPtr, _, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	tracer.activateGoAutoSDKFlag(key)
	require.Equal(t, byte(1), access.memory[flagPtr])
	tracer.goAutoSDKEligibleByExecutable = map[goExecutableKey]bool{testGoExecutableKey(ino): true}
	tracer.goAutoSDKReadyByExecutable = map[goExecutableKey]bool{testGoExecutableKey(ino): false}
	tracer.goAutoSDKProbesByExecutable = map[goExecutableKey][]string{testGoExecutableKey(ino): {symbol}}

	readerCreations := 0
	tracer.newGoAutoSDKEventReader = func(*ebpf.Map) (goAutoSDKEventReader, error) {
		readerCreations++
		return newFakeGoAutoSDKEventReader(nil), nil
	}
	tracer.bpfObjects.GoAutoSdkFlagEvents = &ebpf.Map{}

	quiesceEntered := make(chan struct{})
	quiesceRelease := make(chan struct{})
	var releaseOnce sync.Once
	releaseQuiesce := func() {
		releaseOnce.Do(func() {
			close(quiesceRelease)
		})
	}
	defer releaseQuiesce()
	tracer.samplerManager = &blockingQuiesceGoAutoSDKSamplerManager{
		fakeGoAutoSDKSamplerManager: sampler,
		entered:                     quiesceEntered,
		release:                     quiesceRelease,
	}

	shutdownDone := make(chan bool)
	go func() {
		shutdownDone <- tracer.shutdownGoAutoSDK()
	}()
	select {
	case <-quiesceEntered:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not reach readiness quiescence")
	}

	recordStarted := make(chan struct{})
	recordDone := make(chan struct{})
	fileInfo := exec.New(exec.Init{Ino: ino, Pid: process.pid, Ns: process.ns})
	go func() {
		close(recordStarted)
		tracer.RecordGoProbeAttachments(fileInfo, map[string]bool{symbol: true})
		close(recordDone)
	}()
	<-recordStarted
	select {
	case <-recordDone:
		t.Fatal("probe readiness update bypassed shutdown serialization")
	case <-time.After(50 * time.Millisecond):
	}

	releaseQuiesce()
	select {
	case shutdownSafe := <-shutdownDone:
		require.True(t, shutdownSafe)
	case <-time.After(time.Second):
		t.Fatal("shutdown deadlocked with probe readiness update")
	}
	select {
	case <-recordDone:
	case <-time.After(time.Second):
		t.Fatal("probe readiness update deadlocked with shutdown")
	}

	assert.Zero(t, access.memory[flagPtr])
	assert.True(t, tracer.goAutoSDKShutdownComplete)
	assert.False(t, tracer.goAutoSDKReadyByExecutable[testGoExecutableKey(ino)])

	tracer.startGoAutoSDKRun(context.Background())

	assert.False(t, tracer.goAutoSDKRunStarted)
	assert.Zero(t, readerCreations)
}

func operationIndex(t *testing.T, operations []string, want string) int {
	t.Helper()
	for i, operation := range operations {
		if operation == want {
			return i
		}
	}
	require.Failf(t, "operation not found", "%q is absent from %v", want, operations)
	return -1
}
