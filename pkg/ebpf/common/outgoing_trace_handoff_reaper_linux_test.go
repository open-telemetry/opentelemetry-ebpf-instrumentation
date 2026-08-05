// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpfcommon

import (
	"encoding/binary"
	"errors"
	"math"
	"os"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type fakeOutgoingTraceMap struct {
	entries  map[any]any
	onUpdate func(key, value any, flags ebpf.MapUpdateFlags)
}

type fakeOutgoingTraceReferenceSource struct {
	refs []outgoingTraceHandoffRef
}

type restartingOutgoingTraceReferenceSource struct {
	total       int
	restartOnce bool
}

func (s fakeOutgoingTraceReferenceSource) scan(
	cursor []byte,
	budget int,
	visitRaw func([]byte) bool,
	visit func(outgoingTraceHandoffKey),
) ([]byte, int, bool, error) {
	start := 0
	if len(cursor) != 0 {
		if len(cursor) != 8 {
			return nil, 0, false, errors.New("invalid fake reference cursor")
		}
		start = int(binary.LittleEndian.Uint64(cursor))
	}
	if start >= len(s.refs) {
		return nil, 0, true, nil
	}
	end := min(start+budget, len(s.refs))
	for i, ref := range s.refs[start:end] {
		raw := make([]byte, 8)
		binary.LittleEndian.PutUint64(raw, uint64(start+i+1))
		if !visitRaw(raw) {
			return nil, i + 1, false, errOutgoingTraceScanRestart
		}
		visit(outgoingTraceHandoffKey{Egress: ref.Egress, Token: ref.Token})
	}
	if end == len(s.refs) {
		return nil, end - start, true, nil
	}
	next := make([]byte, 8)
	binary.LittleEndian.PutUint64(next, uint64(end))
	return next, end - start, false, nil
}

func (s fakeOutgoingTraceReferenceSource) capacity() int {
	return len(s.refs)
}

func (s *restartingOutgoingTraceReferenceSource) scan(
	cursor []byte,
	budget int,
	visitRaw func([]byte) bool,
	_ func(outgoingTraceHandoffKey),
) ([]byte, int, bool, error) {
	if s.restartOnce && len(cursor) != 0 {
		s.restartOnce = false
		raw := make([]byte, 8)
		binary.LittleEndian.PutUint64(raw, 1)
		if !visitRaw(raw) {
			return nil, 1, false, errOutgoingTraceScanRestart
		}
		return nil, 1, false, errOutgoingTraceScanRestart
	}

	start := 0
	if len(cursor) != 0 {
		if len(cursor) != 8 {
			return nil, 0, false, errors.New("invalid restart cursor")
		}
		start = int(binary.LittleEndian.Uint64(cursor))
	}
	end := min(start+budget, s.total)
	for i := start; i < end; i++ {
		raw := make([]byte, 8)
		binary.LittleEndian.PutUint64(raw, uint64(i+1))
		if !visitRaw(raw) {
			return nil, i - start + 1, false, errOutgoingTraceScanRestart
		}
	}
	if end == s.total {
		return nil, end - start, true, nil
	}
	next := make([]byte, 8)
	binary.LittleEndian.PutUint64(next, uint64(end))
	return next, end - start, false, nil
}

func (s *restartingOutgoingTraceReferenceSource) capacity() int {
	return s.total
}

func newFakeOutgoingTraceMap() *fakeOutgoingTraceMap {
	return &fakeOutgoingTraceMap{entries: map[any]any{}}
}

func fakeMapValue(value any) any {
	v := reflect.ValueOf(value)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	return v.Interface()
}

func (m *fakeOutgoingTraceMap) Lookup(key, valueOut any) error {
	value, ok := m.entries[fakeMapValue(key)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	out := reflect.ValueOf(valueOut)
	if out.Kind() != reflect.Pointer || out.IsNil() {
		return errors.New("value output is not a pointer")
	}
	out.Elem().Set(reflect.ValueOf(value))
	return nil
}

func (m *fakeOutgoingTraceMap) Update(
	key, value any,
	flags ebpf.MapUpdateFlags,
) error {
	exactKey := fakeMapValue(key)
	_, exists := m.entries[exactKey]
	if flags == ebpf.UpdateNoExist && exists {
		return ebpf.ErrKeyExist
	}
	if flags == ebpf.UpdateExist && !exists {
		return ebpf.ErrKeyNotExist
	}
	m.entries[exactKey] = fakeMapValue(value)
	if m.onUpdate != nil {
		m.onUpdate(exactKey, fakeMapValue(value), flags)
	}
	return nil
}

func (m *fakeOutgoingTraceMap) Delete(key any) error {
	exactKey := fakeMapValue(key)
	if _, ok := m.entries[exactKey]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.entries, exactKey)
	return nil
}

func (*fakeOutgoingTraceMap) NextKey(any, any) error {
	return ebpf.ErrKeyNotExist
}

type restartingOutgoingTraceAuthorityMap struct {
	*fakeOutgoingTraceMap
	keys        []outgoingTraceHandoffKey
	restartOnce bool
}

func (m *restartingOutgoingTraceAuthorityMap) NextKey(
	key,
	nextKeyOut any,
) error {
	if len(m.keys) == 0 {
		return ebpf.ErrKeyNotExist
	}

	var next outgoingTraceHandoffKey
	if key == nil {
		next = m.keys[0]
	} else {
		current, ok := fakeMapValue(key).(outgoingTraceHandoffKey)
		if !ok {
			return errors.New("invalid authority cursor")
		}
		if m.restartOnce && current == m.keys[len(m.keys)-1] {
			m.restartOnce = false
			next = m.keys[0]
		} else {
			index := -1
			for i := range m.keys {
				if m.keys[i] == current {
					index = i
					break
				}
			}
			switch {
			case index < 0:
				next = m.keys[0]
			case index+1 == len(m.keys):
				return ebpf.ErrKeyNotExist
			default:
				next = m.keys[index+1]
			}
		}
	}

	out := reflect.ValueOf(nextKeyOut)
	if out.Kind() != reflect.Pointer || out.IsNil() {
		return errors.New("next key output is not a pointer")
	}
	out.Elem().Set(reflect.ValueOf(next))
	return nil
}

func (m *restartingOutgoingTraceAuthorityMap) outgoingTraceCapacity() int {
	return len(m.keys)
}

type scaledOutgoingTraceAuthorityMap struct {
	count       int
	activeValue outgoingTraceHandoffValue
	tailValue   outgoingTraceHandoffValue
	tailDeleted bool
}

func (m *scaledOutgoingTraceAuthorityMap) key(sequence int) outgoingTraceHandoffKey {
	key := testOutgoingTraceKey()
	key.Token.Sequence = uint64(sequence)
	return key
}

func (m *scaledOutgoingTraceAuthorityMap) sequence(key any) (int, bool) {
	exact, ok := fakeMapValue(key).(outgoingTraceHandoffKey)
	if !ok || exact.Token.Sequence == 0 ||
		exact.Token.Sequence > uint64(m.count) ||
		exact != m.key(int(exact.Token.Sequence)) {
		return 0, false
	}
	return int(exact.Token.Sequence), true
}

func (m *scaledOutgoingTraceAuthorityMap) Lookup(key, valueOut any) error {
	sequence, ok := m.sequence(key)
	if !ok || (sequence == m.count && m.tailDeleted) {
		return ebpf.ErrKeyNotExist
	}
	value := m.activeValue
	if sequence == m.count {
		value = m.tailValue
	}
	out := reflect.ValueOf(valueOut)
	if out.Kind() != reflect.Pointer || out.IsNil() {
		return errors.New("value output is not a pointer")
	}
	out.Elem().Set(reflect.ValueOf(value))
	return nil
}

func (*scaledOutgoingTraceAuthorityMap) Update(
	any,
	any,
	ebpf.MapUpdateFlags,
) error {
	return errors.New("scaled authority does not support updates")
}

func (m *scaledOutgoingTraceAuthorityMap) Delete(key any) error {
	sequence, ok := m.sequence(key)
	if !ok || sequence != m.count || m.tailDeleted {
		return ebpf.ErrKeyNotExist
	}
	m.tailDeleted = true
	return nil
}

func (m *scaledOutgoingTraceAuthorityMap) NextKey(
	key,
	nextKeyOut any,
) error {
	sequence := 1
	if key != nil {
		current, ok := m.sequence(key)
		if !ok || current == m.count {
			return ebpf.ErrKeyNotExist
		}
		sequence = current + 1
	}
	out := reflect.ValueOf(nextKeyOut)
	if out.Kind() != reflect.Pointer || out.IsNil() {
		return errors.New("next key output is not a pointer")
	}
	out.Elem().Set(reflect.ValueOf(m.key(sequence)))
	return nil
}

func (m *scaledOutgoingTraceAuthorityMap) outgoingTraceCapacity() int {
	return m.count
}

type deadProcessOutgoingTraceAuthorityMap struct {
	count           int
	uniqueProcesses bool
	value           outgoingTraceHandoffValue
	deleted         []bool
	deletedCount    int
}

func newDeadProcessOutgoingTraceAuthorityMap(
	count int,
	uniqueProcesses bool,
	value outgoingTraceHandoffValue,
) *deadProcessOutgoingTraceAuthorityMap {
	return &deadProcessOutgoingTraceAuthorityMap{
		count:           count,
		uniqueProcesses: uniqueProcesses,
		value:           value,
		deleted:         make([]bool, count+1),
	}
}

func (m *deadProcessOutgoingTraceAuthorityMap) key(
	sequence int,
) outgoingTraceHandoffKey {
	key := testOutgoingTraceKey()
	key.Token.Sequence = uint64(sequence)
	if m.uniqueProcesses {
		key.Egress.PID = uint32(sequence)
		key.Token.ProcessStartTime = uint64(sequence) + 10_000
	} else {
		key.Egress.PID = 42
		key.Token.ProcessStartTime = 10_042
	}
	return key
}

func (m *deadProcessOutgoingTraceAuthorityMap) sequence(
	key any,
) (int, bool) {
	exact, ok := fakeMapValue(key).(outgoingTraceHandoffKey)
	if !ok || exact.Token.Sequence == 0 ||
		exact.Token.Sequence > uint64(m.count) ||
		exact != m.key(int(exact.Token.Sequence)) {
		return 0, false
	}
	return int(exact.Token.Sequence), true
}

func (m *deadProcessOutgoingTraceAuthorityMap) Lookup(
	key,
	valueOut any,
) error {
	sequence, ok := m.sequence(key)
	if !ok || m.deleted[sequence] {
		return ebpf.ErrKeyNotExist
	}
	out := reflect.ValueOf(valueOut)
	if out.Kind() != reflect.Pointer || out.IsNil() {
		return errors.New("value output is not a pointer")
	}
	out.Elem().Set(reflect.ValueOf(m.value))
	return nil
}

func (*deadProcessOutgoingTraceAuthorityMap) Update(
	any,
	any,
	ebpf.MapUpdateFlags,
) error {
	return errors.New("dead-process authority does not support updates")
}

func (m *deadProcessOutgoingTraceAuthorityMap) Delete(key any) error {
	sequence, ok := m.sequence(key)
	if !ok || m.deleted[sequence] {
		return ebpf.ErrKeyNotExist
	}
	m.deleted[sequence] = true
	m.deletedCount++
	return nil
}

func (m *deadProcessOutgoingTraceAuthorityMap) NextKey(
	key,
	nextKeyOut any,
) error {
	sequence := 1
	if key != nil {
		current, ok := m.sequence(key)
		if !ok || current == m.count {
			return ebpf.ErrKeyNotExist
		}
		sequence = current + 1
	}
	out := reflect.ValueOf(nextKeyOut)
	if out.Kind() != reflect.Pointer || out.IsNil() {
		return errors.New("next key output is not a pointer")
	}
	out.Elem().Set(reflect.ValueOf(m.key(sequence)))
	return nil
}

func (m *deadProcessOutgoingTraceAuthorityMap) outgoingTraceCapacity() int {
	return m.count
}

func testOutgoingTraceKey() outgoingTraceHandoffKey {
	return outgoingTraceHandoffKey{
		Egress: outgoingTraceEgressKey{
			PID:             0,
			StreamID:        3,
			SourcePort:      31000,
			DestinationPort: 443,
		},
		Token: outgoingTraceToken{
			MapEpoch:         7,
			Sequence:         11,
			ProcessStartTime: 13,
			CPU:              2,
		},
	}
}

func testOutgoingTraceValue(now uint64) outgoingTraceHandoffValue {
	return outgoingTraceHandoffValue{
		Trace: outgoingTraceParentPID{
			Trace: outgoingTraceParent{
				TraceID:   [16]byte{1},
				SpanID:    [8]byte{2},
				Timestamp: 17,
				Flags:     1,
			},
			Valid:       1,
			Written:     outboundTraceWritten,
			RequestType: 2,
		},
		CreatedAt:     now - 100,
		LastProgress:  now - 50,
		TerminalAt:    now,
		LocalConsumed: 1,
	}
}

func testOutgoingTraceReaper(
	authority outgoingTraceMap,
	locators, claims, egressClaims, legacy *fakeOutgoingTraceMap,
) *outgoingTraceHandoffReaper {
	reaper := &outgoingTraceHandoffReaper{
		authority:            authority,
		locators:             locators,
		claims:               claims,
		egressClaims:         egressClaims,
		deadObservations:     map[outgoingTraceProcessKey]outgoingTraceDeadObservation{},
		deadObservationLimit: outgoingTraceMapTraversalCapacity(authority),
		claimConflicts:       map[outgoingTraceHandoffKey]uint8{},
		timeOffsetsValid:     true,
	}
	if legacy != nil {
		reaper.legacy = legacy
	}
	return reaper
}

func TestOutgoingTraceHandoffReaperABI(t *testing.T) {
	assert.Equal(t, uintptr(44), unsafe.Sizeof(outgoingTraceEgressKey{}))
	assert.Equal(t, uintptr(32), unsafe.Sizeof(outgoingTraceToken{}))
	assert.Equal(t, uintptr(80), unsafe.Sizeof(outgoingTraceHandoffKey{}))
	assert.Equal(t, uintptr(48), unsafe.Sizeof(outgoingTraceParent{}))
	assert.Equal(t, uintptr(56), unsafe.Sizeof(outgoingTraceParentPID{}))
	assert.Equal(t, uintptr(88), unsafe.Sizeof(outgoingTraceHandoffValue{}))
	assert.Equal(t, uintptr(80), unsafe.Sizeof(outgoingTraceHandoffRef{}))
	assert.Equal(t, uintptr(48), unsafe.Offsetof(outgoingTraceHandoffKey{}.Token))
	assert.Equal(t, uintptr(56), unsafe.Offsetof(outgoingTraceHandoffValue{}.CreatedAt))
}

func TestOutgoingTraceHandoffReaperRetiresExactGeneration(t *testing.T) {
	const now = uint64(10_000)
	key := testOutgoingTraceKey()
	value := testOutgoingTraceValue(now)
	value.Trace.PID = key.Egress.PID

	authority := newFakeOutgoingTraceMap()
	locators := newFakeOutgoingTraceMap()
	claims := newFakeOutgoingTraceMap()
	egressClaims := newFakeOutgoingTraceMap()
	legacy := newFakeOutgoingTraceMap()
	authority.entries[key] = value
	locators.entries[key.Egress] = key.Token
	legacy.entries[key.Egress] = value.Trace
	reaper := testOutgoingTraceReaper(
		authority, locators, claims, egressClaims, legacy,
	)

	reaper.maybeRetire(key, value, now)

	assert.NotContains(t, authority.entries, key)
	assert.NotContains(t, locators.entries, key.Egress)
	assert.NotContains(t, legacy.entries, key.Egress)
	assert.Empty(t, claims.entries)
	assert.Empty(t, egressClaims.entries)
	assert.Equal(t, uint64(1), reaper.counters.retired.Load())
}

func TestOutgoingTraceHandoffReaperNeverStealsClaim(t *testing.T) {
	const now = uint64(10_000)
	key := testOutgoingTraceKey()
	value := testOutgoingTraceValue(now)
	authority := newFakeOutgoingTraceMap()
	claims := newFakeOutgoingTraceMap()
	authority.entries[key] = value
	claims.entries[key] = uint8(1)
	reaper := testOutgoingTraceReaper(
		authority,
		newFakeOutgoingTraceMap(),
		claims,
		newFakeOutgoingTraceMap(),
		nil,
	)

	reaper.maybeRetire(key, value, now)

	assert.Contains(t, authority.entries, key)
	assert.Equal(t, uint8(1), claims.entries[key])
	assert.Equal(t, uint64(1), reaper.counters.claimConflicts.Load())
}

func TestOutgoingTraceHandoffReaperRechecksAfterClaim(t *testing.T) {
	const now = uint64(10_000)
	key := testOutgoingTraceKey()
	terminal := testOutgoingTraceValue(now)
	active := terminal
	active.TerminalAt = 0
	active.LocalConsumed = 0
	active.Trace.Written = 0
	active.CreatedAt = now
	active.LastProgress = now

	authority := newFakeOutgoingTraceMap()
	claims := newFakeOutgoingTraceMap()
	authority.entries[key] = terminal
	claims.onUpdate = func(any, any, ebpf.MapUpdateFlags) {
		authority.entries[key] = active
	}
	reaper := testOutgoingTraceReaper(
		authority,
		newFakeOutgoingTraceMap(),
		claims,
		newFakeOutgoingTraceMap(),
		nil,
	)
	reaper.maybeRetire(key, terminal, now)

	require.Equal(t, active, authority.entries[key])
	assert.Empty(t, claims.entries)
	assert.Zero(t, reaper.counters.retired.Load())
}

func TestOutgoingTraceHandoffReaperKeepsNewerLocator(t *testing.T) {
	const now = uint64(10_000)
	key := testOutgoingTraceKey()
	value := testOutgoingTraceValue(now)
	newer := key.Token
	newer.Sequence++

	authority := newFakeOutgoingTraceMap()
	locators := newFakeOutgoingTraceMap()
	authority.entries[key] = value
	locators.entries[key.Egress] = newer
	reaper := testOutgoingTraceReaper(
		authority,
		locators,
		newFakeOutgoingTraceMap(),
		newFakeOutgoingTraceMap(),
		nil,
	)

	reaper.maybeRetire(key, value, now)

	assert.NotContains(t, authority.entries, key)
	assert.Equal(t, newer, locators.entries[key.Egress])
}

func TestOutgoingTraceShouldRetireConservatively(t *testing.T) {
	now := uint64(outgoingTraceOrphanTTL) + 1_000
	active := outgoingTraceHandoffValue{
		CreatedAt:    1_000,
		LastProgress: now - uint64(outgoingTraceOrphanTTL),
	}
	assert.False(t, outgoingTraceShouldRetire(active, false, false, now))
	assert.True(t, outgoingTraceShouldRetire(active, true, false, now))

	now = uint64(outgoingTraceHardTTL) + 1_000
	active.CreatedAt = now - uint64(outgoingTraceHardTTL)
	assert.False(t, outgoingTraceShouldRetire(active, false, false, now))
	assert.True(t, outgoingTraceShouldRetire(active, true, false, now))
}

func TestOutgoingTraceCurrentProcessIncarnationIsAlive(t *testing.T) {
	start, err := outgoingTraceProcStartTime(uint32(os.Getpid()))
	require.NoError(t, err)
	offsets, offsetsValid := outgoingTraceLoadTimeNamespaceOffsets()
	require.True(t, offsetsValid)
	rawStart, ok := outgoingTraceSubtractSignedOffset(start, offsets.boottime)
	require.True(t, ok)
	assert.Equal(t,
		outgoingTraceProcessAlive,
		outgoingTraceProcessIncarnationStatus(outgoingTraceProcessKey{
			PID:       uint32(os.Getpid()),
			StartTime: rawStart,
		}, offsets, true),
	)
}

func TestOutgoingTraceReaperUsesBPFMonotonicClockDomain(t *testing.T) {
	original := outgoingTraceClockGettime
	t.Cleanup(func() { outgoingTraceClockGettime = original })

	var observedClock int32 = -1
	outgoingTraceClockGettime = func(clockID int32, ts *unix.Timespec) error {
		observedClock = clockID
		ts.Sec = 12
		ts.Nsec = 34
		return nil
	}

	got, ok := outgoingTraceMonotonicNanoseconds(
		outgoingTraceTimeNamespaceOffsets{},
	)
	require.True(t, ok)
	assert.Equal(t,
		uint64(12)*uint64(time.Second)+34,
		got)
	assert.Equal(t, int32(unix.CLOCK_MONOTONIC), observedClock)
	assert.NotEqual(t, int32(unix.CLOCK_BOOTTIME), observedClock,
		"suspend-inclusive time must never age BPF monotonic timestamps")
}

func TestOutgoingTraceSignedTimeNamespaceOffsets(t *testing.T) {
	originalClock := outgoingTraceClockGettime
	t.Cleanup(func() { outgoingTraceClockGettime = originalClock })

	offsets, ok := outgoingTraceParseTimeNamespaceOffsets([]byte(
		"monotonic 7200 5\nboottime -7200 500000000\n",
	))
	require.True(t, ok)
	assert.Equal(t, int64(7200)*int64(time.Second)+5, offsets.monotonic)
	assert.Equal(
		t,
		-int64(7199)*int64(time.Second)-int64(500*time.Millisecond),
		offsets.boottime,
	)

	outgoingTraceClockGettime = func(_ int32, ts *unix.Timespec) error {
		ts.Sec = 7201
		return nil
	}
	raw, ok := outgoingTraceMonotonicNanoseconds(
		outgoingTraceTimeNamespaceOffsets{
			monotonic: int64(7200 * time.Second),
		},
	)
	require.True(t, ok)
	assert.Equal(t, uint64(time.Second), raw)

	outgoingTraceClockGettime = func(_ int32, ts *unix.Timespec) error {
		ts.Sec = 1
		return nil
	}
	raw, ok = outgoingTraceMonotonicNanoseconds(
		outgoingTraceTimeNamespaceOffsets{
			monotonic: -int64(7200 * time.Second),
		},
	)
	require.True(t, ok)
	assert.Equal(t, uint64(7201*time.Second), raw)
}

func TestOutgoingTraceTimeNamespaceOffsetsFailClosed(t *testing.T) {
	originalReadlink := outgoingTraceReadlink
	originalReadFile := outgoingTraceReadFile
	t.Cleanup(func() {
		outgoingTraceReadlink = originalReadlink
		outgoingTraceReadFile = originalReadFile
	})

	outgoingTraceReadFile = func(string) ([]byte, error) {
		return []byte("monotonic 1 0\nboottime -1 0\n"), nil
	}
	outgoingTraceReadlink = func(path string) (string, error) {
		if path == "/proc/self/ns/time" {
			return "time:[1]", nil
		}
		return "time:[2]", nil
	}
	_, ok := outgoingTraceLoadTimeNamespaceOffsets()
	assert.False(t, ok, "time_for_children offsets are not current offsets")

	outgoingTraceReadlink = func(string) (string, error) {
		return "time:[1]", nil
	}
	offsets, ok := outgoingTraceLoadTimeNamespaceOffsets()
	require.True(t, ok)
	assert.Equal(t, int64(time.Second), offsets.monotonic)
	assert.Equal(t, -int64(time.Second), offsets.boottime)

	outgoingTraceReadlink = func(string) (string, error) {
		return "", unix.ENOENT
	}
	_, ok = outgoingTraceLoadTimeNamespaceOffsets()
	assert.False(t, ok, "zero is valid only when the offsets file is absent too")

	outgoingTraceReadFile = func(string) ([]byte, error) {
		return nil, unix.ENOENT
	}
	offsets, ok = outgoingTraceLoadTimeNamespaceOffsets()
	require.True(t, ok)
	assert.Zero(t, offsets)
}

func TestOutgoingTraceTimeNamespaceOffsetOverflowIsUnknown(t *testing.T) {
	_, ok := outgoingTraceParseTimeNamespaceOffsets([]byte(
		"monotonic 9223372037 0\nboottime 0 0\n",
	))
	assert.False(t, ok)

	_, ok = outgoingTraceAddSignedOffset(math.MaxUint64, 1)
	assert.False(t, ok)
	_, ok = outgoingTraceSubtractSignedOffset(0, 1)
	assert.False(t, ok)
	_, ok = outgoingTraceSubtractSignedOffset(math.MaxUint64, -1)
	assert.False(t, ok)

	originalClock := outgoingTraceClockGettime
	t.Cleanup(func() { outgoingTraceClockGettime = originalClock })
	outgoingTraceClockGettime = func(_ int32, ts *unix.Timespec) error {
		ts.Sec = int64(math.MaxUint64 / uint64(time.Second))
		ts.Nsec = int64(time.Second - 1)
		return nil
	}
	_, ok = outgoingTraceMonotonicNanoseconds(
		outgoingTraceTimeNamespaceOffsets{},
	)
	assert.False(t, ok)
}

func TestOutgoingTraceProcessStartAppliesSignedBoottimeOffset(t *testing.T) {
	original := outgoingTraceProcStartTimeForStatus
	t.Cleanup(func() { outgoingTraceProcStartTimeForStatus = original })

	const rawStart = uint64(50 * time.Millisecond)
	tests := []struct {
		name      string
		offset    int64
		procStart uint64
	}{
		{
			name:      "positive",
			offset:    int64(15 * time.Millisecond),
			procStart: uint64(60 * time.Millisecond),
		},
		{
			name:      "negative",
			offset:    -int64(15 * time.Millisecond),
			procStart: uint64(30 * time.Millisecond),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outgoingTraceProcStartTimeForStatus = func(uint32) (uint64, error) {
				return test.procStart, nil
			}
			assert.Equal(
				t,
				outgoingTraceProcessAlive,
				outgoingTraceProcessIncarnationStatus(
					outgoingTraceProcessKey{
						PID:       1,
						StartTime: rawStart,
					},
					outgoingTraceTimeNamespaceOffsets{
						boottime: test.offset,
					},
					true,
				),
			)
		})
	}

	outgoingTraceProcStartTimeForStatus = func(uint32) (uint64, error) {
		return rawStart, nil
	}
	assert.Equal(
		t,
		outgoingTraceProcessUnknown,
		outgoingTraceProcessIncarnationStatus(
			outgoingTraceProcessKey{
				PID:       1,
				StartTime: math.MaxUint64,
			},
			outgoingTraceTimeNamespaceOffsets{boottime: 1},
			true,
		),
	)
}

func TestOutgoingTraceHandoffReaperActivatesAfterMapsLoad(t *testing.T) {
	originalFactory := newOutgoingTraceHandoffReaperForContext
	t.Cleanup(func() { newOutgoingTraceHandoffReaperForContext = originalFactory })

	ready := false
	authority := newFakeOutgoingTraceMap()
	authority.entries[testOutgoingTraceKey()] = testOutgoingTraceValue(10_000)
	newOutgoingTraceHandoffReaperForContext = func(
		*EBPFEventContext,
	) (*outgoingTraceHandoffReaper, error) {
		if !ready {
			return nil, errOutgoingTraceHandoffMapsUnavailable
		}
		return &outgoingTraceHandoffReaper{
			authority:        authority,
			locators:         newFakeOutgoingTraceMap(),
			claims:           newFakeOutgoingTraceMap(),
			egressClaims:     newFakeOutgoingTraceMap(),
			stop:             make(chan struct{}),
			done:             make(chan struct{}),
			deadObservations: map[outgoingTraceProcessKey]outgoingTraceDeadObservation{},
			claimConflicts:   map[outgoingTraceHandoffKey]uint8{},
		}, nil
	}

	ctx := NewEBPFEventContext()
	releaseFirst := ctx.StartOutgoingTraceHandoffReaper()
	assert.Nil(t, ctx.handoffReaper)
	assert.Equal(t, 1, ctx.handoffReaperRun)

	ready = true
	ctx.NotifyOutgoingTraceHandoffMapsLoaded()
	require.NotNil(t, ctx.handoffReaper)

	releaseSecond := ctx.StartOutgoingTraceHandoffReaper()
	assert.Equal(t, 2, ctx.handoffReaperRun)
	releaseFirst()
	assert.NotNil(t, ctx.handoffReaper)

	ctx.RetainResources()
	releaseSecond()
	assert.Nil(t, ctx.handoffReaper)
	assert.Equal(t, 0, ctx.handoffReaperRun)
	assert.NotEmpty(t, authority.entries,
		"retained-resource shutdown stops without clearing authority")
}

func TestOutgoingTraceHandoffReaperRefreshesLateReferences(t *testing.T) {
	key := testOutgoingTraceKey()
	now := uint64(outgoingTraceOrphanTTL) + 1_000
	value := outgoingTraceHandoffValue{
		CreatedAt:    1_000,
		LastProgress: now - uint64(outgoingTraceOrphanTTL),
	}
	reaper := &outgoingTraceHandoffReaper{}
	reaper.trackReferenceCandidate(key, value, now)

	reaper.optionalMu.Lock()
	reaper.goRefs = fakeOutgoingTraceReferenceSource{
		refs: []outgoingTraceHandoffRef{{Egress: key.Egress, Token: key.Token}},
	}
	reaper.grpcRefs = fakeOutgoingTraceReferenceSource{
		refs: []outgoingTraceHandoffRef{{Egress: key.Egress, Token: key.Token}},
	}
	reaper.optionalMu.Unlock()

	reaper.advanceReferenceCycle(now)
	assert.NotContains(t, reaper.referenceCycle.active, key,
		"late Go/gRPC maps must protect their live exact authority")
}

func TestOutgoingTraceReferenceInsertionAfterScanResetsProof(t *testing.T) {
	now := uint64(outgoingTraceOrphanTTL) + 10_000
	key := testOutgoingTraceKey()
	value := outgoingTraceHandoffValue{
		CreatedAt:    1_000,
		LastProgress: now - uint64(outgoingTraceOrphanTTL),
	}
	authority := newFakeOutgoingTraceMap()
	claims := newFakeOutgoingTraceMap()
	authority.entries[key] = value
	reaper := testOutgoingTraceReaper(
		authority,
		newFakeOutgoingTraceMap(),
		claims,
		newFakeOutgoingTraceMap(),
		nil,
	)
	claims.onUpdate = func(any, any, ebpf.MapUpdateFlags) {
		refreshed := authority.entries[key].(outgoingTraceHandoffValue)
		refreshed.LastProgress = now
		authority.entries[key] = refreshed
		claims.onUpdate = nil
	}

	reaper.trackReferenceCandidate(key, value, now)
	reaper.advanceReferenceCycle(now)
	reaper.advanceReferenceCycle(now)

	assert.Contains(t, authority.entries, key,
		"a post-scan reference handshake must invalidate the old revision")
	assert.Empty(t, claims.entries)
	assert.NotContains(t, reaper.referenceCycle.active, key,
		"fresh progress is not orphan-expired")
}

func TestOutgoingTraceHardTTLRefreshNeedsTwoFreshCycles(t *testing.T) {
	now := uint64(outgoingTraceHardTTL) + 10_000
	key := testOutgoingTraceKey()
	value := outgoingTraceHandoffValue{
		CreatedAt:    now - uint64(outgoingTraceHardTTL),
		LastProgress: 1_000,
	}
	authority := newFakeOutgoingTraceMap()
	claims := newFakeOutgoingTraceMap()
	authority.entries[key] = value
	reaper := testOutgoingTraceReaper(
		authority,
		newFakeOutgoingTraceMap(),
		claims,
		newFakeOutgoingTraceMap(),
		nil,
	)
	claims.onUpdate = func(any, any, ebpf.MapUpdateFlags) {
		refreshed := authority.entries[key].(outgoingTraceHandoffValue)
		refreshed.LastProgress = now
		authority.entries[key] = refreshed
		claims.onUpdate = nil
	}

	reaper.trackReferenceCandidate(key, value, now)
	reaper.advanceReferenceCycle(now)
	reaper.advanceReferenceCycle(now)
	require.Contains(t, authority.entries, key)
	require.Equal(
		t,
		uint8(0),
		reaper.referenceCycle.active[key].misses,
		"hard TTL still requires an unchanged progress revision",
	)

	reaper.advanceReferenceCycle(now)
	assert.Contains(t, authority.entries, key,
		"one fresh absence cycle is insufficient")
	reaper.advanceReferenceCycle(now)
	assert.NotContains(t, authority.entries, key)
}

func TestOutgoingTraceHardTTLKeepsContinuousReference(t *testing.T) {
	now := uint64(outgoingTraceHardTTL) + 10_000
	key := testOutgoingTraceKey()
	value := outgoingTraceHandoffValue{
		CreatedAt:    now - uint64(outgoingTraceHardTTL),
		LastProgress: 1_000,
	}
	authority := newFakeOutgoingTraceMap()
	authority.entries[key] = value
	reaper := testOutgoingTraceReaper(
		authority,
		newFakeOutgoingTraceMap(),
		newFakeOutgoingTraceMap(),
		newFakeOutgoingTraceMap(),
		nil,
	)
	reaper.goRefs = fakeOutgoingTraceReferenceSource{
		refs: []outgoingTraceHandoffRef{{
			Egress: key.Egress,
			Token:  key.Token,
		}},
	}

	for range 4 {
		reaper.trackReferenceCandidate(key, value, now)
		reaper.advanceReferenceCycle(now)
	}
	assert.Contains(t, authority.entries, key,
		"hard TTL cannot retire a continuously referenced handoff")
}

func TestOutgoingTraceOptionalGenerationChangesInFlight(t *testing.T) {
	now := uint64(outgoingTraceOrphanTTL) + 10_000
	key := testOutgoingTraceKey()
	value := outgoingTraceHandoffValue{
		CreatedAt:    1_000,
		LastProgress: now - uint64(outgoingTraceOrphanTTL),
	}
	authority := newFakeOutgoingTraceMap()
	egressClaims := newFakeOutgoingTraceMap()
	authority.entries[key] = value
	reaper := testOutgoingTraceReaper(
		authority,
		newFakeOutgoingTraceMap(),
		newFakeOutgoingTraceMap(),
		egressClaims,
		nil,
	)
	egressClaims.onUpdate = func(any, any, ebpf.MapUpdateFlags) {
		reaper.optionalMu.Lock()
		reaper.optionalID++
		reaper.optionalMu.Unlock()
		egressClaims.onUpdate = nil
	}

	reaper.trackReferenceCandidate(key, value, now)
	reaper.advanceReferenceCycle(now)
	reaper.advanceReferenceCycle(now)
	require.Contains(t, authority.entries, key,
		"replacement between scan and retirement invalidates the proof")
	require.Equal(t, uint8(0), reaper.referenceCycle.active[key].misses)

	reaper.advanceReferenceCycle(now)
	assert.Contains(t, authority.entries, key,
		"replacement requires a first fresh cycle")
	reaper.advanceReferenceCycle(now)
	assert.NotContains(t, authority.entries, key,
		"retirement is allowed after two fresh cycles")
}

func TestOutgoingTraceMapsLoadedAlwaysChangesGeneration(t *testing.T) {
	ctx := NewEBPFEventContext()
	reaper := &outgoingTraceHandoffReaper{}
	ctx.handoffReaper = reaper

	ctx.NotifyOutgoingTraceHandoffMapsLoaded()
	first := reaper.optionalID
	ctx.NotifyOutgoingTraceHandoffMapsLoaded()

	assert.Equal(t, uint64(1), first)
	assert.Equal(t, uint64(2), reaper.optionalID,
		"same-object resets still invalidate in-flight scans")
}

func TestOutgoingTraceHandoffReaperBoundsBookkeeping(t *testing.T) {
	reaper := &outgoingTraceHandoffReaper{
		deadObservations:     map[outgoingTraceProcessKey]outgoingTraceDeadObservation{},
		deadObservationLimit: outgoingTraceBookkeepingLimit,
		claimConflicts:       map[outgoingTraceHandoffKey]uint8{},
	}
	firstProcess := outgoingTraceProcessKey{PID: 1, StartTime: 1}
	firstClaim := testOutgoingTraceKey()

	for i := 0; i < outgoingTraceBookkeepingLimit+17; i++ {
		reaper.rememberDeadProcessObservation(outgoingTraceProcessKey{
			PID:       uint32(i + 1),
			StartTime: uint64(i + 1),
		}, uint64(i+1))
		key := testOutgoingTraceKey()
		key.Token.Sequence = uint64(i + 1)
		reaper.recordClaimConflict(key)
	}

	assert.LessOrEqual(t, len(reaper.deadObservations), outgoingTraceBookkeepingLimit)
	assert.LessOrEqual(t, len(reaper.claimConflicts), outgoingTraceBookkeepingLimit)
	assert.Contains(t, reaper.deadObservations, firstProcess)
	assert.Contains(t, reaper.claimConflicts, firstClaim)
}

func TestOutgoingTraceReferenceCycleProgressesPastBudget(t *testing.T) {
	now := uint64(outgoingTraceOrphanTTL) + 10_000
	value := outgoingTraceHandoffValue{
		CreatedAt:    1_000,
		LastProgress: now - uint64(outgoingTraceOrphanTTL),
	}
	stale := testOutgoingTraceKey()
	stale.Token.Sequence = 1
	live := testOutgoingTraceKey()
	live.Token.Sequence = 2

	refs := make(
		[]outgoingTraceHandoffRef,
		outgoingTraceReferenceScanBudget*2+1,
	)
	for i := range refs {
		key := testOutgoingTraceKey()
		key.Token.Sequence = uint64(i + 100)
		refs[i] = outgoingTraceHandoffRef{
			Egress: key.Egress,
			Token:  key.Token,
		}
	}
	refs[len(refs)-1] = outgoingTraceHandoffRef{
		Egress: live.Egress,
		Token:  live.Token,
	}

	authority := newFakeOutgoingTraceMap()
	authority.entries[stale] = value
	authority.entries[live] = value
	reaper := testOutgoingTraceReaper(
		authority,
		newFakeOutgoingTraceMap(),
		newFakeOutgoingTraceMap(),
		newFakeOutgoingTraceMap(),
		nil,
	)
	reaper.goRefs = fakeOutgoingTraceReferenceSource{refs: refs}
	reaper.trackReferenceCandidate(stale, value, now)
	reaper.trackReferenceCandidate(live, value, now)

	for range 3 {
		reaper.advanceReferenceCycle(now)
	}
	assert.Contains(t, authority.entries, stale,
		"one complete miss must not authorize orphan retirement")
	assert.Contains(t, authority.entries, live,
		"a live reference beyond the first budget must be observed")

	for range 3 {
		reaper.advanceReferenceCycle(now)
	}
	assert.NotContains(t, authority.entries, stale,
		"two complete bounded cycles must prove an orphan")
	assert.Contains(t, authority.entries, live)
	assert.LessOrEqual(
		t,
		len(reaper.referenceCycle.active),
		outgoingTraceReferenceScanBudget,
	)
	assert.LessOrEqual(
		t,
		len(reaper.referenceCycle.pending),
		outgoingTraceReferenceScanBudget,
	)
}

func TestOutgoingTraceReferenceRestartDoesNotAdvanceMisses(t *testing.T) {
	now := uint64(outgoingTraceOrphanTTL) + 10_000
	key := testOutgoingTraceKey()
	value := outgoingTraceHandoffValue{
		CreatedAt:    1_000,
		LastProgress: now - uint64(outgoingTraceOrphanTTL),
	}
	authority := newFakeOutgoingTraceMap()
	authority.entries[key] = value
	reaper := testOutgoingTraceReaper(
		authority,
		newFakeOutgoingTraceMap(),
		newFakeOutgoingTraceMap(),
		newFakeOutgoingTraceMap(),
		nil,
	)
	reaper.goRefs = &restartingOutgoingTraceReferenceSource{
		total:       outgoingTraceReferenceScanBudget + 1,
		restartOnce: true,
	}
	reaper.trackReferenceCandidate(key, value, now)

	reaper.advanceReferenceCycle(now)
	reaper.advanceReferenceCycle(now)
	assert.Contains(t, authority.entries, key)
	require.Equal(
		t,
		uint8(0),
		reaper.referenceCycle.pending[key].misses,
		"a repeated first key aborts and clears partial absence",
	)

	reaper.advanceReferenceCycle(now)
	reaper.advanceReferenceCycle(now)
	assert.Contains(t, authority.entries, key,
		"one stable 513-key cycle is insufficient")
	reaper.advanceReferenceCycle(now)
	reaper.advanceReferenceCycle(now)
	assert.NotContains(t, authority.entries, key,
		"the reaper recovers after churn and two stable cycles")
}

func TestOutgoingTraceReferenceCycleUsesScaledMapCapacity(t *testing.T) {
	const referenceEntries = 80_000
	now := uint64(outgoingTraceOrphanTTL) + 10_000
	key := testOutgoingTraceKey()
	value := outgoingTraceHandoffValue{
		CreatedAt:    1_000,
		LastProgress: now - uint64(outgoingTraceOrphanTTL),
	}
	authority := newFakeOutgoingTraceMap()
	authority.entries[key] = value
	reaper := testOutgoingTraceReaper(
		authority,
		newFakeOutgoingTraceMap(),
		newFakeOutgoingTraceMap(),
		newFakeOutgoingTraceMap(),
		nil,
	)
	reaper.grpcRefs = &restartingOutgoingTraceReferenceSource{
		total: referenceEntries,
	}
	reaper.trackReferenceCandidate(key, value, now)

	callsPerCycle := (referenceEntries +
		outgoingTraceReferenceScanBudget - 1) /
		outgoingTraceReferenceScanBudget
	for range callsPerCycle {
		reaper.advanceReferenceCycle(now)
	}
	require.Contains(t, authority.entries, key)
	require.Equal(t, uint8(1), reaper.referenceCycle.active[key].misses,
		"one complete 80k-entry absence cycle is insufficient")

	for range callsPerCycle {
		reaper.advanceReferenceCycle(now)
	}
	assert.NotContains(t, authority.entries, key,
		"two complete scans must reach beyond the former 65,536-entry limit")
}

func TestOutgoingTraceAuthorityRestartAbortsBoundedScan(t *testing.T) {
	originalClock := outgoingTraceClockGettime
	t.Cleanup(func() { outgoingTraceClockGettime = originalClock })

	now := uint64(outgoingTraceOrphanTTL) + 10_000
	outgoingTraceClockGettime = func(_ int32, ts *unix.Timespec) error {
		ts.Sec = int64(now / uint64(time.Second))
		ts.Nsec = int64(now % uint64(time.Second))
		return nil
	}

	const total = outgoingTraceScanBudget + 1
	base := newFakeOutgoingTraceMap()
	keys := make([]outgoingTraceHandoffKey, total)
	for i := range keys {
		key := testOutgoingTraceKey()
		key.Token.Sequence = uint64(i + 1)
		keys[i] = key
		base.entries[key] = outgoingTraceHandoffValue{
			CreatedAt:    now,
			LastProgress: now,
		}
	}
	last := keys[len(keys)-1]
	base.entries[last] = testOutgoingTraceValue(now)
	authority := &restartingOutgoingTraceAuthorityMap{
		fakeOutgoingTraceMap: base,
		keys:                 keys,
		restartOnce:          true,
	}
	reaper := testOutgoingTraceReaper(
		authority,
		newFakeOutgoingTraceMap(),
		newFakeOutgoingTraceMap(),
		newFakeOutgoingTraceMap(),
		nil,
	)

	reaper.scan()
	require.NotNil(t, reaper.nextKey)
	assert.Equal(t, last, *reaper.nextKey)
	reaper.scan()
	assert.Contains(t, base.entries, last,
		"a cursor deletion restart must not process an unproven boundary")
	assert.Nil(t, reaper.nextKey)

	reaper.scan()
	reaper.scan()
	assert.NotContains(t, base.entries, last,
		"a later stable bounded traversal recovers")
}

func TestOutgoingTraceAuthorityScanUsesScaledMapCapacity(t *testing.T) {
	originalClock := outgoingTraceClockGettime
	t.Cleanup(func() { outgoingTraceClockGettime = originalClock })

	const authorityEntries = 120_000
	now := uint64(outgoingTraceOrphanTTL) + 10_000
	outgoingTraceClockGettime = func(_ int32, ts *unix.Timespec) error {
		ts.Sec = int64(now / uint64(time.Second))
		ts.Nsec = int64(now % uint64(time.Second))
		return nil
	}

	authority := &scaledOutgoingTraceAuthorityMap{
		count: authorityEntries,
		activeValue: outgoingTraceHandoffValue{
			CreatedAt:    now,
			LastProgress: now,
		},
		tailValue: testOutgoingTraceValue(now),
	}
	reaper := testOutgoingTraceReaper(
		authority,
		newFakeOutgoingTraceMap(),
		newFakeOutgoingTraceMap(),
		newFakeOutgoingTraceMap(),
		nil,
	)

	scans := (authorityEntries + outgoingTraceScanBudget - 1) /
		outgoingTraceScanBudget
	for range scans - 1 {
		reaper.scan()
	}
	require.False(t, authority.tailDeleted)
	reaper.scan()

	assert.True(t, authority.tailDeleted,
		"the bounded cursor must reach a tail beyond 65,536 entries")
	assert.Equal(t, uint64(1), reaper.counters.retired.Load())
}

func TestOutgoingTraceTraversalCapacityHasRepositoryBound(t *testing.T) {
	assert.Equal(t, 80_000, boundedOutgoingTraceCapacity(80_000))
	assert.Equal(t, 120_000, boundedOutgoingTraceCapacity(120_000))
	assert.Equal(
		t,
		outgoingTraceMaxTraversalEntries,
		boundedOutgoingTraceCapacity(outgoingTraceMaxTraversalEntries+1),
	)
}

func TestOutgoingTraceDeadObservationsMatureAcrossScaledTraversal(t *testing.T) {
	originalClock := outgoingTraceClockGettime
	originalProcStart := outgoingTraceProcStartTimeForStatus
	t.Cleanup(func() {
		outgoingTraceClockGettime = originalClock
		outgoingTraceProcStartTimeForStatus = originalProcStart
	})

	const authorityEntries = 120_000
	currentNow := uint64(10 * time.Second)
	outgoingTraceClockGettime = func(_ int32, ts *unix.Timespec) error {
		ts.Sec = int64(currentNow / uint64(time.Second))
		ts.Nsec = int64(currentNow % uint64(time.Second))
		return nil
	}
	outgoingTraceProcStartTimeForStatus = func(uint32) (uint64, error) {
		return 0, os.ErrNotExist
	}

	authority := newDeadProcessOutgoingTraceAuthorityMap(
		authorityEntries,
		true,
		outgoingTraceHandoffValue{
			CreatedAt:    currentNow,
			LastProgress: currentNow,
		},
	)
	reaper := testOutgoingTraceReaper(
		authority,
		newFakeOutgoingTraceMap(),
		newFakeOutgoingTraceMap(),
		newFakeOutgoingTraceMap(),
		nil,
	)
	scansPerCycle := (authorityEntries + outgoingTraceScanBudget - 1) /
		outgoingTraceScanBudget

	for range scansPerCycle {
		reaper.scan()
	}
	require.Zero(t, authority.deletedCount)
	require.Len(t, reaper.deadObservations, authorityEntries)
	require.Equal(t, authorityEntries, reaper.deadObservationOrder.Len())

	currentNow += uint64(outgoingTraceDeadObservationDelay)
	for range scansPerCycle {
		reaper.scan()
	}
	assert.Equal(t, authorityEntries, authority.deletedCount,
		"one observation per authority slot must survive until the next cycle")
	assert.Len(t, reaper.deadObservations, authorityEntries,
		"retirement retains mature proof for the dead incarnation")
	assert.Equal(t, authorityEntries, reaper.deadObservationOrder.Len())
}

func TestOutgoingTraceDeadProcessProofRetiresAllHandoffsAtScanRate(t *testing.T) {
	originalClock := outgoingTraceClockGettime
	originalProcStart := outgoingTraceProcStartTimeForStatus
	t.Cleanup(func() {
		outgoingTraceClockGettime = originalClock
		outgoingTraceProcStartTimeForStatus = originalProcStart
	})

	const authorityEntries = 4 * outgoingTraceScanBudget
	currentNow := uint64(10 * time.Second)
	outgoingTraceClockGettime = func(_ int32, ts *unix.Timespec) error {
		ts.Sec = int64(currentNow / uint64(time.Second))
		ts.Nsec = int64(currentNow % uint64(time.Second))
		return nil
	}
	outgoingTraceProcStartTimeForStatus = func(uint32) (uint64, error) {
		return 0, os.ErrNotExist
	}

	authority := newDeadProcessOutgoingTraceAuthorityMap(
		authorityEntries,
		false,
		outgoingTraceHandoffValue{
			CreatedAt:    currentNow,
			LastProgress: currentNow,
		},
	)
	reaper := testOutgoingTraceReaper(
		authority,
		newFakeOutgoingTraceMap(),
		newFakeOutgoingTraceMap(),
		newFakeOutgoingTraceMap(),
		nil,
	)
	scansPerCycle := authorityEntries / outgoingTraceScanBudget

	for range scansPerCycle {
		reaper.scan()
	}
	require.Zero(t, authority.deletedCount)
	require.Len(t, reaper.deadObservations, 1)

	currentNow += uint64(outgoingTraceDeadObservationDelay)
	for range scansPerCycle {
		reaper.scan()
	}
	assert.Equal(t, authorityEntries, authority.deletedCount,
		"mature shared proof must not be discarded after each retirement")
	assert.Len(t, reaper.deadObservations, 1)
	assert.Equal(t, 1, reaper.deadObservationOrder.Len())
}

func TestOutgoingTraceDeadObservationAdmissionChecksOnlyOldest(t *testing.T) {
	reaper := &outgoingTraceHandoffReaper{
		deadObservations:     map[outgoingTraceProcessKey]outgoingTraceDeadObservation{},
		deadObservationLimit: 2,
	}
	first := outgoingTraceProcessKey{PID: 1, StartTime: 1}
	second := outgoingTraceProcessKey{PID: 2, StartTime: 2}
	next := outgoingTraceProcessKey{PID: 3, StartTime: 3}
	base := uint64(10 * time.Second)
	assert.False(t, reaper.rememberDeadProcessObservation(first, base))
	assert.False(t, reaper.rememberDeadProcessObservation(second, base+1))

	secondObservation := reaper.deadObservations[second]
	secondObservation.firstSeen = 0
	reaper.deadObservations[second] = secondObservation
	beforeMaturity := base + uint64(outgoingTraceDeadObservationDelay) - 1
	assert.False(t, reaper.rememberDeadProcessObservation(next, beforeMaturity))
	assert.NotContains(t, reaper.deadObservations, next,
		"admission must not scan the cache for a later mature victim")
	assert.Contains(t, reaper.deadObservations, first)
	assert.Contains(t, reaper.deadObservations, second)

	assert.False(t, reaper.rememberDeadProcessObservation(
		next,
		base+uint64(outgoingTraceDeadObservationDelay),
	))
	assert.NotContains(t, reaper.deadObservations, first)
	assert.Contains(t, reaper.deadObservations, next)
}

func TestOutgoingTraceAliveEvidenceInvalidatesDeadObservation(t *testing.T) {
	originalProcStart := outgoingTraceProcStartTimeForStatus
	t.Cleanup(func() {
		outgoingTraceProcStartTimeForStatus = originalProcStart
	})

	process := outgoingTraceProcessKey{
		PID:       42,
		StartTime: uint64(20 * time.Millisecond),
	}
	outgoingTraceProcStartTimeForStatus = func(uint32) (uint64, error) {
		return process.StartTime, nil
	}
	reaper := &outgoingTraceHandoffReaper{
		deadObservations:     map[outgoingTraceProcessKey]outgoingTraceDeadObservation{},
		deadObservationLimit: 2,
		timeOffsetsValid:     true,
	}
	assert.False(t, reaper.rememberDeadProcessObservation(process, 1))
	require.Contains(t, reaper.deadObservations, process)
	require.Equal(t, 1, reaper.deadObservationOrder.Len())

	key := testOutgoingTraceKey()
	key.Egress.PID = process.PID
	key.Token.ProcessStartTime = process.StartTime
	assert.False(t, reaper.deadProcessConfirmed(key, uint64(time.Second)))
	assert.NotContains(t, reaper.deadObservations, process)
	assert.Zero(t, reaper.deadObservationOrder.Len())
}

func TestOutgoingTraceDeadObservationBatchMaturesAtCapacity(t *testing.T) {
	reaper := &outgoingTraceHandoffReaper{
		deadObservations:     map[outgoingTraceProcessKey]outgoingTraceDeadObservation{},
		deadObservationLimit: outgoingTraceBookkeepingLimit,
	}
	const firstSeen = uint64(1_000)

	for i := 0; i < outgoingTraceBookkeepingLimit+outgoingTraceScanBudget; i++ {
		assert.False(t, reaper.rememberDeadProcessObservation(
			outgoingTraceProcessKey{
				PID:       uint32(i + 1),
				StartTime: uint64(i + 1),
			},
			firstSeen,
		))
	}
	require.Len(t, reaper.deadObservations, outgoingTraceBookkeepingLimit)

	maturedAt := firstSeen + uint64(outgoingTraceDeadObservationDelay)
	for i := 0; i < outgoingTraceScanBudget; i++ {
		assert.True(t, reaper.rememberDeadProcessObservation(
			outgoingTraceProcessKey{
				PID:       uint32(i + 1),
				StartTime: uint64(i + 1),
			},
			maturedAt,
		))
	}
	assert.NotContains(t, reaper.deadObservations, outgoingTraceProcessKey{
		PID:       uint32(outgoingTraceBookkeepingLimit + 1),
		StartTime: uint64(outgoingTraceBookkeepingLimit + 1),
	})
}

func TestOutgoingTraceDeadObservationEvictsMatureDisappearedAuthority(t *testing.T) {
	reaper := &outgoingTraceHandoffReaper{
		deadObservations:     map[outgoingTraceProcessKey]outgoingTraceDeadObservation{},
		deadObservationLimit: outgoingTraceBookkeepingLimit,
	}
	for i := 0; i < outgoingTraceBookkeepingLimit; i++ {
		assert.False(t, reaper.rememberDeadProcessObservation(
			outgoingTraceProcessKey{
				PID:       uint32(i + 1),
				StartTime: uint64(i + 1),
			},
			uint64(i+1),
		))
	}

	now := uint64(outgoingTraceBookkeepingLimit) +
		uint64(outgoingTraceDeadObservationDelay) + 1
	newProcess := outgoingTraceProcessKey{
		PID:       outgoingTraceBookkeepingLimit + 1,
		StartTime: outgoingTraceBookkeepingLimit + 1,
	}
	assert.False(t, reaper.rememberDeadProcessObservation(newProcess, now))
	assert.Len(t, reaper.deadObservations, outgoingTraceBookkeepingLimit)
	assert.NotContains(t, reaper.deadObservations, outgoingTraceProcessKey{
		PID:       1,
		StartTime: 1,
	}, "the oldest mature observation can belong to vanished authority")
	assert.Contains(t, reaper.deadObservations, newProcess)
}

func TestOutgoingTraceEgressClaimConflictsAccumulate(t *testing.T) {
	const now = uint64(10_000)
	key := testOutgoingTraceKey()
	value := testOutgoingTraceValue(now)
	authority := newFakeOutgoingTraceMap()
	claims := newFakeOutgoingTraceMap()
	egressClaims := newFakeOutgoingTraceMap()
	authority.entries[key] = value
	egressClaims.entries[key.Egress] = uint8(1)
	reaper := testOutgoingTraceReaper(
		authority,
		newFakeOutgoingTraceMap(),
		claims,
		egressClaims,
		nil,
	)

	for range 3 {
		reaper.maybeRetire(key, value, now)
	}

	assert.Contains(t, authority.entries, key)
	assert.Empty(t, claims.entries)
	assert.Equal(t, uint8(3), reaper.claimConflicts[key])
	assert.Equal(t, uint64(3), reaper.counters.claimConflicts.Load())
	assert.Equal(t, uint64(1), reaper.counters.stuckClaimConflicts.Load())
}
