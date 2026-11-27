// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
import (
	"cmp"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
)

const (
	testBatchLen   = 2
	testMaxEntries = 50_000
)

func TestLookupAndDelete(t *testing.T) {
	expectedAggregation := map[NetFlowId]*NetFlowMetrics{
		{IfIndex: 1}: {Packets: 3, StartMonoTimeNs: 101, EndMonoTimeNs: 103},
		{IfIndex: 2}: {Packets: 5, StartMonoTimeNs: 10, EndMonoTimeNs: 130},
		{IfIndex: 3}: {Packets: 35, StartMonoTimeNs: 101, EndMonoTimeNs: 125},
		{IfIndex: 4}: {Packets: 22, StartMonoTimeNs: 101, EndMonoTimeNs: 110},
	}
	t.Run("legacy", func(t *testing.T) {
		fmd := legacyReader()
		flows, err := fmd.lookupAndDeleteMap()
		require.NoError(t, err)
		assert.Equal(t, expectedAggregation, flows)
		assertLegacyMapRead(t, fmd.flowMap.(*fakeLegacyMap))
	})
	t.Run("batch", func(t *testing.T) {
		fmd := batchReader()
		flows, err := fmd.lookupAndDeleteMap()
		require.NoError(t, err)
		assert.Equal(t, expectedAggregation, flows)
	})
	t.Run("auto", func(t *testing.T) {
		fmd := flowMapReaderChooser{legacy: legacyReader(), batch: batchReader()}
		flows, err := fmd.lookupAndDeleteMap()
		require.NoError(t, err)
		assert.Equal(t, expectedAggregation, flows)
	})
}

func TestLookupAndDelete_FlowReadTwice(t *testing.T) {
	// the programs create a flow again after the reader deleted it, and the reader finds it again
	input := func() fakeBPFMap {
		return []entry{
			{k: NetFlowId{IfIndex: 1}, v: NetFlowMetrics{Packets: 3, Bytes: 30, StartMonoTimeNs: 101, EndMonoTimeNs: 103}},
			{k: NetFlowId{IfIndex: 2}, v: NetFlowMetrics{Packets: 1, StartMonoTimeNs: 110, EndMonoTimeNs: 110}},
			{k: NetFlowId{IfIndex: 1}, v: NetFlowMetrics{Packets: 4, Bytes: 40, StartMonoTimeNs: 120, EndMonoTimeNs: 125}},
		}
	}
	expected := map[NetFlowId]*NetFlowMetrics{
		{IfIndex: 1}: {Packets: 7, Bytes: 70, StartMonoTimeNs: 101, EndMonoTimeNs: 125},
		{IfIndex: 2}: {Packets: 1, StartMonoTimeNs: 110, EndMonoTimeNs: 110},
	}
	t.Run("legacy", func(t *testing.T) {
		in := input()
		flowMap := newFakeLegacyMap(in[:2])
		flowMap.recreated = map[NetFlowId]NetFlowMetrics{in[2].k: in[2].v}
		reader := &flowMapLegacyReader{log: slog.Default(), flowMap: flowMap}
		flows, err := reader.lookupAndDeleteMap()
		require.NoError(t, err)
		assert.Equal(t, expected, flows)
		assertLegacyMapRead(t, flowMap)
	})
	t.Run("batch", func(t *testing.T) {
		flowMap := input()
		reader := &flowMapBatchReader{
			flowMap:      &flowMap,
			cachedKeys:   make([]NetFlowId, testBatchLen),
			cachedValues: make([]NetFlowMetrics, testBatchLen),
		}
		flows, err := reader.lookupAndDeleteMap()
		require.NoError(t, err)
		assert.Equal(t, expected, flows)
	})
}

func TestBatchReaderForwardsOptions(t *testing.T) {
	opts := &ebpf.BatchOptions{ElemFlags: uint64(ebpf.LookupLock)}
	flowMap := &ebpfMapMock{}
	flowMap.On("BatchLookupAndDelete", mock.Anything, mock.Anything, mock.Anything, opts).
		Return(0, ebpf.ErrKeyNotExist)

	reader := &flowMapBatchReader{flowMap: flowMap, opts: opts}
	_, err := reader.lookupAndDeleteMap()
	require.NoError(t, err)

	flowMap.AssertExpectations(t)
}

func TestLegacyReaderForwardsLookupFlags(t *testing.T) {
	for _, flags := range []ebpf.MapLookupFlags{0, ebpf.LookupLock} {
		flowMap := newFakeLegacyMap(inputFlows())
		reader := &flowMapLegacyReader{log: slog.Default(), flowMap: flowMap, lookupFlags: flags}
		_, err := reader.lookupAndDeleteMap()
		require.NoError(t, err)

		require.Len(t, flowMap.lookupFlags, len(inputFlows()))
		for _, got := range flowMap.lookupFlags {
			assert.Equal(t, flags, got)
		}
	}
}

func TestChooseMapReader_LockedValues(t *testing.T) {
	for _, locked := range []bool{false, true} {
		chooser := chooseMapReader(config.MapReaderAuto, nil, 0, locked).(*flowMapReaderChooser)
		if locked {
			assert.Equal(t, ebpf.LookupLock, chooser.legacy.lookupFlags)
			assert.Equal(t, uint64(ebpf.LookupLock), chooser.batch.opts.ElemFlags)
		} else {
			assert.Zero(t, chooser.legacy.lookupFlags)
			assert.Nil(t, chooser.batch.opts)
		}
	}
}

func TestLegacyReader_LookupError(t *testing.T) {
	lookupErr := errors.New("lookup failed")
	flowMap := newFakeLegacyMap(inputFlows())
	flowMap.lookupErrs = map[NetFlowId]error{{IfIndex: 3}: lookupErr}
	reader := &flowMapLegacyReader{log: slog.Default(), flowMap: flowMap}

	flows, err := reader.lookupAndDeleteMap()
	require.ErrorIs(t, err, lookupErr)

	assert.Equal(t, []NetFlowId{{IfIndex: 1}, {IfIndex: 2}}, flowIDs(flows))
	assert.Equal(t, []NetFlowId{{IfIndex: 3}, {IfIndex: 4}}, flowMap.keys)
}

func TestLegacyReader_KeyGone(t *testing.T) {
	flowMap := newFakeLegacyMap(inputFlows())
	flowMap.lookupErrs = map[NetFlowId]error{{IfIndex: 2}: ebpf.ErrKeyNotExist}
	reader := &flowMapLegacyReader{log: slog.Default(), flowMap: flowMap}

	flows, err := reader.lookupAndDeleteMap()
	require.NoError(t, err)

	assert.Equal(t, []NetFlowId{{IfIndex: 1}, {IfIndex: 3}, {IfIndex: 4}}, flowIDs(flows))
	assert.Equal(t, []NetFlowId{{IfIndex: 2}}, flowMap.keys)
}

func TestLegacyReader_StopsAtCapacity(t *testing.T) {
	flowMap := newFakeLegacyMap(inputFlows())
	flowMap.maxEntries = 2
	reader := &flowMapLegacyReader{log: slog.Default(), flowMap: flowMap}

	flows, err := reader.lookupAndDeleteMap()
	require.NoError(t, err)

	assert.Equal(t, []NetFlowId{{IfIndex: 1}, {IfIndex: 2}}, flowIDs(flows))
	assert.Equal(t, []NetFlowId{{IfIndex: 3}, {IfIndex: 4}}, flowMap.keys)
}

func TestLegacyReader_ScaledMap(t *testing.T) {
	// the map can be larger than the configured cache size: global_scale_factor resizes it
	flowMap := newFakeLegacyMap(inputFlows())
	reader := &flowMapLegacyReader{log: slog.Default(), flowMap: flowMap, cacheMaxSize: 2}

	flows, err := reader.lookupAndDeleteMap()
	require.NoError(t, err)

	assert.Len(t, flows, len(inputFlows()))
	assertLegacyMapRead(t, flowMap)
}

func TestAutoChoose_BatchSupported(t *testing.T) {
	// using a mock to verify that once if the BatchLookupAndDelete function works,
	// the legacy iteration functions are not called
	legacyMap := &ebpfMapMock{}
	legacyMap.On("BatchLookupAndDelete", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(0, ebpf.ErrKeyNotExist)

	auto := flowMapReaderChooser{
		batch:  &flowMapBatchReader{flowMap: legacyMap},
		legacy: &flowMapLegacyReader{log: slog.Default(), flowMap: legacyMap},
	}
	_, err := auto.lookupAndDeleteMap()
	require.NoError(t, err)

	legacyMap.AssertCalled(t, "BatchLookupAndDelete", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	legacyMap.AssertNotCalled(t, "NextKey", mock.Anything, mock.Anything)
}

func TestAutoChoose_BatchUnsupported(t *testing.T) {
	// using a mock to verify that once if the BatchLookupAndDelete is not supported,
	// the flowMapReaderChooser switches to the legacy map reader

	legacyMap := &ebpfMapMock{}
	legacyMap.On("BatchLookupAndDelete", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(0, ebpf.ErrNotSupported)
	legacyMap.On("NextKey", nil, mock.Anything).Return(nil)
	legacyMap.On("NextKey", mock.Anything, mock.Anything).Return(ebpf.ErrKeyNotExist)
	legacyMap.On("LookupWithFlags", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	legacyMap.On("Delete", mock.Anything).Return(nil)
	legacyMap.On("MaxEntries").Return(uint32(testMaxEntries))

	auto := flowMapReaderChooser{
		batch:  &flowMapBatchReader{flowMap: legacyMap},
		legacy: &flowMapLegacyReader{log: slog.Default(), flowMap: legacyMap},
	}
	_, err := auto.lookupAndDeleteMap()
	require.NoError(t, err)

	legacyMap.AssertCalled(t, "BatchLookupAndDelete", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	legacyMap.AssertCalled(t, "LookupWithFlags", mock.Anything, mock.Anything, mock.Anything)
	legacyMap.AssertCalled(t, "Delete", mock.Anything)

	// Verify that once the legacy map is selected, we don't try the batch lookup anymore
	legacyMap.Calls = nil
	_, err = auto.lookupAndDeleteMap()
	require.NoError(t, err)
	legacyMap.AssertNotCalled(t, "BatchLookupAndDelete")
	legacyMap.AssertCalled(t, "LookupWithFlags", mock.Anything, mock.Anything, mock.Anything)
}

func inputFlows() fakeBPFMap {
	return []entry{
		{k: NetFlowId{IfIndex: 1}, v: NetFlowMetrics{Packets: 3, StartMonoTimeNs: 101, EndMonoTimeNs: 103}},
		{k: NetFlowId{IfIndex: 2}, v: NetFlowMetrics{Packets: 5, StartMonoTimeNs: 10, EndMonoTimeNs: 130}},
		{k: NetFlowId{IfIndex: 3}, v: NetFlowMetrics{Packets: 35, StartMonoTimeNs: 101, EndMonoTimeNs: 125}},
		{k: NetFlowId{IfIndex: 4}, v: NetFlowMetrics{Packets: 22, StartMonoTimeNs: 101, EndMonoTimeNs: 110}},
	}
}

func legacyReader() *flowMapLegacyReader {
	return &flowMapLegacyReader{
		log:          slog.Default(),
		cacheMaxSize: 50_000,
		flowMap:      newFakeLegacyMap(inputFlows()),
	}
}

func batchReader() *flowMapBatchReader {
	flows := inputFlows()
	return &flowMapBatchReader{
		cacheMaxSize: 50_000,
		flowMap:      &flows,
		cachedKeys:   make([]NetFlowId, testBatchLen),
		cachedValues: make([]NetFlowMetrics, testBatchLen),
	}
}

type fakeBPFMap []entry

type entry struct {
	k NetFlowId
	v NetFlowMetrics
}

// fakeLegacyMap mimics the kernel: NextKey restarts from the first key when given a deleted key.
// Deleting a key in recreated inserts it again at the end, as the programs do with a busy flow.
type fakeLegacyMap struct {
	keys        []NetFlowId
	values      map[NetFlowId]NetFlowMetrics
	recreated   map[NetFlowId]NetFlowMetrics
	lookupErrs  map[NetFlowId]error
	maxEntries  uint32
	restarts    int
	lookupFlags []ebpf.MapLookupFlags
}

func newFakeLegacyMap(entries []entry) *fakeLegacyMap {
	f := &fakeLegacyMap{values: map[NetFlowId]NetFlowMetrics{}, maxEntries: testMaxEntries}
	for _, e := range entries {
		f.keys = append(f.keys, e.k)
		f.values[e.k] = e.v
	}
	return f
}

func (f *fakeLegacyMap) NextKey(key, nextKeyOut any) error {
	next := 0
	if key != nil {
		i := slices.Index(f.keys, *key.(*NetFlowId))
		if i < 0 {
			f.restarts++
		}
		next = i + 1
	}
	if next >= len(f.keys) {
		return ebpf.ErrKeyNotExist
	}
	*nextKeyOut.(*NetFlowId) = f.keys[next]
	return nil
}

func (f *fakeLegacyMap) LookupWithFlags(key, valueOut any, flags ebpf.MapLookupFlags) error {
	id := *key.(*NetFlowId)
	f.lookupFlags = append(f.lookupFlags, flags)
	if err := f.lookupErrs[id]; err != nil {
		return err
	}
	value, ok := f.values[id]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	*valueOut.(*NetFlowMetrics) = value
	return nil
}

func (f *fakeLegacyMap) Delete(key any) error {
	id := *key.(*NetFlowId)
	i := slices.Index(f.keys, id)
	if i < 0 {
		return ebpf.ErrKeyNotExist
	}
	f.keys = slices.Delete(f.keys, i, i+1)
	delete(f.values, id)
	if value, ok := f.recreated[id]; ok {
		delete(f.recreated, id)
		f.keys = append(f.keys, id)
		f.values[id] = value
	}
	return nil
}

func (f *fakeLegacyMap) MaxEntries() uint32 {
	return f.maxEntries
}

func assertLegacyMapRead(t *testing.T, flowMap *fakeLegacyMap) {
	t.Helper()
	assert.Empty(t, flowMap.keys, "entries left in the map")
	assert.Zero(t, flowMap.restarts, "NextKey was given a deleted key")
}

func flowIDs(flows map[NetFlowId]*NetFlowMetrics) []NetFlowId {
	return slices.SortedFunc(maps.Keys(flows), func(a, b NetFlowId) int {
		return cmp.Compare(a.IfIndex, b.IfIndex)
	})
}

func (f *fakeBPFMap) BatchLookupAndDelete(_ *ebpf.MapBatchCursor, keysOut, valuesOut any, _ *ebpf.BatchOptions) (int, error) {
	if len(*f) == 0 {
		return 0, ebpf.ErrKeyNotExist
	}
	keys := keysOut.([]NetFlowId)
	values := valuesOut.([]NetFlowMetrics)
	k := 0
	for len(*f) > 0 && k < len(keys) {
		keys[k] = (*f)[0].k
		values[k] = (*f)[0].v
		*f = (*f)[1:]
		k++
	}
	if len(*f) == 0 {
		return k, ebpf.ErrKeyNotExist
	}
	return k, nil
}

type ebpfMapMock struct {
	mock.Mock
}

func (u *ebpfMapMock) MaxEntries() uint32 {
	return u.Called().Get(0).(uint32)
}

func (u *ebpfMapMock) Delete(key any) error {
	args := u.Called(key)
	return args.Error(0)
}

func (u *ebpfMapMock) NextKey(key, nextKeyOut any) error {
	return u.Called(key, nextKeyOut).Error(0)
}

func (u *ebpfMapMock) LookupWithFlags(key, valueOut any, flags ebpf.MapLookupFlags) error {
	return u.Called(key, valueOut, flags).Error(0)
}

func (u *ebpfMapMock) BatchLookupAndDelete(c *ebpf.MapBatchCursor, k, v any, o *ebpf.BatchOptions) (int, error) {
	args := u.Called(c, k, v, o)
	return args.Int(0), args.Error(1)
}
