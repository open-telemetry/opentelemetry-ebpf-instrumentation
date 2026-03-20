// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
import (
	"log/slog"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	testBatchLen     = 2
	testPossibleCPUs = 2
)

func TestLookupAndDelete(t *testing.T) {
	expectedAggregation := map[NetFlowId]*NetFlowMetrics{
		{IfIndex: 1}: {Packets: 6, StartMonoTimeNs: 101, EndMonoTimeNs: 103},
		{IfIndex: 3}: {Packets: 35, StartMonoTimeNs: 101, EndMonoTimeNs: 125},
		{IfIndex: 4}: {Packets: 22, StartMonoTimeNs: 101, EndMonoTimeNs: 110},
	}
	t.Run("legacy", func(t *testing.T) {
		fmd := legacyReader()
		flows, err := fmd.lookupAndDeleteMap()
		require.NoError(t, err)
		assert.Equal(t, expectedAggregation, flows)
		assert.EqualValues(t, 125, fmd.lastReadNS)
	})
	t.Run("batch", func(t *testing.T) {
		fmd := batchReader()
		flows, err := fmd.lookupAndDeleteMap()
		require.NoError(t, err)
		assert.Equal(t, expectedAggregation, flows)
		assert.EqualValues(t, 125, fmd.lastReadNS)
	})
	t.Run("auto", func(t *testing.T) {
		fmd := flowMapReaderChooser[*fakeMapIterator]{legacy: legacyReader(), batch: batchReader()}
		flows, err := fmd.lookupAndDeleteMap()
		require.NoError(t, err)
		assert.Equal(t, expectedAggregation, flows)
	})
}

func TestAutoChoose_BatchSupported(t *testing.T) {
	// using a mock to verify that once if the BatchLookupAndDelete function works,
	// the legacy iteration functions are not called
	legacyMap := &ebpfMapMock{}
	iter := &mockedMapIterator{}
	legacyMap.On("Iterate").Return(iter)
	legacyMap.On("BatchLookupAndDelete", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(4, ebpf.ErrKeyNotExist)

	auto := flowMapReaderChooser[*mockedMapIterator]{
		batch:  &flowMapBatchReader{flowMap: legacyMap},
		legacy: &flowMapLegacyReader[*mockedMapIterator]{log: slog.Default(), flowMap: legacyMap},
	}
	_, err := auto.lookupAndDeleteMap()
	require.NoError(t, err)

	legacyMap.AssertCalled(t, "BatchLookupAndDelete", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	legacyMap.AssertNotCalled(t, "Iterate")
	iter.AssertNotCalled(t, "Next")
}

func TestAutoChoose_BatchUnsupported(t *testing.T) {
	// using a mock to verify that once if the BatchLookupAndDelete is not supported,
	// the flowMapReaderChooser switches to the legacy map reader

	legacyMap := &ebpfMapMock{}
	iter := &mockedMapIterator{}
	legacyMap.On("Iterate").Return(iter)
	legacyMap.On("BatchLookupAndDelete", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(0, ebpf.ErrNotSupported)
	legacyMap.On("Delete", mock.Anything).Return(nil)
	iter.On("Next", mock.Anything, mock.Anything).Return(true).Once()
	iter.On("Next", mock.Anything, mock.Anything).Return(false)

	auto := flowMapReaderChooser[*mockedMapIterator]{
		batch:  &flowMapBatchReader{flowMap: legacyMap},
		legacy: &flowMapLegacyReader[*mockedMapIterator]{log: slog.Default(), flowMap: legacyMap},
	}
	_, err := auto.lookupAndDeleteMap()
	require.NoError(t, err)

	legacyMap.AssertCalled(t, "BatchLookupAndDelete", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	legacyMap.AssertCalled(t, "Iterate")
	iter.AssertCalled(t, "Next", mock.Anything, mock.Anything)
	legacyMap.AssertCalled(t, "Delete", mock.Anything)

	// Verify that once the legacy map is selected, we don't try the batch lookup anymore
	legacyMap.Calls = nil
	iter.Calls = nil
	_, err = auto.lookupAndDeleteMap()
	require.NoError(t, err)
	legacyMap.AssertNotCalled(t, "BatchLookupAndDelete")
	legacyMap.AssertCalled(t, "Iterate")
}

func inputFlows() fakeBPFMap {
	return []entry{{
		k: NetFlowId{IfIndex: 1},
		v: []NetFlowMetrics{{Packets: 1, StartMonoTimeNs: 101, EndMonoTimeNs: 101}, {Packets: 2, StartMonoTimeNs: 102, EndMonoTimeNs: 103}},
	}, {
		// repeated entry in map, will anyway try to aggregate,
		k: NetFlowId{IfIndex: 1},
		// will ignore the last flow because is too old
		v: []NetFlowMetrics{{Packets: 3, StartMonoTimeNs: 101, EndMonoTimeNs: 102}, {Packets: 4, StartMonoTimeNs: 101, EndMonoTimeNs: 80}},
	}, {
		// this line is too old, will be ignored
		k: NetFlowId{IfIndex: 2},
		v: []NetFlowMetrics{{Packets: 5, StartMonoTimeNs: 10, EndMonoTimeNs: 130}, { /* zero metric */ }},
	}, {
		k: NetFlowId{IfIndex: 3},
		v: []NetFlowMetrics{{ /* zero metric */ }, {Packets: 35, StartMonoTimeNs: 101, EndMonoTimeNs: 125}},
	}, {
		k: NetFlowId{IfIndex: 4},
		v: []NetFlowMetrics{{Packets: 22, StartMonoTimeNs: 101, EndMonoTimeNs: 110}, { /* zero metric */ }},
	}}
}

func legacyReader() *flowMapLegacyReader[*fakeMapIterator] {
	return &flowMapLegacyReader[*fakeMapIterator]{
		log:          slog.Default(),
		cacheMaxSize: 50_000,
		flowMap:      inputFlows(),
		lastReadNS:   100,
	}
}

func batchReader() *flowMapBatchReader {
	flows := inputFlows()
	return &flowMapBatchReader{
		cacheMaxSize: 50_000,
		lastReadNS:   100,
		possibleCPUs: testPossibleCPUs,
		flowMap:      &flows,
		cachedKeys:   make([]NetFlowId, testBatchLen),
		cachedValues: make([]NetFlowMetrics, testBatchLen*testPossibleCPUs),
	}
}

type fakeBPFMap []entry

type entry struct {
	k NetFlowId
	v []NetFlowMetrics
}

func (f fakeBPFMap) Delete(_ any) error {
	// won't care ATM
	return nil
}

func (f fakeBPFMap) Iterate() *fakeMapIterator {
	return &fakeMapIterator{srcMap: f}
}

type fakeMapIterator struct {
	srcMap []entry
}

func (f *fakeMapIterator) Next(key any, val any) bool {
	if len(f.srcMap) == 0 {
		return false
	}
	tsKey := key.(*NetFlowId)
	tsVal := val.(*[]NetFlowMetrics)
	*tsKey = f.srcMap[0].k
	*tsVal = f.srcMap[0].v
	f.srcMap = f.srcMap[1:]
	return true
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
		copy(values[k*testPossibleCPUs:(k+1)*testPossibleCPUs], (*f)[0].v)
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

func (u *ebpfMapMock) Delete(key any) error {
	args := u.Called(key)
	return args.Error(0)
}

func (u *ebpfMapMock) Iterate() *mockedMapIterator {
	return u.Called().Get(0).(*mockedMapIterator)
}

func (u *ebpfMapMock) BatchLookupAndDelete(c *ebpf.MapBatchCursor, k, v any, o *ebpf.BatchOptions) (int, error) {
	args := u.Called(c, k, v, o)
	return args.Int(0), args.Error(1)
}

type mockedMapIterator struct {
	mock.Mock
}

func (m *mockedMapIterator) Next(key any, value any) bool {
	args := m.Called(key, value)
	return args.Bool(0)
}
