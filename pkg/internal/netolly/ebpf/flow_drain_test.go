// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
import (
	"log/slog"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
)

const testPossibleCPUs = 2

func TestLookupAndDelete(t *testing.T) {
	flowMap := fakeBPFMap([]entry{{
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
	}})
	fmd := flowMapDrainer{
		log:          slog.Default(),
		cacheMaxSize: 50_000,
		lastReadNS:   100,
		possibleCPUs: testPossibleCPUs,
		batchLen:     2,
		flowMap:      &flowMap,
	}
	flows := fmd.lookupAndDeleteMap()
	assert.Equal(t,
		map[NetFlowId]*NetFlowMetrics{
			{IfIndex: 1}: {Packets: 6, StartMonoTimeNs: 101, EndMonoTimeNs: 103},
			{IfIndex: 3}: {Packets: 35, StartMonoTimeNs: 101, EndMonoTimeNs: 125},
			{IfIndex: 4}: {Packets: 22, StartMonoTimeNs: 101, EndMonoTimeNs: 110},
		}, flows)
	assert.EqualValues(t, 125, fmd.lastReadNS)
}

type fakeBPFMap []entry

type entry struct {
	k NetFlowId
	v []NetFlowMetrics
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
