// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookupAndDelete(t *testing.T) {
	fmd := flowMapDrainer[*fakeMapIterator]{
		log:          slog.Default(),
		cacheMaxSize: 50_000,
		lastReadNS:   100,
		flowMap: fakeBPFMap([]entry{{
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
			v: []NetFlowMetrics{{Packets: 5, StartMonoTimeNs: 10, EndMonoTimeNs: 130}},
		}, {
			k: NetFlowId{IfIndex: 3},
			v: []NetFlowMetrics{{Packets: 35, StartMonoTimeNs: 101, EndMonoTimeNs: 125}},
		}, {
			k: NetFlowId{IfIndex: 4},
			v: []NetFlowMetrics{{Packets: 22, StartMonoTimeNs: 101, EndMonoTimeNs: 110}},
		}}),
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
