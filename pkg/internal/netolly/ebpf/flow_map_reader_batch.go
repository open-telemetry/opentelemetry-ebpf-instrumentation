// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
import (
	"errors"

	"github.com/cilium/ebpf"
)

// TODO: make configurable
const defaultReadBatchLen = 1024

// flowMapBatchReader reads, aggregates and removes all the flows in the eBPF flows map
type flowMapBatchReader struct {
	flowMap      ebpfBatchMap
	cacheMaxSize int

	opts *ebpf.BatchOptions

	// given that lookupAndDeleteMap is not called concurrently, we can save some
	// allocations by reusing the lookup slice
	cachedKeys   []NetFlowId
	cachedValues []NetFlowMetrics
}

type ebpfBatchMap interface {
	BatchLookupAndDelete(cursor *ebpf.MapBatchCursor, keysOut, valuesOut any, opts *ebpf.BatchOptions) (int, error)
}

// lookupAndDeleteMap reads all the entries from the eBPF map and removes them from it.
// It returns a map where the key is the network flow identifier (e.g. src/dst addresses)
// and the value is the aggregated time and metrics for all the packets of this flow.
func (fmd *flowMapBatchReader) lookupAndDeleteMap() (map[NetFlowId]*NetFlowMetrics, error) {
	flows := make(map[NetFlowId]*NetFlowMetrics, fmd.cacheMaxSize)
	cursor := ebpf.MapBatchCursor{}
	for {
		n, err := fmd.flowMap.BatchLookupAndDelete(&cursor, fmd.cachedKeys, fmd.cachedValues, fmd.opts)
		for i := range n {
			addFlow(flows, fmd.cachedKeys[i], &fmd.cachedValues[i])
		}
		if err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				// reaching the end of the map. We can stop reading
				return flows, nil
			}
			return flows, err
		}
	}
}
