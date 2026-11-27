// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
import (
	"errors"
	"log/slog"

	"github.com/cilium/ebpf"
)

// flowMapLegacyReader reads, aggregates and removes all the flows in the eBPF flows map.
// This is a legacy implementation for RHEL8 and derivative distributions, which ship a
// custom 4.18 kernel that backports many eBPF features but don't ship BPF batch maps.
// https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/8.10_release_notes/available_bpf_features
// This implementation can be removed when we stop supporting RHEL8 and derived..
type flowMapLegacyReader struct {
	log          *slog.Logger
	flowMap      ebpfMap
	cacheMaxSize int
	lookupFlags  ebpf.MapLookupFlags
}

type ebpfMap interface {
	NextKey(key, nextKeyOut any) error
	LookupWithFlags(key, valueOut any, flags ebpf.MapLookupFlags) error
	Delete(key any) error
	MaxEntries() uint32
}

// lookupAndDeleteMap reads all the entries from the eBPF map and removes them from it.
// It returns a map where the key is the network flow identifier (e.g. src/dst addresses)
// and the value are the aggregated time and metrics for all the packets of this flow.
func (fmd *flowMapLegacyReader) lookupAndDeleteMap() (map[NetFlowId]*NetFlowMetrics, error) {
	flows := make(map[NetFlowId]*NetFlowMetrics, fmd.cacheMaxSize)

	var id, next NetFlowId
	var metrics NetFlowMetrics
	maxEntries := fmd.flowMap.MaxEntries()
	err := fmd.flowMap.NextKey(nil, &id)
	// the programs can insert flows while the map is read: the rest is left for the next read
	for read := uint32(0); err == nil && read < maxEntries; read++ {
		// the next key is read before this entry is deleted: given a key that is no longer in the
		// map, the kernel restarts the walk from the first key
		err = fmd.flowMap.NextKey(&id, &next)

		lookupErr := fmd.flowMap.LookupWithFlags(&id, &metrics, fmd.lookupFlags)
		switch {
		case errors.Is(lookupErr, ebpf.ErrKeyNotExist):
			// not deleted: it may be the same flow inserted again since, unread
		case lookupErr != nil:
			return flows, lookupErr
		default:
			if deleteErr := fmd.flowMap.Delete(&id); deleteErr != nil {
				fmd.log.Debug("couldn't delete flow entry", "flowId", id, "error", deleteErr)
			}
			addFlow(flows, id, &metrics)
		}
		id = next
	}

	if err == nil {
		fmd.log.Debug("stopped reading the flow map at its capacity", "flows", maxEntries)
		return flows, nil
	}
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return flows, nil
	}
	return flows, err
}
