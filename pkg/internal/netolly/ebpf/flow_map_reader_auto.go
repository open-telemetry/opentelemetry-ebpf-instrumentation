// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"

import (
	"errors"
	"log/slog"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
)

func dlog(implementation string) *slog.Logger {
	return slog.With("component", "ebpf.FlowMapReader", "implementation", implementation)
}

// addFlow adds to the flow read before: the programs may create it again after the reader deleted it.
func addFlow(flows map[NetFlowId]*NetFlowMetrics, id NetFlowId, metrics *NetFlowMetrics) {
	if stored, ok := flows[id]; ok {
		stored.Accumulate(metrics)
		return
	}
	copied := *metrics
	flows[id] = &copied
}

type flowMapReader interface {
	lookupAndDeleteMap() (map[NetFlowId]*NetFlowMetrics, error)
}

func chooseMapReader(forcedType config.EBPFMapReader, flowMap *ebpf.Map, cacheMaxSize int, lockedValues bool) flowMapReader {
	batchLen := defaultReadBatchLen
	// BPF_F_LOCK fails on maps whose values have no spin lock
	var batchOpts *ebpf.BatchOptions
	if lockedValues {
		batchOpts = &ebpf.BatchOptions{ElemFlags: uint64(ebpf.LookupLock)}
	}
	batch := &flowMapBatchReader{
		flowMap:      flowMap,
		cacheMaxSize: cacheMaxSize,
		opts:         batchOpts,
		cachedKeys:   make([]NetFlowId, batchLen),
		cachedValues: make([]NetFlowMetrics, batchLen),
	}
	legacy := &flowMapLegacyReader[*ebpf.MapIterator]{
		log:          dlog("legacy"),
		flowMap:      flowMap,
		cacheMaxSize: cacheMaxSize,
	}
	switch forcedType {
	case config.MapReaderLegacy:
		return legacy
	case config.MapReaderBatch:
		return batch
	default:
		return &flowMapReaderChooser[*ebpf.MapIterator]{
			batch:  batch,
			legacy: legacy,
		}
	}
}

// flowMapReaderChooser will choose, during first invocation to lookupAndDeleteMap,
// between the map Batch reader (if available) and the legacy iterator-based reader (fallback)
type flowMapReaderChooser[IT mapIterator] struct {
	working flowMapReader
	batch   *flowMapBatchReader
	legacy  *flowMapLegacyReader[IT]
}

func (ad *flowMapReaderChooser[IT]) lookupAndDeleteMap() (map[NetFlowId]*NetFlowMetrics, error) {
	if ad.working != nil {
		return ad.working.lookupAndDeleteMap()
	}
	log := dlog("auto")
	flows, err := ad.batch.lookupAndDeleteMap()
	if err == nil {
		log.Debug("batch map lookup is working")
		ad.working = ad.batch
		ad.batch, ad.legacy = nil, nil
		return flows, nil
	}
	if errors.Is(err, ebpf.ErrNotSupported) {
		log.Warn("batch map lookup is not supported, falling back to legacy map iteration. This"+
			" is expected in RHEL8-based systems", "error", err)
		ad.working = ad.legacy
		ad.batch, ad.legacy = nil, nil
		return ad.working.lookupAndDeleteMap()
	}
	return flows, err
}
