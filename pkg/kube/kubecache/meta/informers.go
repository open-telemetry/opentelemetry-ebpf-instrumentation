// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta // import "go.opentelemetry.io/obi/pkg/kube/kubecache/meta"

import (
	"cmp"
	"log/slog"
	"slices"
	"sync"

	"k8s.io/client-go/tools/cache"

	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

type Informers struct {
	BaseNotifier

	log    *slog.Logger
	config *informersConfig

	// pods and replicaSets cache the different K8s types to custom, smaller object types
	pods     cache.SharedIndexInformer
	nodes    cache.SharedIndexInformer
	services cache.SharedIndexInformer

	waitForSync chan struct{}
	syncMutex   sync.Mutex

	// localInstance is true if the current informer instance runs inside an OBI instance
	// if it runs as part of the k8s-cache service, it is false
	localInstance bool
}

type timestamped interface {
	// FromEpoch returns a timestamp in Unix seconds.
	FromEpoch() int64
}

func (inf *Informers) Subscribe(observer Observer) {
	inf.syncMutex.Lock()
	defer inf.syncMutex.Unlock()

	inf.SubscribeWithSnapshot(observer, func() []*informer.Event {
		fromEpoch := int64(0)
		if conn, ok := observer.(timestamped); ok {
			fromEpoch = conn.FromEpoch()
		}

		pods := inf.pods.GetStore().List()
		var nodes, services []any
		if !inf.config.disableNodes {
			nodes = inf.nodes.GetStore().List()
		}
		if !inf.config.disableServices {
			services = inf.services.GetStore().List()
		}
		storedEntities := make([]any, 0, len(pods)+len(nodes)+len(services))
		storedEntities = append(storedEntities, pods...)
		storedEntities = append(storedEntities, nodes...)
		storedEntities = append(storedEntities, services...)
		storedEntities = inf.sortAndCut(storedEntities, fromEpoch)
		inf.log.Debug("sending welcome snapshot to new observer",
			"observerID", observer.ID(), "count", len(storedEntities))

		events := make([]*informer.Event, 0, len(storedEntities)+1)
		for _, entity := range storedEntities {
			events = append(events, &informer.Event{
				Type:     informer.EventType_CREATED,
				Resource: entity.(*indexableEntity).EncodedMeta,
			})
		}
		select {
		case <-inf.waitForSync:
			events = append(events, &informer.Event{Type: informer.EventType_SYNC_FINISHED})
		default:
		}
		return events
	})
}

// sorts the list of entities by status time and cuts the list from the given timestamp.
// If the timestamp is zero, the list is not cut.
// The returned list is sorted in ascending order by status time.
func (inf *Informers) sortAndCut(list []any, cutFromEpoch int64) []any {
	if inf.localInstance {
		// this feature is only useful for minimizing traffic with the k8s-cache service
		return list
	}
	slices.SortFunc(list, func(i, j any) int {
		return cmp.Compare(
			i.(*indexableEntity).EncodedMeta.StatusTimeEpoch,
			j.(*indexableEntity).EncodedMeta.StatusTimeEpoch,
		)
	})
	if cutFromEpoch == 0 {
		return list
	}

	elementsFromTS, _ := slices.BinarySearchFunc(list, cutFromEpoch, func(e any, ts int64) int {
		ets := e.(*indexableEntity).EncodedMeta.StatusTimeEpoch
		return cmp.Compare(ets, ts)
	})
	return list[elementsFromTS:]
}
