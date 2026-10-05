// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cloud // import "go.opentelemetry.io/obi/pkg/internal/cloud"

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

type MetadataRefresher interface {
	Name() string
	Refresh(ctx context.Context, snapshot *MetadataSnapshot) error
}

// MetadataSnapshot keeps track of two kinds of cloud resources:
//   - those that are identifiable by IP address (e.g. an ECS task endpoint).
//     Useful for service graphs and peer address resolution.
//   - those that are identifiable by a local ID (e.g. ECS container).
//     Useful for RED metrics decoration of services in the same host as OBI
type MetadataSnapshot struct {
	ServiceByIP          map[string]string
	ServiceByContainerID map[string]string
}

// ContainerChanges describes container metadata added, renamed, or removed by a renewal.
type ContainerChanges struct {
	Changed map[string]string
	Removed map[string]string
}

type Inventory struct {
	changes    *msg.Queue[ContainerChanges]
	log        *slog.Logger
	refreshers []MetadataRefresher
	mu         sync.RWMutex
	snapshot   MetadataSnapshot
}

func NewInventory(refreshers []MetadataRefresher) *Inventory {
	return &Inventory{
		changes:    msg.NewQueue[ContainerChanges](),
		log:        slog.With("component", "cloud.Inventory"),
		refreshers: refreshers,
	}
}

func (i *Inventory) SubscribeContainerChanges() <-chan ContainerChanges {
	return i.changes.Subscribe(msg.SubscriberName("CloudProcessEventDecorator"))
}

func (i *Inventory) ServiceNameForIP(ip string) (string, bool) {
	if addr, err := netip.ParseAddr(ip); err == nil {
		ip = addr.Unmap().String()
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	name, ok := i.snapshot.ServiceByIP[ip]
	return name, ok
}

func (i *Inventory) ServiceNameForContainerID(id string) (string, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	name, ok := i.snapshot.ServiceByContainerID[id]
	return name, ok
}

func (i *Inventory) refresh(ctx context.Context) {
	snapshot := MetadataSnapshot{
		ServiceByIP:          map[string]string{},
		ServiceByContainerID: map[string]string{},
	}

	for _, r := range i.refreshers {
		if err := r.Refresh(ctx, &snapshot); err != nil {
			i.log.Warn("can't refresh cloud metadata",
				"source", r.Name(), "error", err)
			return
		}
	}
	i.mu.Lock()
	changes := ContainerChanges{
		Changed: map[string]string{}, Removed: map[string]string{},
	}
	for id, name := range snapshot.ServiceByContainerID {
		if previous, ok := i.snapshot.ServiceByContainerID[id]; !ok || previous != name {
			changes.Changed[id] = name
		}
	}
	for id, name := range i.snapshot.ServiceByContainerID {
		if _, ok := snapshot.ServiceByContainerID[id]; !ok {
			changes.Removed[id] = name
		}
	}
	i.snapshot = snapshot
	hasChanges := len(changes.Changed)+len(changes.Removed) > 0
	i.mu.Unlock()
	if hasChanges {
		i.changes.SendCtx(ctx, changes)
	}
}

func InventoryRefresherNode(i *Inventory, refreshInterval time.Duration) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if i == nil || len(i.refreshers) == 0 {
			return func(context.Context) {}, nil
		}
		// before even any other node in the swarm starts its execution
		// we refresh the inventory so it is pre-populated with existing data
		i.refresh(ctx)
		return func(ctx context.Context) {
			ticker := time.NewTicker(refreshInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					i.refresh(ctx)
				}
			}
		}, nil
	}
}
