// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"context"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/net"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

type processKey struct {
	pid   int32
	start uint64
}

type processInventory struct {
	mu        sync.Mutex
	processes map[processKey]*exec.FileInfo
}

// This code here keeps an inventory of local servers, e.g. processes that we are instrumenting that are listeners
// on certain ports.
func runInventory(ctx context.Context, events <-chan exec.ProcessEvent, store *localStore, interval time.Duration) {
	inventory := &processInventory{processes: map[processKey]*exec.FileInfo{}}

	var polling sync.WaitGroup

	polling.Go(func() {
		inventory.poll(ctx, store, interval)
	})

	defer polling.Wait()

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				events = nil
				continue
			}

			inventory.mu.Lock()
			updateProcesses(inventory.processes, event)
			inventory.mu.Unlock()
		}
	}
}

func (i *processInventory) poll(ctx context.Context, store *localStore, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			i.mu.Lock()
			processes := maps.Clone(i.processes)
			i.mu.Unlock()

			expired := refreshInventory(ctx, processes, store)

			i.mu.Lock()
			for _, key := range expired {
				delete(i.processes, key)
			}
			i.mu.Unlock()
		}
	}
}

func updateProcesses(processes map[processKey]*exec.FileInfo, event exec.ProcessEvent) {
	if event.File == nil {
		return
	}

	key := processKey{pid: int32(event.File.Pid()), start: event.File.StartTime()}

	if event.Type == exec.ProcessEventTerminated {
		delete(processes, key)
		return
	}

	processes[key] = event.ServiceFile()
}

func refreshInventory(ctx context.Context, processes map[processKey]*exec.FileInfo, store *localStore) []processKey {
	var expired []processKey
	services := map[Service]struct{}{}
	listeners := map[Listener]struct{}{}

	for key, file := range processes {
		if ctx.Err() != nil {
			return expired
		}

		start, err := procs.StartTime(app.PID(key.pid))
		if err != nil || (key.start != 0 && start != key.start) {
			delete(processes, key)
			expired = append(expired, key)
			continue
		}

		attrs := file.ServiceAttrs()
		service := Service{Name: attrs.UID.Name, Namespace: attrs.UID.Namespace}
		if service.Name == "" {
			continue
		}

		services[service] = struct{}{}
		registerListeners(ctx, key.pid, service, listeners)
	}

	serviceList := slices.AppendSeq(make([]Service, 0, len(services)), maps.Keys(services))
	listenerList := slices.AppendSeq(make([]Listener, 0, len(listeners)), maps.Keys(listeners))
	store.setInventory(serviceList, listenerList)

	return expired
}

func registerListeners(ctx context.Context, pid int32, service Service, listeners map[Listener]struct{}) {
	connections, err := net.ConnectionsPidWithoutUidsWithContext(ctx, "inet", pid)
	if err != nil {
		return
	}

	for _, connection := range connections {
		if connection.Status != "LISTEN" {
			continue
		}

		addr, err := netip.ParseAddr(connection.Laddr.IP)
		if err != nil {
			continue
		}

		listeners[Listener{
			Endpoint: Endpoint{
				IP:   addr.Unmap().String(),
				Port: int(connection.Laddr.Port),
			},
			Service: service,
		}] = struct{}{}
	}
}
