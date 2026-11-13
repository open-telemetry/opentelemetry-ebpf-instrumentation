// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

// pidEntries keeps the namespaced keys of a per-process eBPF map, to remove entries after exit
type pidEntries struct {
	mu   sync.Mutex
	keys map[app.PID]BpfPidInfoT
}

func (e *pidEntries) put(m *ebpf.Map, pid app.PID, ns uint32, value any) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	key, err := pidMapKey(pid, ns)
	if err != nil {
		return err
	}
	if old, exists := e.keys[pid]; exists && old != key {
		if err := e.delete(m, pid); err != nil {
			return err
		}
	}
	if err := m.Put(key, value); err != nil {
		return err
	}
	if e.keys == nil {
		e.keys = map[app.PID]BpfPidInfoT{}
	}
	e.keys[pid] = key
	return nil
}

func (e *pidEntries) remove(m *ebpf.Map, pid app.PID) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.delete(m, pid)
}

func (e *pidEntries) delete(m *ebpf.Map, pid app.PID) error {
	key, ok := e.keys[pid]
	if !ok {
		return nil
	}
	if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	delete(e.keys, pid)
	return nil
}

func pidMapKey(pid app.PID, ns uint32) (BpfPidInfoT, error) {
	pids, err := readNamespacePIDs(pid)
	if err != nil {
		return BpfPidInfoT{}, fmt.Errorf("reading namespaced PIDs: %w", err)
	}
	if len(pids) != 0 {
		pid = pids[len(pids)-1]
	}
	return BpfPidInfoT{UserPid: uint32(pid), Ns: ns}, nil
}
