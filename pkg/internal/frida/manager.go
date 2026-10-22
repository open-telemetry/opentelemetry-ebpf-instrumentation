// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package frida // import "go.opentelemetry.io/obi/pkg/internal/frida"

import (
	"context"
	_ "embed"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	discoverexec "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/frida/core"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
)

//go:embed agent.js
var agent string

type session struct {
	start  uint64
	cancel context.CancelFunc
	done   chan struct{}
}

func (s *session) close() { s.cancel() }

// Manager owns Frida sessions for processes selected by OBI discovery.
type Manager struct {
	engine   *core.Engine
	log      *slog.Logger
	mu       sync.Mutex
	sessions map[app.PID]*session
	selected map[app.PID]uint64
	closed   bool
}

func New(cfg obi.FridaConfig, log *slog.Logger) *Manager {
	if !cfg.Enabled || ebpfcommon.IntegrityModeOverride || !ebpfcommon.SupportsContextPropagationWithProbe(log) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	engine, err := core.Open(ctx, cfg.Library)
	if err != nil {
		log.Warn("starting Frida Core", "error", err)
		return nil
	}
	return &Manager{engine: engine, log: log, sessions: make(map[app.PID]*session), selected: make(map[app.PID]uint64)}
}

func (m *Manager) Select(process *procs.ProcessHandle) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.selected[process.PID()] = process.StartTime()
	}
}

func (m *Manager) Attach(ctx context.Context, process *procs.ProcessHandle) {
	pid := process.PID()
	if err := process.Alive(); err != nil || ctx.Err() != nil || ebpfcommon.IntegrityModeOverride {
		return
	}
	m.mu.Lock()
	if m.closed || m.selected[pid] != process.StartTime() {
		m.mu.Unlock()
		return
	}
	if old := m.sessions[pid]; old != nil {
		if old.start == process.StartTime() {
			m.mu.Unlock()
			return
		}
		old.close()
	}
	lifetime, cancel := context.WithCancel(ctx)
	current := &session{start: process.StartTime(), cancel: cancel, done: make(chan struct{})}
	m.sessions[pid] = current
	m.mu.Unlock()
	ready := make(chan struct{})
	go m.runSession(lifetime, process, current, ready)
	select {
	case <-ready:
	case <-current.done:
	case <-ctx.Done():
		current.close()
	}
}

func (m *Manager) runSession(lifetime context.Context, process *procs.ProcessHandle, current *session, ready chan struct{}) {
	pid := process.PID()
	defer func() {
		current.close()
		m.mu.Lock()
		if m.sessions[pid] == current {
			delete(m.sessions, pid)
		}
		close(current.done)
		m.mu.Unlock()
	}()
	startup, stop := context.WithTimeout(lifetime, 10*time.Second)
	defer stop()
	native, err := m.engine.Attach(startup, uint32(pid), agent)
	if err != nil {
		m.log.Warn("attaching Frida agent", "pid", pid, "error", err)
		return
	}
	drain := false
	defer func() {
		if err := native.Close(drain); err != nil {
			m.log.Warn("detaching Frida agent", "pid", pid, "error", err)
		}
	}()
	if err := process.Alive(); err != nil || lifetime.Err() != nil {
		return
	}
	hooks, err := native.Call(startup, "start")
	if err != nil {
		drain = true
		m.log.Warn("starting Frida hooks", "pid", pid, "error", err)
		return
	}
	m.log.Info("Frida OpenSSL agent attached", "pid", pid, "hooks", string(hooks))
	close(ready)
	running := true
	for running {
		select {
		case message := <-native.Messages:
			m.log.Warn("Frida agent event", "pid", pid, "message", string(message))
			var event struct {
				Type    string `json:"type"`
				Payload struct {
					Type string `json:"type"`
				} `json:"payload"`
			}
			if json.Unmarshal(message, &event) == nil && (event.Type == "error" || event.Payload.Type == "failure") {
				running = false
			}
		case <-native.Detached:
			running = false
		case <-native.Failed:
			m.log.Warn("Frida message queue overflowed", "pid", pid)
			running = false
		case <-lifetime.Done():
			running = false
		}
	}
	select {
	case <-native.Detached:
		return
	default:
	}
	shutdown, finish := context.WithTimeout(context.Background(), 5*time.Second)
	defer finish()
	result, err := native.Call(shutdown, "stop")
	if err != nil {
		m.log.Warn("stopping Frida hooks", "pid", pid, "error", err)
		// Preserve storage if a live target could still hold an expanded buffer.
		drain = true
	} else {
		drain = string(result) == "false"
	}
	if drain {
		m.log.Info("Frida agent draining", "pid", pid)
	}
}

func (m *Manager) Remove(fi *discoverexec.FileInfo) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.selected[fi.Pid()] == fi.StartTime() {
		delete(m.selected, fi.Pid())
	}
	if current := m.sessions[fi.Pid()]; current != nil && current.start == fi.StartTime() {
		current.close()
	}
}

func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	clear(m.selected)
	sessions := make([]*session, 0, len(m.sessions))
	for _, current := range m.sessions {
		current.close()
		sessions = append(sessions, current)
	}
	m.mu.Unlock()
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	for _, current := range sessions {
		select {
		case <-current.done:
		case <-timer.C:
			m.log.Warn("Frida sessions are still detaching; retaining native runtime")
			return
		}
	}
	if m.engine != nil {
		if err := m.engine.Close(); err != nil {
			m.log.Warn("closing Frida Core", "error", err)
		}
	}
}
