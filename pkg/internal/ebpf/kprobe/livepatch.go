// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kprobe // import "go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

var kernelProbes = &probeMonitor{
	patchDir: "/sys/kernel/livepatch", kallsyms: "/proc/kallsyms", interval: 30 * time.Second,
}

type probeMonitor struct {
	patchDir string
	kallsyms string
	interval time.Duration

	mu     sync.Mutex
	probes map[*watchedProbe]bool
	stop   chan struct{}
}

type watchedProbe struct {
	monitor *probeMonitor
	symbol  string
	ret     bool
	program *ebpf.Program
	primary io.Closer
	links   map[probeTarget]io.Closer

	lastError string
	once      sync.Once
	closeErr  error
}

func (m *probeMonitor) register(p *watchedProbe, prog *ebpf.Program) (io.Closer, error) {
	if p.primary != nil {
		if _, statErr := os.Stat(m.patchDir); errors.Is(statErr, os.ErrNotExist) {
			return p.primary, nil
		}
	}

	// Callers can close the original program concurrently with its links at shutdown.
	var err error
	p.program, err = prog.Clone()
	if err != nil {
		return nil, errors.Join(err, p.Close())
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.probes) == 0 {
		m.probes = map[*watchedProbe]bool{}
		m.stop = make(chan struct{})
		go m.watch(m.stop)
	}

	p.monitor = m
	m.probes[p] = true

	return p, nil
}

func (p *watchedProbe) Close() error {
	p.once.Do(func() {
		if m := p.monitor; m != nil {
			m.mu.Lock()
			delete(m.probes, p)
			if len(m.probes) == 0 {
				close(m.stop)
			}
			m.mu.Unlock()
		}

		if p.primary != nil {
			p.closeErr = p.primary.Close()
		}

		for _, link := range p.links {
			p.closeErr = errors.Join(p.closeErr, link.Close())
		}

		if p.program != nil {
			p.closeErr = errors.Join(p.closeErr, p.program.Close())
		}
	})

	return p.closeErr
}

func (m *probeMonitor) watch(stop <-chan struct{}) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if err := m.scan(); err != nil {
				slog.Debug("scanning kernel livepatches", "error", err)
			}
		}
	}
}

func (m *probeMonitor) scan() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var patches map[string]map[string]bool
	for p := range m.probes {
		if p.primary == nil {
			continue
		}

		var err error
		patches, err = livepatchTargets(m.patchDir)
		if err != nil {
			// Keep existing probe links until sysfs can be read again.
			return nil
		}
		break
	}

	wanted := map[string]bool{}
	for p := range m.probes {
		prefixed := syscallPrefix() + p.symbol
		if p.primary == nil || patches[p.symbol] != nil || patches[prefixed] != nil {
			wanted[p.symbol], wanted[prefixed] = true, true
		}
	}

	var symbols kallsyms
	if len(wanted) > 0 {
		var err error
		symbols, err = readSymbols(m.kallsyms, wanted)
		if err != nil {
			return err
		}
	}

	for p := range m.probes {
		symbol := symbols.resolveName(p.symbol)
		var modules map[string]bool

		if p.primary != nil {
			modules = patches[symbol]
			if len(modules) == 0 {
				p.report(p.update(p.program, nil, nil))
				continue
			}
		}

		targets, lookupErr := symbols.targets(symbol, modules)
		p.report(p.update(p.program, targets, lookupErr))
	}

	return nil
}

func (p *watchedProbe) report(err error) {
	if err == nil {
		p.lastError = ""
		return
	}

	if msg := err.Error(); msg != p.lastError {
		slog.Warn("incomplete kprobe coverage", "symbol", p.symbol, "return", p.ret, "error", err)
		p.lastError = msg
	}
}

// The ABI lists original functions as <patch>/<object>/<symbol>,<position>.
// During a transition both implementations can execute.
func livepatchTargets(root string) (map[string]map[string]bool, error) {
	patches, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}

	result := map[string]map[string]bool{}
	for _, patch := range patches {
		if !patch.IsDir() {
			continue
		}

		dir := filepath.Join(root, patch.Name())
		enabled, err := os.ReadFile(filepath.Join(dir, "enabled"))
		if err != nil {
			return nil, err
		}

		if strings.TrimSpace(string(enabled)) == "0" {
			transition, err := os.ReadFile(filepath.Join(dir, "transition"))
			if err != nil {
				return nil, err
			}
			if strings.TrimSpace(string(transition)) == "0" {
				continue
			}
		}

		objects, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}

		for _, object := range objects {
			if !object.IsDir() {
				continue
			}

			objDir := filepath.Join(dir, object.Name())
			// Since Linux 6.1, unloaded kernel objects are explicitly marked unpatched.
			patched, err := os.ReadFile(filepath.Join(objDir, "patched"))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}

			if strings.TrimSpace(string(patched)) == "0" {
				continue
			}

			functions, err := os.ReadDir(objDir)
			if err != nil {
				return nil, err
			}

			for _, function := range functions {
				symbol, _, ok := strings.Cut(function.Name(), ",")
				if !function.IsDir() || !ok {
					continue
				}
				if result[symbol] == nil {
					result[symbol] = map[string]bool{}
				}
				result[symbol][patch.Name()] = true
			}
		}
	}

	return result, nil
}
