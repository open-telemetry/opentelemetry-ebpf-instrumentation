// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kprobe // import "go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
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
	target  probeTarget
	link    io.Closer

	lastError string
	once      sync.Once
	closeErr  error
}

func (m *probeMonitor) attachResolved(symbol string, prog *ebpf.Program, ret bool, symbols kallsyms) (io.Closer, error) {
	target, err := symbols.target(symbol, m.patchDir)
	if err != nil {
		return nil, err
	}

	if target.token == "" {
		return nil, fmt.Errorf("kernel address for %q is hidden and no active livepatch targets it", symbol)
	}

	link, err := attachTraceFS(target.token, prog, ret)
	if err != nil || target.module == "" {
		return link, err
	}

	// The caller can close its program while the monitor still needs to move the probe.
	clone, err := prog.Clone()
	if err != nil {
		return nil, errors.Join(err, link.Close())
	}
	p := &watchedProbe{monitor: m, symbol: symbol, ret: ret, program: clone, target: target, link: link}

	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.probes) == 0 {
		m.probes = map[*watchedProbe]bool{}
		m.stop = make(chan struct{})
		go m.watch(m.stop)
	}

	m.probes[p] = true

	return p, nil
}

func (m *probeMonitor) unwatch(p *watchedProbe) error {
	if !m.probes[p] {
		return nil
	}

	delete(m.probes, p)

	if len(m.probes) == 0 {
		close(m.stop)
	}

	return p.program.Close()
}

func (p *watchedProbe) Close() error {
	p.once.Do(func() {
		m := p.monitor

		m.mu.Lock()
		defer m.mu.Unlock()

		p.closeErr = m.unwatch(p)

		if p.link != nil {
			p.closeErr = errors.Join(p.closeErr, p.link.Close())
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
	if len(m.probes) == 0 {
		return nil
	}
	wanted := map[string]bool{}
	for p := range m.probes {
		wanted[p.symbol] = true
	}
	symbols, err := readSymbols(m.kallsyms, wanted)
	if err != nil {
		return err
	}

	var discoveryErr error
	for p := range m.probes {
		target, err := symbols.target(p.symbol, m.patchDir)
		if err != nil {
			p.report(err)
			discoveryErr = errors.Join(discoveryErr, err)
			continue
		}
		p.report(p.update(target))
	}
	return discoveryErr
}

func (p *watchedProbe) update(target probeTarget) error {
	if target == p.target {
		return nil
	}

	var (
		next io.Closer
		err  error
	)
	if target.token != "" {
		next, err = attachTraceFS(target.token, p.program, p.ret)
		if err != nil {
			return err
		}
	} else {
		slog.Warn("waiting for original kprobe after livepatch rollback", "symbol", p.symbol, "return", p.ret)
	}

	if p.link != nil {
		err = p.link.Close()
	}

	p.target, p.link = target, next
	if next != nil && target.module == "" {
		err = errors.Join(err, p.monitor.unwatch(p))
	}

	return err
}

func (p *watchedProbe) report(err error) {
	if err == nil {
		p.lastError = ""
		return
	}

	if msg := err.Error(); msg != p.lastError {
		slog.Warn("updating livepatch kprobe", "symbol", p.symbol, "return", p.ret, "error", err)
		p.lastError = msg
	}
}

func activeLivepatch(root, symbol string) (string, error) {
	patches, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}

	var active []string
	for _, patch := range patches {
		if !patch.IsDir() {
			continue
		}

		dir := filepath.Join(root, patch.Name())

		// A unique vmlinux symbol is the first occurrence in the livepatch ABI.
		_, err := os.Stat(filepath.Join(dir, "vmlinux", symbol+",1"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}

		if err != nil {
			return "", err
		}

		transition, err := patchAttribute(dir, "transition")
		if err != nil {
			return "", err
		}

		if transition != 0 {
			return "", fmt.Errorf("livepatch %s is in transition", patch.Name())
		}

		enabled, err := patchAttribute(dir, "enabled")
		if err != nil {
			return "", err
		}

		if enabled == 1 {
			active = append(active, patch.Name())
		}
	}

	switch len(active) {
	case 0:
		return "", nil
	case 1:
		return active[0], nil
	}

	// Linux 6.14 added stack_order. Older kernels cannot identify the top of a stack.
	var latest string
	var highest int
	for _, module := range active {
		order, err := patchAttribute(filepath.Join(root, module), "stack_order")
		if err != nil {
			return "", fmt.Errorf("cannot order livepatches for %q: %w", symbol, err)
		}

		if order > highest {
			latest, highest = module, order
		}
	}

	return latest, nil
}

func patchAttribute(dir, name string) (int, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(strings.TrimSpace(string(b)))
}
