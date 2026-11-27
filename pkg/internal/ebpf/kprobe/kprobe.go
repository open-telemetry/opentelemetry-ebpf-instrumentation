// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kprobe // import "go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/tracefs"
)

var attachPMU = func(symbol string, prog *ebpf.Program, ret bool) (io.Closer, error) {
	if ret {
		return link.Kretprobe(symbol, prog, nil)
	}
	return link.Kprobe(symbol, prog, nil)
}

var attachTraceFSEvent = tracefs.Attach

// Attach instruments each resolvable copy of an ambiguous symbol and follows livepatches.
func Attach(symbol string, prog *ebpf.Program, ret bool) (io.Closer, error) {
	probe := &watchedProbe{symbol: symbol, ret: ret, links: map[probeTarget]io.Closer{}}
	p, err := tracefs.WithFallback(tracefs.Kprobe, tracefs.AttachFuncs[*watchedProbe]{
		PMU:           func() (*watchedProbe, error) { return probe.withPrimary(attachPMU(symbol, prog, ret)) },
		TraceFS:       func() (*watchedProbe, error) { return probe.attachTraceFSName(prog, symbol) },
		ResolveKprobe: func(cause error) (*watchedProbe, error) { return probe.resolveTraceFS(prog, cause) },
	})
	if err != nil {
		return nil, err
	}

	return kernelProbes.register(p, prog)
}

func (p *watchedProbe) withPrimary(link io.Closer, err error) (*watchedProbe, error) {
	if err != nil {
		return nil, err
	}
	p.primary = link
	return p, nil
}

func (p *watchedProbe) attachTraceFSName(prog *ebpf.Program, name string) (*watchedProbe, error) {
	p.symbol = name
	return p.withPrimary(attachTraceFSEvent(prog, tracefs.Options{
		Type: tracefs.Kprobe, Targets: []string{name}, Return: p.ret,
	}))
}

func (p *watchedProbe) resolveTraceFS(prog *ebpf.Program, cause error) (*watchedProbe, error) {
	name := p.symbol
	prefixed := syscallPrefix() + name
	var lookupErr error
	for {
		knownAmbiguous := errors.Is(cause, unix.EADDRNOTAVAIL)
		if knownAmbiguous || errors.Is(cause, unix.EINVAL) {
			symbols, err := readSymbols(kernelProbes.kallsyms, map[string]bool{name: true, prefixed: true})
			if err == nil && (knownAmbiguous || symbols.ambiguousFunction(name)) {
				return p.attachDuplicates(prog, symbols.resolveName(name), symbols)
			}

			lookupErr = errors.Join(lookupErr, err)
			if knownAmbiguous {
				return nil, errors.Join(cause, lookupErr)
			}
		}

		// Match Cilium's retry for syscall names such as sys_connect.
		if name == prefixed {
			return nil, errors.Join(cause, lookupErr)
		}

		name = prefixed
		probe, err := p.attachTraceFSName(prog, name)
		if err == nil {
			return probe, nil
		}
		cause = err
	}
}

func (p *watchedProbe) attachDuplicates(prog *ebpf.Program, name string, symbols kallsyms) (*watchedProbe, error) {
	p.symbol = name
	targets, lookupErr := symbols.targets(name, nil)
	attachErr := p.update(prog, targets, lookupErr)

	if len(p.links) == 0 {
		return nil, errors.Join(fmt.Errorf("no tracefs target attached for %q", name), attachErr)
	}

	slog.Debug("attached ambiguous kprobe through tracefs", "symbol", name, "targets", len(p.links))
	p.report(attachErr)

	return p, nil
}

func (p *watchedProbe) update(prog *ebpf.Program, targets map[probeTarget]bool, lookupErr error) error {
	var err error
	for target := range targets {
		if _, exists := p.links[target]; exists {
			continue
		}

		link, attachErr := attachTraceFSEvent(prog, tracefs.Options{
			Type: tracefs.Kprobe, Targets: []string{target.token}, Return: p.ret,
		})

		if attachErr != nil {
			err = errors.Join(err, attachErr)
			continue
		}

		p.links[target] = link
	}

	// A partial lookup (e.g. kptr_restrict changed) cannot establish that an old target vanished.
	if lookupErr == nil {
		for target, link := range p.links {
			if !targets[target] {
				err = errors.Join(err, link.Close())
				delete(p.links, target)
			}
		}
	}

	return errors.Join(lookupErr, err)
}

func syscallPrefix() string {
	switch runtime.GOARCH {
	case "amd64":
		return "__x64_"
	case "arm64":
		return "__arm64_"
	default:
		return ""
	}
}
