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
	attachByName := func(link io.Closer, err error) (*watchedProbe, error) {
		if err != nil {
			return nil, err
		}
		return &watchedProbe{symbol: symbol, ret: ret, primary: link, links: map[probeTarget]io.Closer{}}, nil
	}

	p, err := tracefs.WithFallback(tracefs.Kprobe, tracefs.AttachFuncs[*watchedProbe]{
		PMU:               func() (*watchedProbe, error) { return attachByName(attachPMU(symbol, prog, ret)) },
		TraceFS:           func() (*watchedProbe, error) { return attachByName(attachTraceFS(symbol, prog, ret)) },
		TraceFSDuplicates: func() (*watchedProbe, error) { return attachDuplicates(symbol, prog, ret) },
	})

	if err != nil {
		return nil, err
	}

	return kernelProbes.register(p, prog)
}

func attachDuplicates(symbol string, prog *ebpf.Program, ret bool) (*watchedProbe, error) {
	wanted := map[string]bool{symbol: true, syscallPrefix() + symbol: true}
	symbols, err := readSymbols(kernelProbes.kallsyms, wanted)
	if err != nil {
		return nil, err
	}

	p := &watchedProbe{symbol: symbol, ret: ret, links: map[probeTarget]io.Closer{}}
	targets, lookupErr := symbols.targets(symbols.resolveName(symbol), nil)
	attachErr := p.update(prog, targets, lookupErr)

	if len(p.links) == 0 {
		return nil, errors.Join(fmt.Errorf("no tracefs target attached for %q", symbol), attachErr)
	}

	slog.Debug("attached ambiguous kprobe through tracefs", "symbol", symbol, "targets", len(p.links))
	p.report(attachErr)

	return p, nil
}

func attachTraceFS(symbol string, prog *ebpf.Program, ret bool) (io.Closer, error) {
	opts := tracefs.Options{Type: tracefs.Kprobe, Targets: []string{symbol}, Return: ret}
	closer, err := attachTraceFSEvent(prog, opts)
	if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.EINVAL) {
		return closer, err
	}

	// Match Cilium's retry for syscall names such as sys_connect.
	if prefix := syscallPrefix(); prefix != "" {
		opts.Targets = []string{prefix + symbol}
		return attachTraceFSEvent(prog, opts)
	}
	return closer, err
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
