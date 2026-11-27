// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kprobe // import "go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"

import (
	"errors"
	"io"
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

// Attach instruments one function entry or return, including when a livepatch shadows its name.
func Attach(symbol string, prog *ebpf.Program, ret bool) (io.Closer, error) {
	return tracefs.WithFallback(tracefs.Kprobe, tracefs.AttachFuncs[io.Closer]{
		PMU:           func() (io.Closer, error) { return attachPMU(symbol, prog, ret) },
		TraceFS:       func() (io.Closer, error) { return attachTraceFS(symbol, prog, ret) },
		ResolveKprobe: func(cause error) (io.Closer, error) { return resolveTraceFS(symbol, prog, ret, cause) },
	})
}

func attachTraceFS(target string, prog *ebpf.Program, ret bool) (io.Closer, error) {
	return attachTraceFSEvent(prog, tracefs.Options{
		Type: tracefs.Kprobe, Targets: []string{target}, Return: ret,
	})
}

func resolveTraceFS(name string, prog *ebpf.Program, ret bool, cause error) (io.Closer, error) {
	prefixed := syscallPrefix() + name
	var lookupErr error
	for {
		knownAmbiguous := errors.Is(cause, unix.EADDRNOTAVAIL)
		if knownAmbiguous || errors.Is(cause, unix.EINVAL) {
			symbols, err := readSymbols(kernelProbes.kallsyms, map[string]bool{name: true, prefixed: true})
			if err == nil && (knownAmbiguous || symbols.ambiguousFunction(name)) {
				return kernelProbes.attachResolved(symbols.resolveName(name), prog, ret, symbols)
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
		probe, err := attachTraceFS(name, prog, ret)
		if err == nil {
			return probe, nil
		}
		cause = err
	}
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
