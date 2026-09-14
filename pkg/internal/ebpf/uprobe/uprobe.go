// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package uprobe attaches userspace probes as uprobe_multi links where the
// running kernel supports them, and as perf events everywhere else.
package uprobe // import "go.opentelemetry.io/obi/pkg/internal/ebpf/uprobe"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// one decision shared by load-time attach types and attach-time links
var multiSupported = sync.OnceValue(func() bool {
	if err := features.HaveBPFLinkUprobeMulti(); err != nil {
		slog.Info("attaching uprobes as perf events, the kernel has no uprobe_multi links", "reason", err)
		return false
	}
	if !multiFiltersByProcess() {
		slog.Info("attaching uprobes as perf events, the kernel filters uprobe_multi links by thread")
		return false
	}
	slog.Info("attaching uprobes as uprobe_multi links")
	return true
})

// multiFiltersByProcess reports whether a PID-scoped link fires on every thread
// of that process. Kernels before 6.10 (6.6.35 in stable) compared the probed
// thread against the one named at attach time, so hits from every other thread
// were dropped. The fix also rejects a negative PID with EINVAL, which is how
// libbpf tells the two apart: kernels without it look the PID up and answer
// ESRCH. See Linux 46ba0e49b642 and 04d939a2ab22
func multiFiltersByProcess() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "obi_probe_upm_pid",
		Type:         ebpf.Kprobe,
		AttachType:   ebpf.AttachTraceUprobeMulti,
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
		License:      "Dual MIT/GPL",
	})
	if err != nil {
		slog.Debug("cannot probe uprobe_multi PID filtering", "error", err)
		return false
	}
	defer prog.Close()

	exe, err := link.OpenExecutable("/proc/self/exe")
	if err != nil {
		slog.Debug("cannot probe uprobe_multi PID filtering", "error", err)
		return false
	}

	// the address is never read: both kernels answer before they look at it
	l, err := exe.UprobeMulti(nil, prog, &link.UprobeMultiOptions{
		Addresses: []uint64{1},
		PID:       math.MaxUint32,
	})
	if err == nil {
		l.Close()
		slog.Debug("the kernel accepted a uprobe_multi link with a negative PID")
		return false
	}
	return errors.Is(err, unix.EINVAL)
}

// PrepareSpecs sets the uprobe_multi attach type before load, the kernel checks it at attach
func PrepareSpecs(spec *ebpf.CollectionSpec) {
	if !multiSupported() {
		return
	}
	markMultiPrograms(spec)
}

func markMultiPrograms(spec *ebpf.CollectionSpec) {
	tailCallTargets := progArrayContents(spec)
	for name, prog := range spec.Programs {
		if prog.Type != ebpf.Kprobe || prog.AttachType != ebpf.AttachNone || !isUprobeSection(prog.SectionName) {
			continue
		}
		// the kernel rejects tail calls between programs with different attach types
		if tailCallTargets[name] || referencesProgArray(spec, prog) {
			continue
		}
		prog.AttachType = ebpf.AttachTraceUprobeMulti
	}
}

func isUprobeSection(name string) bool {
	return name == "uprobe" || name == "uretprobe" ||
		strings.HasPrefix(name, "uprobe/") || strings.HasPrefix(name, "uretprobe/")
}

func progArrayContents(spec *ebpf.CollectionSpec) map[string]bool {
	targets := map[string]bool{}
	for _, m := range spec.Maps {
		if m.Type != ebpf.ProgramArray {
			continue
		}
		for _, kv := range m.Contents {
			switch value := kv.Value.(type) {
			case string:
				targets[value] = true
			case *ebpf.ProgramSpec:
				targets[value.Name] = true
			}
		}
	}
	return targets
}

func referencesProgArray(spec *ebpf.CollectionSpec, prog *ebpf.ProgramSpec) bool {
	for _, ins := range prog.Instructions {
		if m, ok := spec.Maps[ins.Reference()]; ok && m.Type == ebpf.ProgramArray {
			return true
		}
	}
	return false
}

type Options struct {
	Addresses    []uint64
	RefCtrOffset uint64
	PID          uint32
	Return       bool
}

// Attach uses one uprobe_multi link, or perf events where the kernel refuses it with EINVAL
func Attach(exe *link.Executable, prog *ebpf.Program, opts Options) (io.Closer, error) {
	if len(opts.Addresses) == 0 {
		return nil, errors.New("attaching uprobe: no addresses")
	}
	if !multiSupported() {
		return attachPerfEvents(exe, prog, opts)
	}
	closer, multiErr := attachMulti(exe, prog, opts)
	if multiErr == nil {
		return closer, nil
	}
	if !errors.Is(multiErr, unix.EINVAL) {
		return nil, multiErr
	}
	closer, err := attachPerfEvents(exe, prog, opts)
	if err != nil {
		return nil, errors.Join(multiErr, err)
	}
	return closer, nil
}

func attachMulti(exe *link.Executable, prog *ebpf.Program, opts Options) (io.Closer, error) {
	multiOpts := multiOptions(opts)
	if opts.Return {
		return exe.UretprobeMulti(nil, prog, multiOpts)
	}
	return exe.UprobeMulti(nil, prog, multiOpts)
}

func multiOptions(opts Options) *link.UprobeMultiOptions {
	multiOpts := &link.UprobeMultiOptions{Addresses: opts.Addresses, PID: opts.PID}
	if opts.RefCtrOffset != 0 {
		multiOpts.RefCtrOffsets = make([]uint64, len(opts.Addresses))
		for i := range multiOpts.RefCtrOffsets {
			multiOpts.RefCtrOffsets[i] = opts.RefCtrOffset
		}
	}
	return multiOpts
}

func attachPerfEvents(exe *link.Executable, prog *ebpf.Program, opts Options) (io.Closer, error) {
	links := make(perfEventLinks, 0, len(opts.Addresses))
	for _, address := range opts.Addresses {
		perfOpts := &link.UprobeOptions{Address: address, PID: int(opts.PID), RefCtrOffset: opts.RefCtrOffset}
		var (
			l   link.Link
			err error
		)
		if opts.Return {
			l, err = exe.Uretprobe("", prog, perfOpts)
		} else {
			l, err = exe.Uprobe("", prog, perfOpts)
		}
		if err != nil {
			_ = links.Close()
			return nil, fmt.Errorf("attaching uprobe at %#x: %w", address, err)
		}
		links = append(links, l)
	}
	if len(links) == 1 {
		return links[0], nil
	}
	return links, nil
}

type perfEventLinks []link.Link

func (l perfEventLinks) Close() error {
	var err error
	for _, lk := range l {
		err = errors.Join(err, lk.Close())
	}
	return err
}
