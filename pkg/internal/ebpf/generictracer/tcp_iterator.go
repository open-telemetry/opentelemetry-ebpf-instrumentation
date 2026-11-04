// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/netns"
)

const tcpListenState = 10

var tcpIteratorSupport = sync.OnceValue(checkTCPIterator)

func checkTCPIterator() error {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "obi_iter_probe", Type: ebpf.Tracing, AttachType: ebpf.AttachTraceIter, AttachTo: "tcp",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}, License: "GPL",
	})
	if err != nil {
		return iteratorProbeError(err)
	}
	defer prog.Close()
	iter, err := link.AttachIter(link.IterOptions{Program: prog})
	if err != nil {
		return iteratorProbeError(err)
	}
	defer iter.Close()
	return nil
}

func iteratorProbeError(err error) error {
	if errors.Is(err, ebpf.ErrNotSupported) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS) {
		return fmt.Errorf("TCP iterator unavailable: %w: %w", ebpf.ErrNotSupported, err)
	}
	return err
}

func (p *Tracer) configureTCPIterator(spec *ebpf.CollectionSpec, supportErr error) error {
	if supportErr == nil {
		return nil
	}
	if !errors.Is(supportErr, ebpf.ErrNotSupported) {
		return fmt.Errorf("probe TCP iterator: %w", supportErr)
	}
	p.listeningPortsFallback = true
	// Keep the generated object binding; this placeholder is never attached.
	spec.Programs["obi_iter_tcp"] = &ebpf.ProgramSpec{
		Name: "obi_iter_unused", Type: ebpf.Kprobe,
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}, License: "MIT",
	}
	p.log.Info("TCP iterator unavailable; discovering listening ports with INET_DIAG", "reason", supportErr)
	return nil
}

func tcpListeningPorts(pid int) ([]BpfSockPortNs, error) {
	var ports []BpfSockPortNs
	err := netns.WithNetNS(pid, func() error {
		info, err := os.Stat("/proc/thread-self/ns/net")
		if err != nil {
			return err
		}
		inode := info.Sys().(*syscall.Stat_t).Ino
		seen := make(map[uint16]struct{})
		for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
			sockets, err := netlink.SocketDiagTCP(family)
			if family == unix.AF_INET6 && (errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.ENOENT)) {
				continue
			}
			if err != nil {
				return fmt.Errorf("dump TCP sockets for family %d: %w", family, err)
			}
			for _, socket := range sockets {
				if socket.State != tcpListenState {
					continue
				}
				port := socket.ID.SourcePort
				if _, ok := seen[port]; ok {
					continue
				}
				seen[port] = struct{}{}
				ports = append(ports, BpfSockPortNs{Netns: uint32(inode), Port: port})
			}
		}
		return nil
	})
	return ports, err
}

func (p *Tracer) seedListeningPorts(pid app.PID) error {
	if p.bpfObjects.ListeningPorts == nil {
		return nil
	}
	ports, err := tcpListeningPorts(int(pid))
	if err != nil {
		return err
	}
	for _, port := range ports {
		if err := p.bpfObjects.ListeningPorts.Put(port, uint8(1)); err != nil {
			return fmt.Errorf("seed listening port %d in netns %d: %w", port.Port, port.Netns, err)
		}
	}
	p.log.Debug("Seeded TCP listening ports with INET_DIAG", "pid", pid, "ports", len(ports))
	return nil
}
