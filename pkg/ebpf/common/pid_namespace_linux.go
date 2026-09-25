// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"log/slog"
	"os"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
)

// Pid 1 of a pid namespace always lives in it, so /proc/1 names the namespace
// OBI's /proc numbers processes in, even when that procfs is not the one of
// OBI's own pid namespace.
var procPIDNamespace = sync.OnceValues(func() (pidNamespace, error) {
	info, err := os.Stat("/proc/1/ns/pid")
	if err != nil {
		return pidNamespace{}, err
	}

	st := info.Sys().(*syscall.Stat_t)

	return pidNamespace{dev: st.Dev, ino: st.Ino}, nil
})

func PIDFilterConstants(progType ebpf.ProgramType) map[string]any {
	log := slog.With("component", "ebpf.PIDFilter")

	ns, err := procPIDNamespace()
	if err != nil {
		log.Warn("can't read the pid namespace of /proc, assuming the initial one", "error", err)
		return pidFilterConstants(PIDNamespaceInit, pidNamespace{})
	}

	mode := pidNamespaceMode(ns, func() error {
		return features.HaveProgramHelper(progType, asm.FnGetNsCurrentPidTgid)
	})
	log.Debug("BPF PID filter namespace", "mode", mode, "ino", ns.ino, "programType", progType)

	return pidFilterConstants(mode, ns)
}
