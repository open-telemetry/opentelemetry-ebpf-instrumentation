// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests && livepatch_vm

package kprobe

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/tracefs"
)

// The AL2023 VM runner supplies the matching signed module to this disposable guest.
func TestAL2023Livepatch(t *testing.T) {
	const symbol = "inet_csk_listen_stop"
	const patch = "/sys/kernel/livepatch/livepatch_inet_reject"
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	require.NoError(t, err)
	require.Equal(t, "6.12.113-138.209.amzn2023.x86_64\n", string(release))
	require.NoError(t, rlimit.RemoveMemlock())
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	originalMonitor := kernelProbes
	kernelProbes = &probeMonitor{patchDir: originalMonitor.patchDir, kallsyms: originalMonitor.kallsyms, interval: 100 * time.Millisecond}
	t.Cleanup(func() { kernelProbes = originalMonitor })
	attach := func(t *testing.T, prog *ebpf.Program, ret bool) io.Closer {
		t.Helper()
		l, err := Attach(symbol, prog, ret)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, l.Close()) })
		return l
	}
	attachWithPMUDenied := func(t *testing.T, prog *ebpf.Program, ret bool) {
		t.Helper()
		pmu := attachPMU
		defer func() { attachPMU = pmu }()
		attachPMU = func(string, *ebpf.Program, bool) (io.Closer, error) { return nil, unix.EACCES }
		attach(t, prog, ret)
	}

	symbols, err := readSymbols(kernelProbes.kallsyms, map[string]bool{symbol: true})
	require.NoError(t, err)
	base := symbols[symbol][""].functions
	require.Len(t, base, 1)
	earlyHits, earlyProg := newFunctionIPCounter(t)
	attach(t, earlyProg, false)
	namedHits, namedProg := newFunctionIPCounter(t)
	attachWithPMUDenied(t, namedProg, true)
	requireListenerHits(t, base[0], earlyHits, namedHits)

	module, err := os.Open("/livepatch-inet-reject.ko")
	require.NoError(t, err)
	defer module.Close()
	require.NoError(t, unix.FinitModule(int(module.Fd()), "", 0))
	require.Eventually(t, func() bool {
		b, e := os.ReadFile(patch + "/transition")
		return e == nil && string(b) == "0\n"
	}, 15*time.Second, 50*time.Millisecond)
	enabled, err := os.ReadFile(patch + "/enabled")
	require.NoError(t, err)
	require.Equal(t, "1\n", string(enabled))
	symbols, err = readSymbols(kernelProbes.kallsyms, map[string]bool{symbol: true})
	require.NoError(t, err)
	replacement := symbols[symbol]["livepatch_inet_reject"].functions
	require.Len(t, replacement, 1)
	require.NotEqual(t, base[0], replacement[0])

	lateHits, lateProg := newFunctionIPCounter(t)
	bare, err := attachPMU(symbol, lateProg, false)
	if bare != nil {
		require.NoError(t, bare.Close())
	}
	require.ErrorIs(t, err, unix.EADDRNOTAVAIL)
	late := attach(t, lateProg, false)
	retHits, retProg := newFunctionIPCounter(t)
	attach(t, retProg, true)
	require.NoError(t, kernelProbes.scan())
	requireListenerHits(t, base[0], earlyHits, namedHits, lateHits, retHits)

	for _, ret := range []bool{false, true} {
		t.Run(fmt.Sprintf("PMU denied/return=%t", ret), func(t *testing.T) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			hits, prog := newFunctionIPCounter(t)
			bare, err := tracefs.Attach(prog, tracefs.Options{Type: tracefs.Kprobe, Targets: []string{symbol}, Return: ret})
			if bare != nil {
				require.NoError(t, bare.Close())
			}
			require.ErrorIs(t, err, unix.EINVAL, "tracefs rejects the ambiguous name")

			attachWithPMUDenied(t, prog, ret)
			requireListenerHits(t, base[0], hits)
		})
	}

	const restrict = "/proc/sys/kernel/kptr_restrict"
	initial, err := os.ReadFile(restrict)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.WriteFile(restrict, initial, 0)) })
	require.NoError(t, os.WriteFile(restrict, []byte("2"), 0))
	fallbackHits, fallbackProg := newFunctionIPCounter(t)
	attach(t, fallbackProg, false)
	requireListenerHits(t, replacement[0], fallbackHits)
	require.NoError(t, os.WriteFile(restrict, initial, 0))
	require.NoError(t, kernelProbes.scan())
	requireListenerHits(t, base[0], fallbackHits)

	require.NoError(t, os.WriteFile(restrict, []byte("2"), 0))
	rollbackHits, rollbackProg := newFunctionIPCounter(t)
	attach(t, rollbackProg, false)
	requireListenerHits(t, replacement[0], rollbackHits)
	require.NoError(t, os.WriteFile(patch+"/enabled", []byte("0"), 0))
	require.Eventually(t, func() bool {
		_, e := os.Stat(patch)
		return os.IsNotExist(e)
	}, 15*time.Second, 50*time.Millisecond)
	require.NoError(t, kernelProbes.scan())
	beforeUnload := functionHits(t, rollbackHits)
	requireListenerHits(t, base[0], earlyHits, namedHits, lateHits, retHits, fallbackHits)
	require.Equal(t, beforeUnload, functionHits(t, rollbackHits))
	require.NoError(t, unix.DeleteModule("livepatch_inet_reject", unix.O_NONBLOCK))
	require.NoError(t, kernelProbes.scan())
	requireListenerHits(t, base[0], rollbackHits)
	require.NoError(t, late.Close())
	before := functionHits(t, lateHits)
	closeListener(t, unix.AF_INET)
	assert.Equal(t, before, functionHits(t, lateHits), "a closed probe must no longer run")
}

// Count hits per function entry, so attaching twice at a single address cannot pass.
func newFunctionIPCounter(t *testing.T) (*ebpf.Map, *ebpf.Program) {
	t.Helper()
	hits, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: 8})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, hits.Close()) })
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.Kprobe, License: "Dual MIT/GPL", Instructions: asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.FnGetCurrentPidTgid.Call(),
		asm.Mov.Reg32(asm.R0, asm.R0),
		asm.JNE.Imm(asm.R0, int32(unix.Gettid()), "exit"),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.FnGetFuncIp.Call(),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.LoadMapPtr(asm.R1, hits.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "first"),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
		asm.Ja.Label("exit"),
		asm.Mov.Imm(asm.R1, 1).WithSymbol("first"),
		asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord),
		asm.LoadMapPtr(asm.R1, hits.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -16),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	}})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, prog.Close()) })
	return hits, prog
}

func functionHits(t *testing.T, m *ebpf.Map) map[uint64]uint64 {
	t.Helper()
	out := map[uint64]uint64{}
	it := m.Iterate()
	var ip, count uint64
	for it.Next(&ip, &count) {
		out[ip] = count
	}
	require.NoError(t, it.Err())
	return out
}

func requireListenerHits(t *testing.T, ip uint64, counters ...*ebpf.Map) {
	t.Helper()
	for _, hits := range counters {
		want := functionHits(t, hits)
		for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
			closeListener(t, family)
			want[ip]++
			require.Equal(t, want, functionHits(t, hits), "one callback per listener close, family %d", family)
		}
	}
}

func closeListener(t *testing.T, family int) {
	t.Helper()
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	require.NoError(t, err)
	require.NoError(t, unix.Listen(fd, 1))
	require.NoError(t, unix.Close(fd))
}
