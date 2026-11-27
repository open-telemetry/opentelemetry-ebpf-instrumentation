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
	attach := func(prog *ebpf.Program, ret bool) io.Closer {
		l, err := Attach(symbol, prog, ret)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, l.Close()) })
		return l
	}

	earlyHits, earlyProg := newFunctionIPCounter(t)
	attach(earlyProg, false)
	closeListeners(t)
	original := functionHits(t, earlyHits)
	require.Len(t, original, 1)
	for _, hits := range original {
		require.EqualValues(t, 2, hits)
	}

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
	symbols, err := readSymbols(kernelProbes.kallsyms, map[string]bool{symbol: true})
	require.NoError(t, err)
	base := symbols[symbol][""].functions
	replacement := symbols[symbol]["livepatch_inet_reject"].functions
	require.Len(t, base, 1)
	require.Len(t, replacement, 1)
	require.NotEqual(t, base[0], replacement[0])

	lateHits, lateProg := newFunctionIPCounter(t)
	bare, err := attachPMU(symbol, lateProg, false)
	if bare != nil {
		require.NoError(t, bare.Close())
	}
	require.ErrorIs(t, err, unix.EADDRNOTAVAIL)
	late := attach(lateProg, false)
	retHits, retProg := newFunctionIPCounter(t)
	attach(retProg, true)
	closeListeners(t)
	lateCounts := functionHits(t, lateHits)
	want := map[uint64]uint64{base[0]: 2, replacement[0]: 2}
	require.Equal(t, want, lateCounts, "entry probes on vmlinux and the signed replacement")
	require.Equal(t, want, functionHits(t, retHits), "return probes on both functions")
	waitForBothFunctions(t, earlyHits, base[0], replacement[0])
	t.Logf("IPv4 and IPv6 closes each hit entry and return probes at vmlinux %#x and livepatch_inet_reject %#x", base[0], replacement[0])

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

			pmu := attachPMU
			t.Cleanup(func() { attachPMU = pmu })
			attachPMU = func(string, *ebpf.Program, bool) (io.Closer, error) { return nil, unix.EACCES }

			probe, err := Attach(symbol, prog, ret)
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, probe.Close()) })
			closeListeners(t)
			require.Equal(t, want, functionHits(t, hits))
		})
	}

	const restrict = "/proc/sys/kernel/kptr_restrict"
	initial, err := os.ReadFile(restrict)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.WriteFile(restrict, initial, 0)) })
	require.NoError(t, os.WriteFile(restrict, []byte("2"), 0))
	partialHits, partialProg := newFunctionIPCounter(t)
	partial := attach(partialProg, false)
	closeListeners(t)
	require.Equal(t, map[uint64]uint64{replacement[0]: 2}, functionHits(t, partialHits))
	require.NoError(t, os.WriteFile(restrict, initial, 0))
	waitForBothFunctions(t, partialHits, base[0], replacement[0])
	require.NoError(t, partial.Close())

	require.NoError(t, os.WriteFile(patch+"/enabled", []byte("0"), 0))
	require.Eventually(t, func() bool {
		_, e := os.Stat(patch)
		return os.IsNotExist(e)
	}, 15*time.Second, 50*time.Millisecond)
	before := functionHits(t, lateHits)
	closeListeners(t)
	after := functionHits(t, lateHits)
	for ip, count := range before {
		if _, base := original[ip]; base {
			require.Equal(t, count+2, after[ip], "original still covers both listener closes")
		} else {
			require.Equal(t, count, after[ip], "disabled replacement is no longer called")
		}
	}
	require.NoError(t, late.Close())
	closeListeners(t)
	assert.Equal(t, after, functionHits(t, lateHits), "closing the registration detaches every target")
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

func waitForBothFunctions(t *testing.T, hits *ebpf.Map, original, replacement uint64) {
	t.Helper()
	// Generate listener closes on the OS thread the BPF program is filtering.
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		closeListeners(t)
		counts := functionHits(t, hits)
		if counts[original] > 0 && counts[replacement] > 0 {
			require.Len(t, counts, 2)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("expected hits at %#x and %#x, got %v", original, replacement, functionHits(t, hits))
}

func closeListeners(t *testing.T) {
	t.Helper()
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
		require.NoError(t, err)
		require.NoError(t, unix.Listen(fd, 1))
		require.NoError(t, unix.Close(fd))
	}
}
