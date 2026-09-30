// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package kprobe

import (
	"fmt"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestTraceFSFallbackPrivileged(t *testing.T) {
	require.NoError(t, rlimit.RemoveMemlock())
	for _, ret := range []bool{false, true} {
		t.Run(fmt.Sprintf("return=%t", ret), func(t *testing.T) {
			restoreAttachments(t)
			attachPMU = func(string, *ebpf.Program, bool) (io.Closer, error) {
				return nil, fmt.Errorf("injected PMU denial: %w", unix.EACCES)
			}

			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			var original unix.CPUSet
			require.NoError(t, unix.SchedGetaffinity(0, &original))
			for cpu := 1; cpu < len(original)*bits.UintSize; cpu++ {
				if original.IsSet(cpu) {
					var selected unix.CPUSet
					selected.Set(cpu)
					require.NoError(t, unix.SchedSetaffinity(0, &selected))
					defer func() { require.NoError(t, unix.SchedSetaffinity(0, &original)) }()
					break
				}
			}

			hits, prog := newProbeCounter(t, unix.Gettid())
			eventsFile := kprobeEventsFile(t)
			before := traceFSEvents(t, eventsFile)
			closer, err := Attach("sys_getpid", prog, ret)
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, closer.Close()) })

			var created []string
			for event := range traceFSEvents(t, eventsFile) {
				if !before[event] {
					created = append(created, event)
				}
			}
			require.Len(t, created, 1)
			prefix := `^p:obi_`
			if ret {
				prefix = `^r[0-9]*:obi_`
			}
			require.Regexp(t, prefix, created[0])

			triggerGetpid(t)
			var count uint64
			require.NoError(t, hits.Lookup(uint32(0), &count))
			require.Positive(t, count, "the tracefs probe must run, including away from CPU 0")

			require.NoError(t, closer.Close())
			require.NoError(t, closer.Close())
			assert.NotContains(t, traceFSEvents(t, eventsFile), created[0])
			_, eventPath, ok := strings.Cut(created[0], ":")
			require.True(t, ok)
			_, err = os.Stat(filepath.Join(filepath.Dir(eventsFile), "events", eventPath))
			require.ErrorIs(t, err, os.ErrNotExist)

			triggerGetpid(t)
			var afterClose uint64
			require.NoError(t, hits.Lookup(uint32(0), &afterClose))
			assert.Equal(t, count, afterClose, "a closed probe must no longer run")
		})
	}
}

func newProbeCounter(t *testing.T, tid int) (*ebpf.Map, *ebpf.Program) {
	t.Helper()
	hits, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, hits.Close()) })

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:    ebpf.Kprobe,
		License: "Dual MIT/GPL",
		Instructions: asm.Instructions{
			asm.FnGetCurrentPidTgid.Call(),
			asm.Mov.Reg32(asm.R0, asm.R0),
			asm.JNE.Imm(asm.R0, int32(tid), "exit"),
			asm.StoreImm(asm.RFP, -4, 0, asm.Word),
			asm.LoadMapPtr(asm.R1, hits.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -4),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "exit"),
			asm.Mov.Imm(asm.R1, 1),
			asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
			asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
			asm.Return(),
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, prog.Close()) })
	return hits, prog
}

func triggerGetpid(t *testing.T) {
	t.Helper()
	_, _, errno := unix.RawSyscall(unix.SYS_GETPID, 0, 0, 0)
	require.Zero(t, errno)
}

func kprobeEventsFile(t *testing.T) string {
	t.Helper()
	for _, path := range []string{"/sys/kernel/tracing/kprobe_events", "/sys/kernel/debug/tracing/kprobe_events"} {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	t.Fatal("privileged tests require a mounted tracefs")
	return ""
}

func traceFSEvents(t *testing.T, path string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	events := map[string]bool{}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && strings.Contains(fields[0], ":obi_") && strings.Contains(fields[1], "sys_getpid") {
			events[fields[0]] = true
		}
	}
	return events
}
