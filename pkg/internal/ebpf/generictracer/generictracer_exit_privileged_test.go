// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package generictracer

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

// loadExitTracepoint attaches obi_tp_sched_process_exit with the PID filter on
// and nothing selected, like a child whose parent has exited, and returns the
// maps it must clear: traces_ctx_v1 and node_manual_ctx_shadow.
func loadExitTracepoint(t *testing.T, populate bool) []*ebpf.Map {
	t.Helper()
	require.NoError(t, rlimit.RemoveMemlock())

	spec, err := LoadBpf()
	require.NoError(t, err)
	for _, m := range spec.Maps {
		if m.Pinning == ebpfconvenience.PinInternal || m.Pinning == ebpf.PinByName {
			m.Pinning = ebpf.PinNone
		}
	}
	require.NoError(t, ebpfconvenience.RewriteConstants(spec, map[string]any{
		"filter_pids":             int32(1),
		"g_traces_ctx_v1_enabled": populate,
	}))

	var objs struct {
		Exit        *ebpf.Program `ebpf:"obi_tp_sched_process_exit"`
		TracesCtxV1 *ebpf.Map     `ebpf:"traces_ctx_v1"`
		Shadow      *ebpf.Map     `ebpf:"node_manual_ctx_shadow"`
	}
	require.NoError(t, spec.LoadAndAssign(&objs, nil))
	t.Cleanup(func() {
		objs.Exit.Close()
		objs.TracesCtxV1.Close()
		objs.Shadow.Close()
	})

	tp, err := link.Tracepoint("sched", "sched_process_exit", objs.Exit, nil)
	require.NoError(t, err)
	t.Cleanup(func() { tp.Close() })

	return []*ebpf.Map{objs.TracesCtxV1, objs.Shadow}
}

func putThreadContext(t *testing.T, maps []*ebpf.Map, pidTgid uint64) {
	t.Helper()
	for _, m := range maps {
		require.NoError(t, m.Put(pidTgid, BpfObiCtxInfoT{TraceId: [16]uint8{1}, SpanId: [8]uint8{1}}))
	}
}

func threadContextDeleted(maps []*ebpf.Map, pidTgid uint64) bool {
	var info BpfObiCtxInfoT
	for _, m := range maps {
		if !errors.Is(m.Lookup(pidTgid, &info), ebpf.ErrKeyNotExist) {
			return false
		}
	}
	return true
}

// forEachPopulation runs test with trace context population on and off: the
// Node.js manual span override writes traces_ctx_v1 either way.
func forEachPopulation(t *testing.T, test func(t *testing.T, maps []*ebpf.Map)) {
	for _, populate := range []bool{true, false} {
		t.Run(fmt.Sprintf("populate=%t", populate), func(t *testing.T) {
			test(t, loadExitTracepoint(t, populate))
		})
	}
}

func TestSchedProcessExitDeletesTraceContext(t *testing.T) {
	forEachPopulation(t, func(t *testing.T, maps []*ebpf.Map) {
		cmd := exec.Command("cat")
		stdin, err := cmd.StdinPipe()
		require.NoError(t, err)
		require.NoError(t, cmd.Start())

		pid := uint64(cmd.Process.Pid)
		pidTgid := pid<<32 | pid
		putThreadContext(t, maps, pidTgid)

		require.NoError(t, stdin.Close())
		require.NoError(t, cmd.Wait())
		require.True(t, threadContextDeleted(maps, pidTgid))
	})
}

// A thread other than the leader exits while its process keeps running.
func TestSchedProcessExitDeletesThreadTraceContext(t *testing.T) {
	forEachPopulation(t, func(t *testing.T, maps []*ebpf.Map) {
		release := make(chan struct{})
		tid := lockedThread(release)
		for tid == os.Getpid() {
			tid = lockedThread(release)
		}

		pidTgid := uint64(os.Getpid())<<32 | uint64(tid)
		putThreadContext(t, maps, pidTgid)
		close(release)

		require.Eventually(t, func() bool { return threadContextDeleted(maps, pidTgid) },
			5*time.Second, 10*time.Millisecond)
	})
}

// lockedThread returns the id of a thread that exits once release is closed.
// The runtime never terminates the main thread, so a goroutine that lands on it
// unlocks and the caller tries again.
func lockedThread(release <-chan struct{}) int {
	tids := make(chan int)
	go func() {
		runtime.LockOSThread()
		tid := unix.Gettid()
		tids <- tid
		if tid == unix.Getpid() {
			runtime.UnlockOSThread()
			return
		}
		<-release
	}()
	return <-tids
}
