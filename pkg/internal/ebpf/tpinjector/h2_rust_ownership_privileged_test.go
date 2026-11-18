// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"

import (
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/config"
)

func TestH2RustOwnershipBatch(t *testing.T) {
	objs := loadSocketGuardHarnessWith(t, map[string]any{
		"filter_pids": int32(0), "inject_flags": uint32(config.ContextPropagationHeaders),
	})
	conn := newGuardConn(t, objs)
	conn.send(h2Preface, h2EmptySettings)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pid := uint32(os.Getpid())
	threadID := uint64(pid)<<32 | uint64(unix.Gettid())
	const task, sender = uint64(100), uint64(1000)
	require.NoError(t, objs.RustCapabilities.Update(pid, BpfRustCapabilitiesT{TaskContext: 1, ClientContext: 1}, ebpf.UpdateAny))
	require.NoError(t, objs.RustThreads.Update(threadID, BpfRustThreadStateT{
		Depth: 1, Tasks: [8]uint64{task},
	}, ebpf.UpdateAny))
	require.NoError(t, objs.RustH2Tasks.Update(BpfRustTaskKeyT{Pid: pid, Addr: task}, sender, ebpf.UpdateAny))

	const requests = 14
	var frames []byte
	for i := range requests {
		streamID := uint32(2*i + 1)
		pending := BpfRustHttpRequestT{Inject: 1}
		pending.Wire.TraceId[0] = 42
		pending.Wire.SpanId[0] = uint8(i + 1)
		pending.Wire.Flags = 1
		key := BpfRustH2KeyT{Pid: pid, Sender: sender, StreamId: streamID}
		require.NoError(t, objs.RustH2Requests.Update(key, pending, ebpf.UpdateAny))
		frames = append(frames, h2ProbeFrame(streamID)...)
	}
	conn.send(frames)
	requireInjected(t, conn, requests)
	for i := range requests {
		var committed BpfTpInfoPidT
		require.NoError(t, objs.OutgoingTraceMap.Lookup(conn.egressKey(uint32(2*i+1)), &committed))
		require.Equal(t, uint8(1), committed.Written)
		require.Equal(t, uint8(42), committed.Tp.TraceId[0])
		require.Equal(t, uint8(i+1), committed.Tp.SpanId[0])
	}
}
