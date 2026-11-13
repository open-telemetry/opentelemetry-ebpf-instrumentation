// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package appolly

import (
	"os"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestHTTPServerRequestsReconcile(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())
	ids, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(ebpfcommon.BpfHttpServerRequestKeyT{})),
		ValueSize:  uint32(unsafe.Sizeof(ebpfcommon.BpfPidInfoT{})),
		MaxEntries: 4,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ids.Close() })
	events := ebpfcommon.NewEBPFEventContext()
	output := msg.NewQueue[[]request.HTTPServerRequestDelta](msg.ChannelBufferLen(4))
	t.Cleanup(output.Close)
	out := output.Subscribe()
	collector := httpServerRequestCollector{output: output}
	start := ebpfcommon.HTTPServerRequestEvent{
		Type:            ebpfcommon.EventTypeHTTPServerRequestStart,
		Pid:             ebpfcommon.BpfPidInfoT{HostPid: 123},
		GoroutineAddr:   456,
		StartMonotimeNs: 789,
	}
	span, delta := collector.tracker.observe(start, svc.Attrs{ProcPID: 123, UID: svc.UID{Name: "original"}})
	require.Equal(t, int64(1), delta)
	key := ebpfcommon.BpfHttpServerRequestKeyT{Pid: 123, GoroutineAddr: 456, StartMonotimeNs: 789}

	collector.reconcile(t.Context(), events)
	require.Len(t, collector.tracker.active, 1, "an unavailable map must not expire a request")
	events.EBPFMaps[httpServerRequestIDsMap] = ids
	require.NoError(t, ids.Put(key, ebpfcommon.BpfPidInfoT{HostPid: 123}))
	collector.reconcile(t.Context(), events)
	require.Len(t, collector.tracker.active, 1, "a live request must survive reconciliation")
	require.Empty(t, out)

	// The kernel removed the request, but its end event was lost.
	require.NoError(t, ids.Delete(key))
	collector.reconcile(t.Context(), events)
	require.Empty(t, collector.tracker.active)
	require.Len(t, out, 1)
	assert.Equal(t, []request.HTTPServerRequestDelta{{Span: span, Delta: -1}}, <-out)
	collector.reconcile(t.Context(), events)
	end := start
	end.Type = ebpfcommon.EventTypeHTTPServerRequestEnd
	collector.handleRequest(t.Context(), end)
	require.Empty(t, out, "a delayed end event must not decrement twice")

	// Reusing a goroutine must not keep an earlier, completed request alive.
	collector.tracker.observe(start, svc.Attrs{ProcPID: 123})
	next := key
	next.StartMonotimeNs++
	require.NoError(t, ids.Put(next, ebpfcommon.BpfPidInfoT{HostPid: 123}))
	collector.reconcile(t.Context(), events)
	require.Empty(t, collector.tracker.active)
	<-out

	collector.tracker.observe(start, svc.Attrs{ProcPID: 123})
	require.NoError(t, ids.Put(key, ebpfcommon.BpfPidInfoT{HostPid: 123}))

	require.NoError(t, ids.Close())
	collector.reconcile(t.Context(), events)
	require.Len(t, collector.tracker.active, 1, "lookup failures are not evidence of completion")
	require.Empty(t, out)
}
