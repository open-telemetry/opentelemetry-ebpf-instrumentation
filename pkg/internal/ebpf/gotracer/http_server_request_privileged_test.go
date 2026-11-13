// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package gotracer

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestHTTPServerRequestOffsetsRegistered(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())
	spec, err := LoadBpf()
	require.NoError(t, err)
	mapSpec := spec.Maps["go_offsets_map"].Copy()
	mapSpec.Pinning = ebpf.PinNone
	mapSpec.MaxEntries = 1
	offsetMap, err := ebpf.NewMap(mapSpec)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, offsetMap.Close()) })

	cfg := obi.DefaultConfig
	tracer := New(nil, &cfg, imetrics.NoopReporter{})
	tracer.bpfObjects.GoOffsetsMap = offsetMap
	fileInfo := exec.New(exec.Init{Dev: 1, Ino: 1})
	fields := []goexec.GoOffset{
		goexec.ReqTLSPos,
		goexec.HTTP2ServerReqMethodPos,
		goexec.HTTP2ServerReqURLPos,
		goexec.HTTP2ServerReqTLSPos,
		goexec.HTTP2ResponseWriterStatePos,
		goexec.HTTP2ResponseWriterReqPos,
	}
	for _, tt := range []struct {
		name  string
		value uint64
	}{
		{"missing", missingGoOffset},
		{"present", 48},
		{"zero", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			offsets := &goexec.Offsets{Field: goexec.FieldOffsets{}}
			if tt.value != missingGoOffset {
				for _, field := range fields {
					offsets.Field[field] = tt.value
				}
			}
			tracer.RegisterOffsets(fileInfo, offsets)
			var table BpfOffTableT
			require.NoError(t, offsetMap.Lookup(goOffsetsMapKey(fileInfo), &table))
			for _, field := range fields {
				assert.Equal(t, tt.value, table.Table[field])
			}
		})
	}
}

func TestHTTPServerRequestProcessExitCleanup(t *testing.T) {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	spec, err := LoadBpf()
	require.NoError(t, err)

	newMap := func(name string) *ebpf.Map {
		ms := spec.Maps[name].Copy()
		ms.Pinning = ebpf.PinNone
		ms.MaxEntries = 4

		m, err := ebpf.NewMap(ms)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, m.Close()) })

		return m
	}

	cfg := obi.DefaultConfig
	tracer := New(nil, &cfg, imetrics.NoopReporter{})
	tracer.bpfObjects.HttpServerRequestIds = newMap("http_server_request_ids")
	tracer.bpfObjects.ActiveHttpServerRequests = newMap("active_http_server_requests")
	tracer.bpfObjects.HttpServerRequestsByGoroutine = newMap("http_server_requests_by_goroutine")
	tracer.httpServerRequestPIDs = map[app.PID]BpfPidInfoT{10: {UserPid: 5, Ns: 67}}

	// The same namespaced PID can belong to another process in a different namespace.
	for _, pid := range []BpfPidInfoT{{HostPid: 100, UserPid: 5, Ns: 67}, {HostPid: 200, UserPid: 5, Ns: 89}} {
		id := BpfHttpServerRequestKeyT{Pid: uint64(pid.HostPid), GoroutineAddr: 123, StartMonotimeNs: 456}
		request := BpfGoAddrKeyT{Pid: id.Pid, Addr: 789}
		owner := BpfGoAddrKeyT{Pid: id.Pid, Addr: 123}

		require.NoError(t, tracer.bpfObjects.HttpServerRequestIds.Put(id, pid))
		require.NoError(t, tracer.bpfObjects.ActiveHttpServerRequests.Put(request, BpfHttpServerRequestStateT{
			GoroutineAddr:   id.GoroutineAddr,
			StartMonotimeNs: id.StartMonotimeNs,
		}))
		require.NoError(t, tracer.bpfObjects.HttpServerRequestsByGoroutine.Put(owner, request))
	}

	tracer.deleteHTTPServerRequests(999)
	tracer.deleteHTTPServerRequests(10)
	tracer.deleteHTTPServerRequests(10)

	require.Empty(t, tracer.httpServerRequestPIDs)

	for _, hostPID := range []uint64{100, 200} {
		var pid BpfPidInfoT
		var state BpfHttpServerRequestStateT
		var request BpfGoAddrKeyT

		errors := []error{
			tracer.bpfObjects.HttpServerRequestIds.Lookup(BpfHttpServerRequestKeyT{Pid: hostPID, GoroutineAddr: 123, StartMonotimeNs: 456}, &pid),
			tracer.bpfObjects.ActiveHttpServerRequests.Lookup(BpfGoAddrKeyT{Pid: hostPID, Addr: 789}, &state),
			tracer.bpfObjects.HttpServerRequestsByGoroutine.Lookup(BpfGoAddrKeyT{Pid: hostPID, Addr: 123}, &request),
		}

		for _, err := range errors {
			if hostPID == 100 {
				require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
			} else {
				require.NoError(t, err)
			}
		}
	}
}
