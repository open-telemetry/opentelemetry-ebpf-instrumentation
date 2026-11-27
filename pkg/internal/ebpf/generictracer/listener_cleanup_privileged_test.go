// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package generictracer

import (
	"errors"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"
)

func TestTCPListenerCleanup(t *testing.T) {
	require.NoError(t, rlimit.RemoveMemlock())
	spec, err := LoadBpf()
	require.NoError(t, err)
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	constants := ebpfcommon.PIDFilterConstants()
	constants["filter_pids"] = int32(1)
	require.NoError(t, ebpfconvenience.RewriteConstants(spec, constants))

	var objs struct {
		Accept    *ebpf.Program `ebpf:"obi_kprobe_security_socket_accept"`
		AcceptRet *ebpf.Program `ebpf:"obi_kretprobe_sys_accept4"`
		State     *ebpf.Program `ebpf:"obi_kprobe_tcp_set_state"`
		Stop      *ebpf.Program `ebpf:"obi_kprobe_inet_csk_listen_stop"`
		Listening *ebpf.Map     `ebpf:"listening_ports"`
		Filter    *ebpf.Map     `ebpf:"filter_ports"`
		PIDs      *ebpf.Map     `ebpf:"valid_pids"`
	}
	require.NoError(t, spec.LoadAndAssign(&objs, nil))
	t.Cleanup(func() {
		objs.Accept.Close()
		objs.AcceptRet.Close()
		objs.State.Close()
		objs.Stop.Close()
		objs.Listening.Close()
		objs.Filter.Close()
		objs.PIDs.Close()
	})
	enter, err := kprobe.Attach("security_socket_accept", objs.Accept, false)
	require.NoError(t, err)
	t.Cleanup(func() { enter.Close() })
	ret, err := kprobe.Attach("sys_accept4", objs.AcceptRet, true)
	require.NoError(t, err)
	t.Cleanup(func() { ret.Close() })

	for _, probe := range []struct {
		symbol  string
		program *ebpf.Program
	}{
		{"inet_csk_listen_stop", objs.Stop},
		{"tcp_set_state", objs.State},
	} {
		t.Run(probe.symbol, func(t *testing.T) {
			hook, err := kprobe.Attach(probe.symbol, probe.program, false)
			if probe.symbol == "inet_csk_listen_stop" && errors.Is(err, unix.EADDRNOTAVAIL) {
				t.Skipf("livepatch can make %s ambiguous: %v", probe.symbol, err)
			}
			require.NoError(t, err)
			t.Cleanup(func() { hook.Close() })
			testListenerCleanup(t, objs.Listening, objs.Filter, objs.PIDs)
		})
	}
}

func testListenerCleanup(t *testing.T, listening, filter, pids *ebpf.Map) {
	t.Helper()
	var bitmap ebpfcommon.PIDBitmap
	pid := app.PID(os.Getpid())
	require.NoError(t, bitmap.Set(pids, pid, true))
	var ns unix.Stat_t
	require.NoError(t, unix.Stat("/proc/self/ns/net", &ns))

	open := func(address string) (net.Listener, net.Conn) {
		t.Helper()
		listener, err := net.Listen("tcp4", address)
		require.NoError(t, err)
		t.Cleanup(func() { listener.Close() })
		client, err := net.Dial("tcp4", listener.Addr().String())
		require.NoError(t, err)
		t.Cleanup(func() { client.Close() })
		server, err := listener.Accept()
		require.NoError(t, err)
		t.Cleanup(func() { server.Close() })
		return listener, server
	}
	check := func(listener net.Listener, want error) {
		t.Helper()
		port := uint16(listener.Addr().(*net.TCPAddr).Port)
		key := BpfSockPortNs{Netns: uint32(ns.Ino), Port: port}
		var value uint8
		require.ErrorIs(t, listening.Lookup(key, &value), want, "listening_ports port %d", port)
		require.ErrorIs(t, filter.Lookup(port, &value), want, "filter_ports port %d", port)
	}

	// Both sockets can bind with SO_REUSEADDR before either begins listening.
	competing, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(competing) })
	require.NoError(t, unix.SetsockoptInt(competing, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1))
	loopback := [4]byte{127, 0, 0, 1}
	require.NoError(t, unix.Bind(competing, &unix.SockaddrInet4{Addr: loopback}))
	addr, err := unix.Getsockname(competing)
	require.NoError(t, err)
	target := net.TCPAddr{IP: net.IP(loopback[:]), Port: addr.(*unix.SockaddrInet4).Port}
	first, conn := open(target.String())
	second, _ := open("127.0.0.1:0")
	check(first, nil)
	check(second, nil)
	require.ErrorIs(t, unix.Listen(competing, 1), unix.EADDRINUSE)
	check(first, nil)

	// Cleanup is system-wide even after discovery stops selecting this PID.
	require.NoError(t, bitmap.Set(pids, pid, false))
	require.NoError(t, conn.(*net.TCPConn).SetLinger(0))
	require.NoError(t, conn.Close())
	check(first, nil)
	require.NoError(t, first.Close())
	check(first, ebpf.ErrKeyNotExist)
	check(second, nil)
	require.NoError(t, second.Close())
	check(second, ebpf.ErrKeyNotExist)
}
