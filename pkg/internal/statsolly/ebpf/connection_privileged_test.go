// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpf

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
)

func TestTCPConnectionTracepoints(t *testing.T) {
	if os.Getenv("OBI_TEST_NETWORK") != "1" {
		t.Skip("set OBI_TEST_NETWORK=1 inside a disposable test VM")
	}
	require.NoError(t, rlimit.RemoveMemlock())
	spec, err := LoadStats()
	require.NoError(t, err)
	names := []string{progObiStatsTpInetSockSetStateTCPSuccessfulConnection, progObiStatsTpInetSockSetStateTCPFailedConnection, progObiStatsTpInetSockSetStateConnRole}
	for name := range spec.Programs {
		if name != names[0] && name != names[1] && name != names[2] {
			delete(spec.Programs, name)
		}
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	collection, err := ebpf.NewCollection(spec)
	require.NoError(t, err)
	defer collection.Close()
	reader, err := ringbuf.NewReader(collection.Maps["stats_events"])
	require.NoError(t, err)
	defer reader.Close()
	for _, name := range names {
		probe, err := link.Tracepoint("sock", "inet_sock_set_state", collection.Programs[name], nil)
		require.NoError(t, err)
		defer probe.Close()
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	client, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	require.NoError(t, err)
	server, err := listener.Accept()
	require.NoError(t, err)
	require.NoError(t, client.Close())
	require.NoError(t, server.Close())
	require.NoError(t, listener.Close())
	refused, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if refused != nil {
		refused.Close()
	}
	require.Error(t, err)
	reader.SetDeadline(time.Now().Add(5 * time.Second))
	success, failed := false, false
	for !success || !failed {
		record, err := reader.Read()
		require.NoError(t, err, "TCP state events must survive tracepoint protocol-field width changes")
		require.NotEmpty(t, record.RawSample)
		switch StatType(record.RawSample[0]) {
		case StatTypeTCPSuccessfulConnection:
			var event StatsTcpSuccessfulConnectionT
			require.NoError(t, binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event))
			success = success || int(event.Conn.D_port) == port || int(event.Conn.S_port) == port
		case StatTypeTCPFailedConnection:
			var event StatsTcpFailedConnectionT
			require.NoError(t, binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event))
			failed = failed || int(event.Conn.D_port) == port || int(event.Conn.S_port) == port
		}
	}
}
