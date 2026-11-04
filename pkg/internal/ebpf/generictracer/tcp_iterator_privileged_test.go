// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package generictracer

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	discoverexec "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

func requireIteratorPrivileges(t *testing.T) {
	t.Helper()
	if os.Getenv("OBI_TEST_TCP_ITERATOR") != "1" {
		t.Skip("set OBI_TEST_TCP_ITERATOR=1 inside a disposable test VM")
	}
	require.NoError(t, rlimit.RemoveMemlock())
}

func listenerKey(t *testing.T, pid, port int) BpfSockPortNs {
	t.Helper()
	info, err := os.Stat(fmt.Sprintf("/proc/%d/ns/net", pid))
	require.NoError(t, err)
	return BpfSockPortNs{Netns: uint32(info.Sys().(*syscall.Stat_t).Ino), Port: uint16(port)}
}

func TestTCPIteratorFallbackLiveIPv4IPv6(t *testing.T) {
	requireIteratorPrivileges(t)
	for _, family := range []string{"tcp4", "tcp6"} {
		t.Run(family, func(t *testing.T) {
			address := "127.0.0.1:0"
			if family == "tcp6" {
				address = "[::1]:0"
			}
			listener, err := net.Listen(family, address)
			require.NoError(t, err)
			defer listener.Close()
			client, err := net.Dial(family, listener.Addr().String())
			require.NoError(t, err)
			defer client.Close()
			server, err := listener.Accept()
			require.NoError(t, err)
			defer server.Close()
			ports, err := tcpListeningPorts(os.Getpid())
			require.NoError(t, err)
			key := listenerKey(t, os.Getpid(), listener.Addr().(*net.TCPAddr).Port)
			require.Contains(t, ports, key)
			require.NotContains(t, ports, listenerKey(t, os.Getpid(), client.LocalAddr().(*net.TCPAddr).Port))
			table, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUHash, KeySize: 8, ValueSize: 1, MaxEntries: 128})
			require.NoError(t, err)
			defer table.Close()
			tracer := &Tracer{
				log: tlog(), listeningPortsFallback: true,
				pidsFilter: fakeServiceFilter{current: map[uint32]map[app.PID]svc.Attrs{1: {app.PID(os.Getpid()): {}}}},
			}
			tracer.bpfObjects.ListeningPorts = table
			tracer.runItersForPids()
			var value uint8
			require.NoError(t, table.Lookup(key, &value))
			require.Equal(t, uint8(1), value)
			// Expired namespace entries must be replenished when a PID is allowed.
			require.NoError(t, table.Delete(key))
			tracer.seenNetns.Remove(uint64(key.Netns))
			tracer.AllowPID(app.PID(os.Getpid()), 1, discoverexec.New(discoverexec.Init{Pid: app.PID(os.Getpid())}))
			require.NoError(t, table.Lookup(key, &value))
		})
	}
}

func TestTCPIteratorFallbackChild(t *testing.T) {
	if os.Getenv("OBI_ITERATOR_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	listener, err := net.Listen("tcp4", ":"+os.Getenv("OBI_ITERATOR_PORT"))
	require.NoError(t, err)
	defer listener.Close()
	fmt.Println(listener.Addr().(*net.TCPAddr).Port)
	_, err = io.Copy(io.Discard, os.Stdin)
	require.NoError(t, err)
}

func TestTCPIteratorFallbackLiveNetworkNamespace(t *testing.T) {
	requireIteratorPrivileges(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	command := exec.Command("unshare", "--net", os.Args[0], "-test.run=^TestTCPIteratorFallbackChild$")
	command.Env = append(os.Environ(), "OBI_ITERATOR_CHILD=1", "OBI_ITERATOR_PORT="+strconv.Itoa(port))
	stdin, err := command.StdinPipe()
	require.NoError(t, err)
	stdout, err := command.StdoutPipe()
	require.NoError(t, err)
	command.Stderr = os.Stderr
	require.NoError(t, command.Start())
	t.Cleanup(func() { _ = stdin.Close(); _ = command.Process.Kill(); _ = command.Wait() })
	require.NoError(t, command.Process.Signal(syscall.Signal(0)))
	line := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			line <- scanner.Text()
		} else {
			line <- ""
		}
	}()
	select {
	case text := <-line:
		require.Equal(t, strconv.Itoa(port), text)
	case <-time.After(10 * time.Second):
		t.Fatal("listener subprocess did not start")
	}
	original, err := os.Readlink("/proc/thread-self/ns/net")
	require.NoError(t, err)
	ports, err := tcpListeningPorts(command.Process.Pid)
	require.NoError(t, err)
	childKey := listenerKey(t, command.Process.Pid, port)
	parentKey := listenerKey(t, os.Getpid(), port)
	require.NotEqual(t, parentKey.Netns, childKey.Netns)
	require.Contains(t, ports, childKey)
	require.NotContains(t, ports, parentKey)
	after, err := os.Readlink("/proc/thread-self/ns/net")
	require.NoError(t, err)
	require.Equal(t, original, after)
}

func TestTCPIteratorFallbackProbeLive(t *testing.T) {
	requireIteratorPrivileges(t)
	err := checkTCPIterator()
	if err != nil {
		require.ErrorIs(t, err, ebpf.ErrNotSupported)
	}
	t.Logf("TCP iterator capability probe: %v", err)
}
