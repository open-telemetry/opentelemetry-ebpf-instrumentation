// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tpinjector

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func connFD(t *testing.T, c syscall.Conn) int {
	t.Helper()
	raw, err := c.SyscallConn()
	require.NoError(t, err)
	var fd int
	require.NoError(t, raw.Control(func(f uintptr) { fd = int(f) }))
	return fd
}

// only the connecting side of a TCP connection is a client socket to backfill
func TestBackfillSelectsOnlyClientTCPSockets(t *testing.T) {
	lsn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer lsn.Close()

	client, err := net.Dial("tcp", lsn.Addr().String())
	require.NoError(t, err)
	defer client.Close()

	server, err := lsn.Accept()
	require.NoError(t, err)
	defer server.Close()

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer udp.Close()

	unixFDs, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	require.NoError(t, err)
	defer syscall.Close(unixFDs[0])
	defer syscall.Close(unixFDs[1])

	pid := app.PID(os.Getpid())
	table, err := readTCPTable(pid)
	require.NoError(t, err)

	sockets, err := socketFDs(pid)
	require.NoError(t, err)
	inodes := map[int]uint64{}
	for _, s := range sockets {
		inodes[s.fd] = s.inode
	}

	clientFD := connFD(t, client.(*net.TCPConn))
	serverFD := connFD(t, server.(*net.TCPConn))
	listenerFD := connFD(t, lsn.(*net.TCPListener))
	udpFD := connFD(t, udp.(*net.UDPConn))
	for _, fd := range []int{clientFD, serverFD, listenerFD, udpFD, unixFDs[0]} {
		assert.Contains(t, inodes, fd, "socket fd %d not listed", fd)
	}

	// told apart before any duplication
	assert.True(t, isTCPFD(pid, clientFD), "the connecting side was not seen as TCP")
	assert.False(t, isTCPFD(pid, udpFD), "a UDP socket was seen as TCP")
	assert.False(t, isTCPFD(pid, unixFDs[0]), "a UNIX socket was seen as TCP")
	assert.True(t, table.clients[inodes[clientFD]], "the connecting side was skipped")
	assert.False(t, table.clients[inodes[serverFD]], "the accepted side was selected")
	assert.False(t, table.clients[inodes[listenerFD]], "the listener was selected")
	assert.NotContains(t, table.clients, inodes[udpFD], "a UDP socket is in the TCP table")
}

const (
	fakeSelfPID   = 10
	fakeTargetPID = 20
)

// a /proc holding only the cgroup files of OBI (self) and of one target process
func fakeProcFS(t *testing.T, self, target string) procfs.FS {
	t.Helper()
	dir := t.TempDir()
	for pid, cgroup := range map[int]string{fakeSelfPID: self, fakeTargetPID: target} {
		pidDir := filepath.Join(dir, strconv.Itoa(pid))
		require.NoError(t, os.Mkdir(pidDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(cgroup), 0o644))
	}
	require.NoError(t, os.Symlink(strconv.Itoa(fakeSelfPID), filepath.Join(dir, "self")))

	fs, err := procfs.NewFS(dir)
	require.NoError(t, err)
	return fs
}

// duplicating a socket moves it to OBI's net_cls and net_prio cgroups, so only a process sharing
// them can have its sockets duplicated
func TestSameNetCgroups(t *testing.T) {
	const (
		unified      = "0::/kubepods/obi\n"
		v1NetOBI     = "4:net_cls,net_prio:/obi\n0::/obi\n"
		v1NetApp     = "4:net_cls,net_prio:/app\n0::/app\n"
		v1NetPrioApp = "5:net_prio:/app\n4:net_cls:/obi\n0::/app\n"
	)

	for _, tc := range []struct {
		name, self, target string
		want               error
	}{
		{name: "cgroup v2 only", self: unified, target: "0::/kubepods/app\n"},
		{name: "same v1 net cgroups", self: v1NetOBI, target: v1NetOBI},
		{name: "different v1 net cgroups", self: v1NetOBI, target: v1NetApp, want: errNetCgroupsDiffer},
		{name: "different v1 net_prio cgroup", self: "5:net_prio:/obi\n4:net_cls:/obi\n0::/obi\n", target: v1NetPrioApp, want: errNetCgroupsDiffer},
		{name: "v1 net cgroups only on one side", self: unified, target: v1NetApp, want: errNetCgroupsDiffer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sameNetCgroups(fakeProcFS(t, tc.self, tc.target), fakeTargetPID))
		})
	}

	t.Run("process gone", func(t *testing.T) {
		err := sameNetCgroups(fakeProcFS(t, unified, unified), fakeTargetPID+1)
		require.Error(t, err)
		assert.NotErrorIs(t, err, errNetCgroupsDiffer)
	})
}

func TestNetCgroupsInUse(t *testing.T) {
	assert.False(t, netCgroupsInUse(fakeProcFS(t, "0::/obi\n", "")), "cgroup v2 only")
	assert.True(t, netCgroupsInUse(fakeProcFS(t, "4:net_cls,net_prio:/\n0::/obi\n", "")), "v1 net cgroups mounted")
	assert.True(t, netCgroupsInUse(procfs.FS{}), "unreadable /proc")
}
