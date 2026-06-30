// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

// Privileged reproducer and regression guard for https://github.com/grafana/beyla/issues/2691
//
// OBI propagates trace context by claiming TCP sockets into the sock_dir
// sockhash and running an sk_msg verdict over them. Claiming sockets it does not
// own collides with another sockmap user on the same host (e.g. Cilium's
// socket-LB) and stalls those connections. These tests assert OBI only claims
// sockets of monitored processes — for both the live sockops path and the
// startup iterator — with PID-filter-off positive controls.
//
// Linux + root only: run with `make test-privileged`.

package tpinjector

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const cgroupFSRoot = "/sys/fs/cgroup"

// requireCgroupV2 skips the test unless the host exposes a unified (v2)
// cgroup hierarchy at /sys/fs/cgroup, which is what OBI attaches sockops to.
func requireCgroupV2(t *testing.T) {
	t.Helper()
	var st unix.Statfs_t
	require.NoError(t, unix.Statfs(cgroupFSRoot, &st))
	const cgroup2Magic = 0x63677270
	if st.Type != cgroup2Magic {
		t.Skipf("%s is not a cgroup v2 mount (magic=%#x); skipping", cgroupFSRoot, st.Type)
	}
}

// currentCgroupV2Path returns the cgroup v2 dir the test process already lives
// in. Attaching the sockops here uses the real production attach type without
// creating/moving cgroups, so it works inside a privileged container too.
func currentCgroupV2Path(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("/proc/self/cgroup")
	require.NoError(t, err)
	for _, line := range strings.Split(string(data), "\n") {
		// The unified-hierarchy entry is "0::<path>".
		if rel, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join(cgroupFSRoot, rel)
		}
	}
	t.Skip("no cgroup v2 (unified) membership found in /proc/self/cgroup")
	return ""
}

// loadTPInjector loads the real tpinjector collection with HTTP-header
// injection enabled (the "headers" mode the reporter saw stall) and the given
// filterPids value, stripping map pinning so it can load outside the OBI bpffs
// layout.
func loadTPInjector(t *testing.T, filterPids int32) *BpfObjects {
	t.Helper()
	require.NoError(t, rlimit.RemoveMemlock())

	spec, err := LoadBpf()
	require.NoError(t, err)

	// The production maps are pinned (OBI_PIN_INTERNAL); a standalone test has
	// no bpffs layout, so disable pinning across the collection.
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}

	// Mirror tpinjector.constants(): headers injection ON.
	setVar(t, spec, "filter_pids", filterPids)
	setVar(t, spec, "inject_flags", uint32(1)) // k_inject_http_headers
	setVar(t, spec, "max_transaction_time", uint64((10 * time.Second).Nanoseconds()))
	_ = trySetVar(spec, "g_bpf_debug", int32(0)) // best-effort; name may vary

	objs := &BpfObjects{}
	require.NoError(t, spec.LoadAndAssign(objs, nil))
	t.Cleanup(func() { objs.Close() })
	return objs
}

func setVar(t *testing.T, spec *ebpf.CollectionSpec, name string, val any) {
	t.Helper()
	require.NoError(t, trySetVar(spec, name, val), "setting const %q", name)
}

func trySetVar(spec *ebpf.CollectionSpec, name string, val any) error {
	v, ok := spec.Variables[name]
	if !ok {
		return errors.New("variable not found: " + name)
	}
	return v.Set(val)
}

// attachSockmap attaches the sockops tracker to the cgroup and the sk_msg
// verdict program to the sock_dir sockhash — exactly as instrumenter.sockops /
// instrumenter.sockmsgs do in production (pkg/ebpf/instrumenter.go).
func attachSockmap(t *testing.T, objs *BpfObjects, cgPath string) {
	t.Helper()

	cg, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgPath,
		Program: objs.ObiSockmapTracker,
		Attach:  ebpf.AttachCGroupSockOps,
	})
	require.NoError(t, err)
	t.Cleanup(func() { cg.Close() })

	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.SockDir.FD(),
		Program: objs.ObiPacketExtender,
		Attach:  ebpf.AttachSkMsgVerdict,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  objs.SockDir.FD(),
			Program: objs.ObiPacketExtender,
			Attach:  ebpf.AttachSkMsgVerdict,
		})
	})
}

// openLoopbackConn opens a loopback TCP connection from THIS (bystander) process
// and returns it still OPEN. Keep it open while measuring: the kernel removes a
// socket from the sockhash on close, so measuring after close misses the capture.
func openLoopbackConn(t *testing.T) func() {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		buf := make([]byte, 16)
		n, _ := c.Read(buf)
		_, _ = c.Write(buf[:n])
		accepted <- c
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	_, _ = conn.Read(make([]byte, 16))

	srv := <-accepted
	return func() {
		conn.Close()
		if srv != nil {
			srv.Close()
		}
		ln.Close()
	}
}

// countSockhashEntries counts keys in a SOCKHASH. Userspace cannot Lookup the
// socket *values* of a sockhash, but GetNextKey (key-only iteration) works.
func countSockhashEntries(t *testing.T, m *ebpf.Map) int {
	t.Helper()
	var key, next uint64
	count := 0
	err := m.NextKey(nil, &next)
	for err == nil {
		count++
		key = next
		err = m.NextKey(key, &next)
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		require.NoError(t, err)
	}
	return count
}

// TestSockmap_DoesNotClaimBystanderSockets is the core reproducer/guard: with
// PID filtering on and no monitored process, a bystander connection must not be
// claimed into sock_dir. Fails pre-fix (socket captured), passes post-fix.
func TestSockmap_DoesNotClaimBystanderSockets(t *testing.T) {
	requireCgroupV2(t)

	objs := loadTPInjector(t, 1) // PID filtering ON
	cgPath := currentCgroupV2Path(t)
	attachSockmap(t, objs, cgPath)

	before := countSockhashEntries(t, objs.SockDir)

	closeConn := openLoopbackConn(t)
	defer closeConn()

	// The bystander connection must not grow sock_dir. Pre-fix it does (the
	// socket is captured while open), which is the beyla#2691 reproduction.
	assert.Never(t, func() bool {
		return countSockhashEntries(t, objs.SockDir) > before
	}, time.Second, 50*time.Millisecond,
		"BUG: tpinjector claimed a bystander (non-monitored) "+
			"socket into sock_dir even with filter_pids=1. Every cgroup socket "+
			"is captured into OBI's sockhash and run through its sk_msg verdict, "+
			"which collides with Cilium's socket-LB sockmap and stalls connections.")
}

// TestSockmap_CapturesWhenPidFilterOff is the positive control: with PID
// filtering off ("track everything"), the sockops must still capture sockets,
// so a green TestSockmap_DoesNotClaimBystanderSockets can't just mean capture is
// broken. The monitored-process-IS-captured path is covered by the end-to-end
// traceparent integration tests.
func TestSockmap_CapturesWhenPidFilterOff(t *testing.T) {
	requireCgroupV2(t)

	objs := loadTPInjector(t, 0) // PID filtering OFF -> track everything
	cgPath := currentCgroupV2Path(t)
	attachSockmap(t, objs, cgPath)

	before := countSockhashEntries(t, objs.SockDir)

	closeConn := openLoopbackConn(t)
	defer closeConn()

	assert.Eventually(t, func() bool {
		return countSockhashEntries(t, objs.SockDir) > before
	}, time.Second, 50*time.Millisecond,
		"with filter_pids=0 the sockops must still capture sockets into sock_dir; "+
			"if this fails the capture machinery (or the fix's gate) is broken")
}

// --- startup iterator (sock_iter.c) -----------------------------------------

// loadTPInjectorIter loads the sock_iter collection (the startup TCP iterator)
// with the given filterPids value, pinning stripped so it loads standalone.
func loadTPInjectorIter(t *testing.T, filterPids int32) *BpfIterObjects {
	t.Helper()
	require.NoError(t, rlimit.RemoveMemlock())

	spec, err := LoadBpfIter()
	require.NoError(t, err)

	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	setVar(t, spec, "filter_pids", filterPids)
	_ = trySetVar(spec, "g_bpf_debug", int32(0))

	objs := &BpfIterObjects{}
	require.NoError(t, spec.LoadAndAssign(objs, nil))
	t.Cleanup(func() { objs.Close() })
	return objs
}

// driveIter attaches the iter/tcp program and reads it to completion, which
// makes the kernel invoke the program once per existing TCP socket. Skips on
// kernels too old to attach iter/tcp + sockhash (< 6.4).
func driveIter(t *testing.T, prog *ebpf.Program) {
	t.Helper()
	it, err := link.AttachIter(link.IterOptions{Program: prog})
	if err != nil {
		t.Skipf("cannot attach iter/tcp (needs kernel >= 6.4): %v", err)
	}
	defer it.Close()

	r, err := it.Open()
	require.NoError(t, err)
	defer r.Close()
	_, err = io.ReadAll(r)
	require.NoError(t, err)
}

// TestSockmapIter_DoesNotTrackBystanderSockets is the iterator counterpart: the
// startup iterator must not pull pre-existing, non-monitored sockets into
// sock_dir. Filter on + empty sock_pids => driving it adds nothing (pre-fix it
// added every existing socket).
func TestSockmapIter_DoesNotTrackBystanderSockets(t *testing.T) {
	objs := loadTPInjectorIter(t, 1) // PID filtering ON

	closeConn := openLoopbackConn(t)
	defer closeConn()

	driveIter(t, objs.ObiSkIterTcp)

	assert.Equal(t, 0, countSockhashEntries(t, objs.SockDir),
		"BUG: the startup iterator tracked pre-existing bystander "+
			"sockets into sock_dir despite filter_pids=1 and an empty sock_pids.")
}

// TestSockmapIter_TracksWhenPidFilterOff is the positive control: with PID
// filtering OFF the iterator must still track existing sockets, guarding
// against the gate disabling startup tracking entirely.
func TestSockmapIter_TracksWhenPidFilterOff(t *testing.T) {
	objs := loadTPInjectorIter(t, 0) // PID filtering OFF -> track everything

	closeConn := openLoopbackConn(t)
	defer closeConn()

	driveIter(t, objs.ObiSkIterTcp)

	assert.Positive(t, countSockhashEntries(t, objs.SockDir),
		"with filter_pids=0 the iterator must track existing sockets into sock_dir")
}
