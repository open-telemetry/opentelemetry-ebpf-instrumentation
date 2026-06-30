// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

// Reproducer for grafana/beyla#2691 ("Beyla sock_ops/sk_msg programs
// conflicting with Cilium L7 LB generating stalled connections").
//
// Root cause being demonstrated
// -----------------------------
// tpinjector's `obi_sockmap_tracker` (SEC("sockops"), attached to the *root*
// cgroup in production) inserts EVERY outgoing established socket into the
// `sock_dir` SOCKHASH (bpf/tpinjector/tpinjector.c, BPF_SOCK_OPS_ACTIVE_-
// ESTABLISHED_CB -> bpf_sock_hash_update), and `obi_packet_extender`
// (SEC("sk_msg")) is attached as the verdict program over that sockhash.
//
// Crucially, the sockops callback has NO PID/process gate: the socket is
// claimed regardless of whether it belongs to a monitored process. The
// `filter_pids` / valid_pid() check only runs *later*, inside the sk_msg
// program, to decide whether to inject — by then the socket is already a
// member of OBI's sockhash and is being routed through OBI's sk_msg verdict.
//
// That indiscriminate capture is the surface that collides with another
// sockmap consumer on the same host/cgroup — e.g. Cilium's socket-LB / L7 LB,
// which also redirects sockets via sockhash + an sk_msg/sk_skb verdict. Two
// verdict programs fighting over the same socket's psock (and OBI rewriting
// bytes with bpf_msg_push_data on streams Cilium has spliced) is what stalls
// connections. The reporter confirmed: context_propagation=disabled => no
// stall; context_propagation=headers => stall.
//
// What this test asserts
// ----------------------
// With PID filtering ON (filter_pids=1) and NO monitored process registered,
// a plain loopback TCP connection opened by an UNRELATED (bystander) process
// must NOT be claimed into OBI's sock_dir sockhash. Today it IS claimed, so
// this test FAILS on current code — that failure is the reproduction. Once the
// sockops program is scoped to monitored sockets only, the test passes and
// becomes the regression guard.
//
// NOTE: authored from static analysis; it must be run on Linux via
//   make test-privileged
// (e.g. `go test -tags=linux,privileged_tests ./pkg/internal/ebpf/tpinjector/`).

package tpinjector

import (
	"errors"
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

// currentCgroupV2Path returns the cgroup v2 (unified) directory the test
// process already belongs to. Attaching the sockops program here exercises the
// exact production attach type (AttachCGroupSockOps) without creating or moving
// cgroups — robust inside a (privileged) container as well as on a bare host.
// In production OBI attaches at the root cgroup; the bug is identical at any
// level of the hierarchy because the sockops callback has no PID gate.
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

// loadTPInjector loads the real tpinjector collection with PID filtering ON and
// HTTP-header injection enabled (the "headers" mode the reporter saw stall),
// stripping map pinning so it can load outside the OBI bpffs layout.
func loadTPInjector(t *testing.T) *BpfObjects {
	t.Helper()
	require.NoError(t, rlimit.RemoveMemlock())

	spec, err := LoadBpf()
	require.NoError(t, err)

	// The production maps are pinned (OBI_PIN_INTERNAL); a standalone test has
	// no bpffs layout, so disable pinning across the collection.
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}

	// Mirror tpinjector.constants(): filtering ON, headers injection ON.
	setVar(t, spec, "filter_pids", int32(1))
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

// loopbackRoundTrip opens a loopback TCP connection from THIS process (the
// bystander) and exchanges a small non-HTTP payload, so the client socket goes
// through BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB while it lives in the cgroup.
// openLoopbackConn establishes a loopback TCP connection from THIS process (the
// bystander), exchanges a byte so both ends reach ESTABLISHED (firing
// BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB on the client socket), and returns it still
// OPEN. The caller must keep it open while measuring: a socket is auto-removed
// from the sockhash on close, so measuring after close would miss the capture.
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

// TestSockmap_DoesNotClaimBystanderSockets reproduces grafana/beyla#2691.
//
// EXPECTED ON CURRENT CODE: FAIL — the bystander socket is found in sock_dir,
// proving tpinjector claims sockets of non-monitored processes into its
// sockmap and routes them through its sk_msg verdict program. That is the
// precondition for the Cilium socket-LB / sk_msg conflict that stalls
// connections. Fixing the sockops program to only track monitored sockets
// makes this pass.
func TestSockmap_DoesNotClaimBystanderSockets(t *testing.T) {
	requireCgroupV2(t)

	objs := loadTPInjector(t)
	cgPath := currentCgroupV2Path(t)
	attachSockmap(t, objs, cgPath)

	// Baseline before generating any traffic of our own.
	before := countSockhashEntries(t, objs.SockDir)

	// Open a bystander connection and KEEP it open while we measure.
	closeConn := openLoopbackConn(t)
	defer closeConn()

	// Desired (post-fix) behaviour: a bystander, non-monitored connection is
	// NOT pulled into OBI's sockhash, so the count does not grow. On current
	// code the count DOES grow (the active-established socket is captured while
	// the connection is open), so this assertion FAILS — which is the
	// reproduction of beyla#2691.
	assert.Never(t, func() bool {
		return countSockhashEntries(t, objs.SockDir) > before
	}, time.Second, 50*time.Millisecond,
		"BUG (beyla#2691): tpinjector claimed a bystander (non-monitored) "+
			"socket into sock_dir even with filter_pids=1. Every cgroup socket "+
			"is captured into OBI's sockhash and run through its sk_msg verdict, "+
			"which collides with Cilium's socket-LB sockmap and stalls connections.")
}
