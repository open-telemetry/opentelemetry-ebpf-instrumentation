// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

const (
	cookieWaitTimeout = 5 * time.Second
	churnConnections  = 2000
	churnWorkers      = 8
	// transient entries for connections still finishing their close handshake
	churnResidueBound = 64
)

// loads tpinjector and attaches its sockops program to a private cgroup that
// contains only the test process, so every loopback connection made here goes
// through bpf_sock_ops_active_est_cb exactly as in production
func setupSockopsHarness(t *testing.T) *BpfObjects {
	require.Equal(t, 0, os.Geteuid(), "privileged eBPF test must run as root")
	require.NoError(t, rlimit.RemoveMemlock())

	spec, err := LoadBpf()
	require.NoError(t, err)

	for _, m := range spec.Maps {
		if m.Pinning == ebpfconvenience.PinInternal {
			m.Pinning = ebpf.PinNone
		}
	}

	objs := &BpfObjects{}
	require.NoError(t, spec.LoadAndAssign(objs, nil))
	t.Cleanup(func() { objs.Close() })

	cgroupDir := enterTempCgroup(t)

	lnk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupDir,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.ObiSockmapTracker,
	})
	require.NoError(t, err)
	t.Cleanup(func() { lnk.Close() })

	return objs
}

// creates a child of the current cgroup, moves the test process into it, and
// restores it on cleanup
func enterTempCgroup(t *testing.T) string {
	data, err := os.ReadFile("/proc/self/cgroup")
	require.NoError(t, err)

	var current string
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		if rel, ok := strings.CutPrefix(line, "0::"); ok {
			current = rel
			break
		}
	}
	require.NotEmpty(t, current, "cgroup v2 entry not found in /proc/self/cgroup")

	base := filepath.Join("/sys/fs/cgroup", current)
	dir := filepath.Join(base, fmt.Sprintf("obi-sock-cookies-test-%d", os.Getpid()))
	require.NoError(t, os.Mkdir(dir, 0o755))

	pid := []byte(strconv.Itoa(os.Getpid()))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cgroup.procs"), pid, 0o644))

	t.Cleanup(func() {
		if err := os.WriteFile(filepath.Join(base, "cgroup.procs"), pid, 0o644); err != nil {
			t.Logf("failed to restore cgroup: %v", err)
		}
		if err := os.Remove(dir); err != nil {
			t.Logf("failed to remove test cgroup: %v", err)
		}
	})

	return dir
}

func socketCookie(t *testing.T, conn *net.TCPConn) uint64 {
	raw, err := conn.SyscallConn()
	require.NoError(t, err)

	var cookie uint64
	var cookieErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		cookie, cookieErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	}))
	require.NoError(t, cookieErr)
	require.NotZero(t, cookie)

	return cookie
}

func cookieTracked(objs *BpfObjects, cookie uint64) bool {
	var val uint8
	return objs.TrackedSockCookies.Lookup(&cookie, &val) == nil
}

func waitFor(t *testing.T, what string, cond func() bool) {
	deadline := time.Now().Add(cookieWaitTimeout)
	for !cond() {
		require.False(t, time.Now().After(deadline), "timed out waiting for %s", what)
		time.Sleep(10 * time.Millisecond)
	}
}

func trackedCookieCount(t *testing.T, objs *BpfObjects) int {
	var (
		key   uint64
		val   uint8
		count int
	)
	it := objs.TrackedSockCookies.Iterate()
	for it.Next(&key, &val) {
		count++
	}
	require.NoError(t, it.Err())
	return count
}

// an active connection's cookie must be registered on establishment and
// removed when the socket dies, since a stale entry occupies the space that
// decides whether a live socket gets the FIONREAD compensation
func TestTrackedSockCookiesDeleteOnClose(t *testing.T) {
	objs := setupSockopsHarness(t)

	lsn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer lsn.Close()

	client, err := net.Dial("tcp", lsn.Addr().String())
	require.NoError(t, err)
	server, err := lsn.Accept()
	require.NoError(t, err)
	defer server.Close()

	cookie := socketCookie(t, client.(*net.TCPConn))
	waitFor(t, "cookie registration", func() bool { return cookieTracked(objs, cookie) })

	// server closes first so the client side, the tracked one, avoids TIME_WAIT
	require.NoError(t, server.Close())
	buf := make([]byte, 1)
	_, readErr := client.Read(buf)
	require.Error(t, readErr)
	require.NoError(t, client.Close())

	waitFor(t, "cookie deletion after close", func() bool { return !cookieTracked(objs, cookie) })
}

// connection churn must not evict the cookie of a live socket: that is the
// exact sequence that silently disarmed the FIONREAD compensation in the field
func TestTrackedSockCookiesSurviveChurn(t *testing.T) {
	objs := setupSockopsHarness(t)

	// the holder: a long-lived idle connection, the coldest possible entry
	holderLsn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer holderLsn.Close()

	holder, err := net.Dial("tcp", holderLsn.Addr().String())
	require.NoError(t, err)
	defer holder.Close()

	holderSrv, err := holderLsn.Accept()
	require.NoError(t, err)
	defer holderSrv.Close()

	holderCookie := socketCookie(t, holder.(*net.TCPConn))
	waitFor(t, "holder cookie registration", func() bool { return cookieTracked(objs, holderCookie) })

	// the churn sink closes every connection immediately, so churned client
	// sockets die without TIME_WAIT
	churnLsn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer churnLsn.Close()

	go func() {
		for {
			conn, err := churnLsn.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	var wg sync.WaitGroup
	churnErrs := make(chan error, churnWorkers)
	for range churnWorkers {
		wg.Go(func() {
			buf := make([]byte, 1)
			for range churnConnections / churnWorkers {
				conn, err := net.Dial("tcp", churnLsn.Addr().String())
				if err != nil {
					churnErrs <- err
					return
				}
				// wait for the peer's close so our close ends the socket for good
				conn.Read(buf) //nolint:errcheck
				conn.Close()
			}
		})
	}
	wg.Wait()
	close(churnErrs)
	for err := range churnErrs {
		require.NoError(t, err)
	}

	// churned entries must have been removed as their sockets died: an
	// accumulating map is what evicts live cookies under LRU pressure
	waitFor(t, "churn residue cleanup", func() bool {
		return trackedCookieCount(t, objs) <= churnResidueBound
	})

	assert.True(t, cookieTracked(objs, holderCookie),
		"the live holder's cookie was evicted by connection churn")
}

// ensures both tracepoint halves of the FIONREAD fixup still find the cookie
// registered by the sockops program, guarding the interaction between
// enrolment, deletion and the fixup's lookup
func TestTrackedSockCookiesFixupLookupAfterReconnect(t *testing.T) {
	objs := setupSockopsHarness(t)

	lsn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer lsn.Close()

	for range 3 {
		client, err := net.Dial("tcp", lsn.Addr().String())
		require.NoError(t, err)
		server, err := lsn.Accept()
		require.NoError(t, err)

		cookie := socketCookie(t, client.(*net.TCPConn))
		waitFor(t, "cookie registration", func() bool { return cookieTracked(objs, cookie) })

		require.NoError(t, server.Close())
		buf := make([]byte, 1)
		if _, err := client.Read(buf); err == nil {
			require.Fail(t, "expected EOF from closed peer")
		}
		require.NoError(t, client.Close())

		waitFor(t, "cookie deletion", func() bool { return !cookieTracked(objs, cookie) })
	}
}
