// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package netns

import (
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// spawnInNewNetNS starts a process in a fresh network namespace and returns its pid.
func spawnInNewNetNS(t *testing.T) int {
	t.Helper()

	cmd := exec.Command("/bin/sleep", "600")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	require.NoError(t, cmd.Start(), "cannot create a network namespace, test needs CAP_SYS_ADMIN")

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	return cmd.Process.Pid
}

func TestWithNetNSEntersAndRestores(t *testing.T) {
	outer, err := os.Readlink(selfNetNS)
	require.NoError(t, err)

	pid := spawnInNewNetNS(t)
	expected, err := os.Readlink(netNSPath(pid))
	require.NoError(t, err)
	require.NotEqual(t, outer, expected, "the child must be in a different namespace")

	var observed string
	require.NoError(t, WithNetNS(pid, func() error {
		var readErr error
		observed, readErr = os.Readlink(selfNetNS)
		return readErr
	}))

	assert.Equal(t, expected, observed, "fn must run inside the target namespace")

	after, err := os.Readlink(selfNetNS)
	require.NoError(t, err)
	assert.Equal(t, outer, after, "the calling thread must be back in its own namespace")
}

// A fresh network namespace has only loopback. Netlink binds to the namespace when the socket
// is created, so this distinguishes a real switch from a readlink that merely looks different.
// Note sysfs would not: /sys/class/net keeps the view of whichever namespace mounted it.
func TestWithNetNSSwitchIsObservableThroughNetlink(t *testing.T) {
	outerLinks, err := netlink.LinkList()
	require.NoError(t, err)
	require.Greater(t, len(outerLinks), 1, "host namespace is expected to have more than lo")

	pid := spawnInNewNetNS(t)

	var innerNames []string
	require.NoError(t, WithNetNS(pid, func() error {
		links, listErr := netlink.LinkList()
		if listErr != nil {
			return listErr
		}
		for _, l := range links {
			innerNames = append(innerNames, l.Attrs().Name)
		}
		return nil
	}))

	assert.Equal(t, []string{"lo"}, innerNames, "a fresh namespace has only loopback")

	afterLinks, err := netlink.LinkList()
	require.NoError(t, err)
	assert.Len(t, afterLinks, len(outerLinks), "caller must see its own links again")
}

// The restore must survive fn returning an error, otherwise a failing iterator would strand
// the thread in the target namespace.
func TestWithNetNSRestoresAfterFnError(t *testing.T) {
	outer, err := os.Readlink(selfNetNS)
	require.NoError(t, err)

	pid := spawnInNewNetNS(t)
	sentinel := os.ErrInvalid
	require.ErrorIs(t, WithNetNS(pid, func() error { return sentinel }), sentinel)

	after, err := os.Readlink(selfNetNS)
	require.NoError(t, err)
	assert.Equal(t, outer, after)
}

// Repeated switches must not accumulate threads that are still in the target namespace: a
// polluted thread would be handed to an unrelated goroutine by the scheduler.
func TestWithNetNSDoesNotPolluteThreadPool(t *testing.T) {
	outer, err := os.Readlink(selfNetNS)
	require.NoError(t, err)

	pid := spawnInNewNetNS(t)
	for range 25 {
		require.NoError(t, WithNetNS(pid, func() error { return nil }))
	}

	// sample many threads; each goroutine pins itself so the read is per-thread
	const samples = 64
	var wg sync.WaitGroup
	seen := make([]string, samples)
	for i := range samples {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			link, readErr := os.Readlink(selfNetNS)
			if readErr != nil {
				seen[i] = readErr.Error()
				return
			}
			seen[i] = link
		}()
	}
	wg.Wait()

	for i, ns := range seen {
		assert.Equal(t, outer, ns, "thread sample %d is in the wrong namespace", i)
	}
}

// The saved descriptor pins the original namespace, so the restore must hold even if fn moves
// the thread somewhere else entirely.
func TestWithNetNSRestoresWhenFnChangesNamespace(t *testing.T) {
	outer, err := os.Readlink(selfNetNS)
	require.NoError(t, err)

	pid := spawnInNewNetNS(t)
	require.NoError(t, WithNetNS(pid, func() error {
		return unix.Unshare(unix.CLONE_NEWNET)
	}))

	after, err := os.Readlink(selfNetNS)
	require.NoError(t, err)
	assert.Equal(t, outer, after, "restore must survive fn unsharing the namespace")
}

func TestWithNetNSConcurrentSwitches(t *testing.T) {
	outer, err := os.Readlink(selfNetNS)
	require.NoError(t, err)

	pids := make([]int, 4)
	for i := range pids {
		pids[i] = spawnInNewNetNS(t)
	}

	var wg sync.WaitGroup
	errs := make([]error, len(pids)*4)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pid := pids[i%len(pids)]
			expected, readErr := os.Readlink(netNSPath(pid))
			if readErr != nil {
				errs[i] = readErr
				return
			}
			errs[i] = WithNetNS(pid, func() error {
				got, e := os.Readlink(selfNetNS)
				if e != nil {
					return e
				}
				if got != expected {
					return os.ErrClosed // stand-in: landed in the wrong namespace
				}
				return nil
			})
		}()
	}
	wg.Wait()

	for i, e := range errs {
		require.NoError(t, e, "concurrent switch %d", i)
	}

	after, err := os.Readlink(selfNetNS)
	require.NoError(t, err)
	assert.Equal(t, outer, after)
}
