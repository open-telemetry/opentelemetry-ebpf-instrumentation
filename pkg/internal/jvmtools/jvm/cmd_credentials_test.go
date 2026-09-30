// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package jvm

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/helpers"
)

const nobodyID = 65534

// switching to a JVM's credentials must not strip the rest of the agent of its privileges
func TestCredentialSwitchChangesOnlyTheCallingThread(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing credentials needs root")
	}

	switched := make(chan error, 1)
	release := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		runOnDisposableThread(func() {
			if err := setEGID(nobodyID); err != nil {
				switched <- err
				return
			}
			switched <- setEUID(nobodyID)
			<-release
		})
	}()
	t.Cleanup(func() {
		close(release)
		<-finished
	})
	require.NoError(t, <-switched)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	require.Equal(t, 0, syscall.Geteuid())
	require.Equal(t, 0, syscall.Getegid())
	caps, err := helpers.GetCurrentProcCapabilities()
	require.NoError(t, err)
	require.True(t, caps.Has(unix.CAP_SYS_ADMIN))
	require.Equal(t, 1, threadsWithEffectiveIDs(t, nobodyID), "only the switched thread may run as the JVM user")
}

// the runtime parks the main thread instead of destroying it, so it must never be the one that
// joins a JVM's namespaces and credentials
func TestDisposableThreadIsNeverTheMainThread(t *testing.T) {
	for range 200 {
		var onMain bool
		runOnDisposableThread(func() { onMain = unix.Gettid() == unix.Getpid() })
		require.False(t, onMain)
	}
}

func threadsWithEffectiveIDs(t *testing.T, id int) int {
	t.Helper()

	tasks, err := os.ReadDir("/proc/self/task")
	require.NoError(t, err)

	want := strconv.Itoa(id)
	count := 0
	for _, task := range tasks {
		status, err := os.ReadFile("/proc/self/task/" + task.Name() + "/status")
		if err != nil {
			continue
		}
		uid, gid := "", ""
		for line := range strings.SplitSeq(string(status), "\n") {
			fields := strings.Fields(line)
			switch {
			case len(fields) > 2 && fields[0] == "Uid:":
				uid = fields[2]
			case len(fields) > 2 && fields[0] == "Gid:":
				gid = fields[2]
			}
		}
		if uid == want && gid == want {
			count++
		}
	}

	return count
}
