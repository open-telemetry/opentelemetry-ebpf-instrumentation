// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package discover

import (
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIdentityStableProcessHandleFailsAfterClose(t *testing.T) {
	handle, err := openIdentityStableProcessHandle(os.Getpid())
	require.NoError(t, err)
	require.NoError(t, handle.Signal(0))
	require.NoError(t, handle.Close())

	require.ErrorContains(t, handle.Signal(0), "process handle is closed")
	require.NoError(t, handle.Close())
}

func TestIdentityStableProcessHandleRejectsExitedProcess(t *testing.T) {
	cmd := exec.Command("sh", "-c", "read value; exit 0")
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	handle, err := openIdentityStableProcessHandle(cmd.Process.Pid)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, handle.Close()) })

	require.NoError(t, stdin.Close())
	require.NoError(t, cmd.Wait())
	require.ErrorIs(t, handle.Signal(0), syscall.ESRCH)
}
