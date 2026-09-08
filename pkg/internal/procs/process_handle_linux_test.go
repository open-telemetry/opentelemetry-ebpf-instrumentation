// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func fakeProcStat(startTime uint64) []byte {
	return []byte(fmt.Sprintf("1000 (java worker) S%s %d 0\n", strings.Repeat(" 0", 18), startTime))
}

func stubProcessHandleEnvironment(t *testing.T, root string, signal func(int, unix.Signal, *unix.Siginfo, int) error) {
	originalRoot := procRootPath
	originalSignal := pidfdSendSignal
	t.Cleanup(func() {
		procRootPath = originalRoot
		pidfdSendSignal = originalSignal
	})
	procRootPath = root
	pidfdSendSignal = signal
}

func TestOpenProcessHandleFailsClosedWithoutStableSignaling(t *testing.T) {
	const (
		pid       = app.PID(1000)
		startTime = uint64(4242)
	)
	root := t.TempDir()
	procDir := filepath.Join(root, "1000")
	require.NoError(t, os.Mkdir(procDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(procDir, "stat"), fakeProcStat(startTime), 0o644))

	stubProcessHandleEnvironment(t, root, func(int, unix.Signal, *unix.Siginfo, int) error {
		return unix.ENOSYS
	})

	handle, err := OpenProcessHandle(pid, startTime)

	require.Error(t, err)
	assert.Nil(t, handle)
	assert.ErrorIs(t, err, unix.ENOSYS)
}

func TestProcessHandleKeepsResourcesAndSignalsOnOriginalProcess(t *testing.T) {
	const (
		pid       = app.PID(1000)
		startTime = uint64(4242)
	)
	root := t.TempDir()
	procDir := filepath.Join(root, "1000")
	originalRoot := filepath.Join(procDir, "root")
	require.NoError(t, os.MkdirAll(filepath.Join(originalRoot, "tmp"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(procDir, "stat"), fakeProcStat(startTime), 0o644))

	var signalFDs []int
	stubProcessHandleEnvironment(t, root, func(fd int, _ unix.Signal, _ *unix.Siginfo, _ int) error {
		signalFDs = append(signalFDs, fd)
		return nil
	})

	handle, err := OpenProcessHandle(pid, startTime)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, handle.Close()) })

	oldProcDir := filepath.Join(root, "old-1000")
	require.NoError(t, os.Rename(procDir, oldProcDir))
	replacementRoot := filepath.Join(procDir, "root")
	require.NoError(t, os.MkdirAll(filepath.Join(replacementRoot, "tmp"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(procDir, "stat"), fakeProcStat(startTime+1), 0o644))

	rootFD, err := handle.Open("root", unix.O_PATH|unix.O_DIRECTORY)
	require.NoError(t, err)
	rootPath := fmt.Sprintf("/proc/self/fd/%d", rootFD.Fd())
	require.NoError(t, os.WriteFile(filepath.Join(rootPath, "tmp", "agent.jar"), []byte("agent"), 0o644))
	require.NoError(t, rootFD.Close())
	require.NoError(t, handle.SendSignal(unix.SIGQUIT))

	assert.FileExists(t, filepath.Join(oldProcDir, "root", "tmp", "agent.jar"))
	assert.NoFileExists(t, filepath.Join(replacementRoot, "tmp", "agent.jar"))
	require.Len(t, signalFDs, 2)
	assert.Equal(t, signalFDs[0], signalFDs[1], "signal must use the descriptor validated at capture")
}

func TestOpenProcessHandleRejectsReusedPID(t *testing.T) {
	const pid = app.PID(1000)
	root := t.TempDir()
	procDir := filepath.Join(root, "1000")
	require.NoError(t, os.Mkdir(procDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(procDir, "stat"), fakeProcStat(5353), 0o644))

	stubProcessHandleEnvironment(t, root, func(int, unix.Signal, *unix.Siginfo, int) error {
		return errors.New("stable signal check must not run after identity mismatch")
	})

	handle, err := OpenProcessHandle(pid, 4242)

	require.Error(t, err)
	assert.Nil(t, handle)
	assert.Contains(t, err.Error(), "was replaced before injection")
}
