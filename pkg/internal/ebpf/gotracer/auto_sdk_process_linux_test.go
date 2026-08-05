// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gotracer

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

func TestNativeGoAutoSDKProcessSessionReadsBoundStartTime(t *testing.T) {
	pid := os.Getpid()
	processRootFD, err := unix.Open(
		fmt.Sprintf("/proc/%d", pid),
		unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC,
		0,
	)
	require.NoError(t, err)
	processRoot := os.NewFile(uintptr(processRootFD), "process-root")
	require.NotNil(t, processRoot)
	executableInfo, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	require.NoError(t, err)
	statInfo, ok := executableInfo.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	fileInfo := exec.New(exec.Init{
		Pid:         999999999,
		Dev:         statInfo.Dev,
		Ino:         statInfo.Ino,
		ProcessRoot: processRoot,
	})
	root := fileInfo.TakeProcessRoot()
	require.Same(t, processRoot, root)

	session, err := (nativeGoAutoSDKProcessAccess{}).Open(root, fileInfo)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, session.Close())
	})
	require.NoError(t, root.Close())

	startTime, err := session.StartTime()
	require.NoError(t, err)
	assert.NotZero(t, startTime)
}

func TestGoAutoSDKStartTimeFromStatHandlesClosingParenInName(t *testing.T) {
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "S"
	fields[19] = "123"
	stat := "42 (worker ) name) " + strings.Join(fields, " ")

	startTime, err := goAutoSDKStartTimeFromStat([]byte(stat))

	require.NoError(t, err)
	assert.Equal(t, 123*10*time.Millisecond, time.Duration(startTime))
}

func TestGoAutoSDKProcessMemoryResultClassification(t *testing.T) {
	t.Run("zero byte read is terminal", func(t *testing.T) {
		err := goAutoSDKProcessReadResult(0, 1, io.EOF)
		assert.ErrorIs(t, err, errGoAutoSDKProcessMemoryGone)
	})
	t.Run("zero byte write is terminal", func(t *testing.T) {
		err := goAutoSDKProcessWriteResult(0, 1, io.ErrUnexpectedEOF)
		assert.ErrorIs(t, err, errGoAutoSDKProcessMemoryGone)
	})
	t.Run("EIO read remains retryable", func(t *testing.T) {
		err := goAutoSDKProcessReadResult(0, 1, unix.EIO)
		require.ErrorIs(t, err, unix.EIO)
		assert.NotErrorIs(t, err, errGoAutoSDKProcessMemoryGone)
	})
	t.Run("EFAULT write remains retryable", func(t *testing.T) {
		err := goAutoSDKProcessWriteResult(0, 1, unix.EFAULT)
		require.ErrorIs(t, err, unix.EFAULT)
		assert.NotErrorIs(t, err, errGoAutoSDKProcessMemoryGone)
	})
}
