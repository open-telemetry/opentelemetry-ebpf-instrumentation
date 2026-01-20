// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCMDLineForPID(t *testing.T) {
	t.Run("current process", func(t *testing.T) {
		pid := int32(os.Getpid())
		executable, args, err := CMDLineForPID(pid)

		require.NoError(t, err)
		assert.NotEmpty(t, executable)
		assert.NotEmpty(t, args)
		// Executable should be the test binary or go test command
		assert.Contains(t, executable, "test")
	})

	t.Run("init process", func(t *testing.T) {
		// PID 1 should always exist
		executable, args, err := CMDLineForPID(1)

		require.NoError(t, err)
		assert.NotEmpty(t, executable)
		// args can be empty or non-empty depending on init system
		assert.NotNil(t, args)
	})

	t.Run("non-existent process", func(t *testing.T) {
		_, _, err := CMDLineForPID(-1)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read")
	})
}

func TestCMDLineForPID_ParseNullSeparated(t *testing.T) {
	// Create a temporary proc-like structure for testing
	tmpDir := t.TempDir()
	fakePID := int32(12345)

	procDir := filepath.Join(tmpDir, "proc", strconv.Itoa(int(fakePID)))
	err := os.MkdirAll(procDir, 0o755)
	require.NoError(t, err)

	cmdlinePath := filepath.Join(procDir, "cmdline")

	t.Run("null-separated arguments", func(t *testing.T) {
		// Write cmdline with null separators
		cmdlineData := []byte("/usr/bin/test\x00-arg1\x00value1\x00-arg2\x00value2\x00")
		err := os.WriteFile(cmdlinePath, cmdlineData, 0o644)
		require.NoError(t, err)

		exec, args, err := cmdLineForPath(cmdlinePath)
		require.NoError(t, err)
		assert.Equal(t, "/usr/bin/test", exec)
		assert.Equal(t, []string{"-arg1", "value1", "-arg2", "value2"}, args)

		cmdlineData = []byte("")
		err = os.WriteFile(cmdlinePath, cmdlineData, 0o644)
		require.NoError(t, err)

		_, _, err = cmdLineForPath(cmdlinePath)
		require.Error(t, err)

		cmdlineData = []byte("\x00")
		err = os.WriteFile(cmdlinePath, cmdlineData, 0o644)
		require.NoError(t, err)

		_, _, err = cmdLineForPath(cmdlinePath)
		assert.Error(t, err)
	})
}

func TestCWDForPID(t *testing.T) {
	t.Run("current process", func(t *testing.T) {
		pid := int32(os.Getpid())
		cwd, err := CWDForPID(pid)

		require.NoError(t, err)
		assert.NotEmpty(t, cwd)

		// Verify the directory actually exists
		info, err := os.Stat(cwd)
		require.NoError(t, err)
		assert.True(t, info.IsDir())

		// Verify it's an absolute path
		assert.True(t, filepath.IsAbs(cwd))

		// Compare with os.Getwd()
		expectedCwd, err := os.Getwd()
		require.NoError(t, err)
		assert.Equal(t, expectedCwd, cwd)
	})

	t.Run("non-existent process", func(t *testing.T) {
		_, err := CWDForPID(-1)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read symlink")
	})
}

func TestCMDLineAndCWD_Together(t *testing.T) {
	t.Run("current process info", func(t *testing.T) {
		pid := int32(os.Getpid())

		executable, args, err := CMDLineForPID(pid)
		require.NoError(t, err)

		cwd, err := CWDForPID(pid)
		require.NoError(t, err)

		// Both should return valid data
		assert.NotEmpty(t, executable)
		assert.NotNil(t, args)
		assert.NotEmpty(t, cwd)

		// CWD should be absolute
		assert.True(t, filepath.IsAbs(cwd))
	})
}

func TestKernelHasSymbol(t *testing.T) {
	found, err := KernelHasSymbol(KSymTCPSendmsg)
	require.NoError(t, err)
	assert.True(t, found, "expected tcp_sendmsg to be present in kernel symbols")

	found, err = KernelHasSymbol(KSymTestDummy)
	require.NoError(t, err)
	assert.False(t, found, "expected test_dummy to be absent in kernel symbols")
}
