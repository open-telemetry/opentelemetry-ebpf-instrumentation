// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build privileged_tests

package ebpfcommon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setNotReadable(t *testing.T, path string) {
	err := os.Chmod(path, 0o00)
	require.NoError(t, err)
}

func TestLockdownParsing_Privileged(t *testing.T) {
	noFile, err := os.CreateTemp(t.TempDir(), "not_existent_fake_lockdown")
	require.NoError(t, err)
	notPath, err := filepath.Abs(noFile.Name())
	require.NoError(t, err)
	noFile.Close()
	os.Remove(noFile.Name())

	// Setup for testing file that doesn't exist
	lockdownPath = notPath
	assert.Equal(t, KernelLockdownNone, KernelLockdownMode())

	tempFile, err := os.CreateTemp(t.TempDir(), "fake_lockdown")
	require.NoError(t, err)
	path, err := filepath.Abs(tempFile.Name())
	require.NoError(t, err)
	tempFile.Close()

	defer os.Remove(tempFile.Name())
	// Setup for testing
	lockdownPath = path

	setIntegrity(t, path, "[none] integrity confidentiality\n")
	setNotReadable(t, path)
	assert.Equal(t, KernelLockdownIntegrity, KernelLockdownMode())
}
