// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goabi

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractCompleteRuntimeABI(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "inspect")
	source := filepath.Join("..", "..", "configs", "offsets", "std_inspect.go")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", executable, source)
	cmd.Env = append(os.Environ(), "GOOS=linux")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))

	file, err := elf.Open(executable)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	data, err := file.DWARF()
	require.NoError(t, err)

	abi, err := Extract(data, "go1.27.0")
	require.NoError(t, err)
	requirements, err := Requirements("go1.27.0")
	require.NoError(t, err)
	assert.Len(t, abi.Facts(), len(requirements))
	require.NotNil(t, abi.TypeMetadata)
	assert.Equal(t, uint64(0), abi.TypeMetadata.ITabInterOffset)

	legacyABI, err := Extract(data, "go1.26.9")
	require.NoError(t, err)
	assert.Nil(t, legacyABI.TypeMetadata)
	assert.Len(t, legacyABI.Facts(), 6)
}

func TestStoreValueRejectsConflicts(t *testing.T) {
	values := map[string]uint64{"fact": 1}
	require.NoError(t, storeValue(values, "fact", 1))
	require.ErrorContains(t, storeValue(values, "fact", 2), "conflicting values")
}
