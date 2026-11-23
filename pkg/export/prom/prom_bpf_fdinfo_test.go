// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
)

func TestOwnedProgramIDs(t *testing.T) {
	fdinfoDir := t.TempDir()
	writeFDInfo(t, fdinfoDir, map[string]string{
		"0": "pos:\t0\nflags:\t02\nmnt_id:\t28\nino:\t3\n",
		"3": "pos:\t0\nflags:\t02000002\nprog_type:\t2\nprog_tag:\tf55f8bd0a1c6b62a\n" +
			"memlock:\t4096\nprog_id:\t33653\nrun_time_ns:\t0\nrun_cnt:\t0\n",
		"4": "pos:\t0\nflags:\t02000002\nmap_type:\t9\nkey_size:\t8\nvalue_size:\t16\n" +
			"max_entries:\t1000\nmemlock:\t86016\nmap_id:\t512\n",
		"5": "pos:\t0\nflags:\t02000000\nlink_type:\tperf\nlink_id:\t7\nprog_tag:\tf55f8bd0a1c6b62a\nprog_id:\t33653\n",
		"6": "pos:\t0\nflags:\t02000000\nlink_type:\titer\nlink_id:\t8\nprog_tag:\t1a2b3c4d5e6f7a8b\nprog_id:\t41\n",
		"7": "pos:\t0\nflags:\t02000002\nprog_id:\tnot-a-number\n",
	})

	ids, err := ownedProgramIDs(fdinfoDir)

	require.NoError(t, err)
	require.Equal(t, []ebpf.ProgramID{41, 33653}, ids)
}

func TestOwnedProgramIDsWithoutPrograms(t *testing.T) {
	fdinfoDir := t.TempDir()
	writeFDInfo(t, fdinfoDir, map[string]string{
		"0": "pos:\t0\nflags:\t02\nmnt_id:\t28\nino:\t3\n",
	})

	ids, err := ownedProgramIDs(fdinfoDir)

	require.NoError(t, err)
	require.Empty(t, ids)
}

func TestOwnedProgramIDsMissingDir(t *testing.T) {
	_, err := ownedProgramIDs(filepath.Join(t.TempDir(), "missing"))

	require.Error(t, err)
}

func TestOwnedProgramIDsSkipsClosedDescriptors(t *testing.T) {
	fdinfoDir := t.TempDir()
	writeFDInfo(t, fdinfoDir, map[string]string{
		"3": "pos:\t0\nflags:\t02000002\nprog_id:\t12\n",
	})
	require.NoError(t, os.Symlink(filepath.Join(fdinfoDir, "closed"), filepath.Join(fdinfoDir, "4")))

	ids, err := ownedProgramIDs(fdinfoDir)

	require.NoError(t, err)
	require.Equal(t, []ebpf.ProgramID{12}, ids)
}

func TestOwnedProgramIDsContinuesPastUnreadableDescriptor(t *testing.T) {
	fdinfoDir := t.TempDir()
	writeFDInfo(t, fdinfoDir, map[string]string{
		"3": "pos:\t0\nflags:\t02000002\nprog_id:\t12\n",
		"5": "pos:\t0\nflags:\t02000002\nprog_id:\t14\n",
	})
	require.NoError(t, os.Mkdir(filepath.Join(fdinfoDir, "4"), 0o700))

	ids, err := ownedProgramIDs(fdinfoDir)

	require.Error(t, err)
	require.Equal(t, []ebpf.ProgramID{12, 14}, ids)
}

func writeFDInfo(t *testing.T, dir string, files map[string]string) {
	t.Helper()

	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
}
