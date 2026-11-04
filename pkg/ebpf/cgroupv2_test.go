// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"testing"

	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/require"
)

func TestResolveCgroupV2RejectsNonCgroup2Path(t *testing.T) {
	r := resolveCgroupV2(t.TempDir())

	require.Error(t, r.err)
	require.Empty(t, r.path)
}

func TestResolveCgroupV2UsesConfiguredMount(t *testing.T) {
	const hostRoot = "/sys/fs/cgroup"
	if !isCgroup2Mount(hostRoot) {
		t.Skipf("%s is not a cgroupv2 mount", hostRoot)
	}

	r := resolveCgroupV2(hostRoot)

	require.NoError(t, r.err)
	require.Equal(t, hostRoot, r.path)
}

func TestCgroupV2MountDiscoveryRejectsSubtrees(t *testing.T) {
	self, err := procfs.Self()
	require.NoError(t, err)
	mounts, err := self.MountInfo()
	require.NoError(t, err)
	root := cgroupV2RootFromMounts(mounts)
	if root == "" {
		t.Skip("no cgroup2 root mounted")
	}
	cases := []*procfs.MountInfo{
		{FSType: "cgroup2", Root: "/other-cgroup", MountPoint: root},
		{FSType: "tmpfs", Root: "/", MountPoint: root},
		{FSType: "cgroup2", Root: "/", MountPoint: t.TempDir()},
	}
	require.Empty(t, cgroupV2RootFromMounts(cases))
	cases = append(cases, &procfs.MountInfo{FSType: "cgroup2", Root: "/", MountPoint: root})
	require.Equal(t, root, cgroupV2RootFromMounts(cases))
}
