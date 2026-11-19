// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
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

func TestAttachCgroupSockOpsUsesAutomaticHierarchy(t *testing.T) {
	previous := cgroupV2Once
	cgroupV2Once = func() cgroupV2Result { return cgroupV2Result{err: errNoCgroupV2} }
	t.Cleanup(func() { cgroupV2Once = previous })

	attached, err := AttachCgroupSockOps(nil, ebpf.AttachCGroupSockOps)
	require.ErrorIs(t, err, errNoCgroupV2)
	require.Nil(t, attached)
}
