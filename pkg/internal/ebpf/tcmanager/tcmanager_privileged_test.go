// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tcmanager

import (
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTCXManagerAddRemove(t *testing.T) {
	progs := loadProgs(t)

	ifaceManager := NewInterfaceManager()
	tcx := NewTCXManager()
	tcx.SetInterfaceManager(ifaceManager)
	assert.NotNil(t, tcx)

	ctx := t.Context()

	ifaceManager.Start(ctx)

	test := func(progName string, prog *ebpf.Program, attachType AttachmentType) {
		tcx.AddProgram(progName, prog, attachType)

		assert.Eventually(t, func() bool {
			linked, err := isBpfProgLinked(progName)
			require.NoError(t, err)
			return linked
		}, 5*time.Second, 100*time.Millisecond)

		tcx.RemoveProgram(progName)

		prog.Close()

		assert.Eventually(t, func() bool {
			linked, err := isBpfProgLinked(progName)
			require.NoError(t, err)
			return !linked
		}, 5*time.Second, 100*time.Millisecond)

		loaded, err := isBpfProgLoaded(progName)
		require.NoError(t, err)
		assert.False(t, loaded)
	}

	test("obi_ingress", progs.Ingress, AttachmentIngress)
	test("obi_egress", progs.Egress, AttachmentEgress)
}

func TestNetlinkManagerAddRemove(t *testing.T) {
	progs := loadProgs(t)

	ifaceManager := NewInterfaceManager()
	tc := NewNetlinkManager()
	tc.SetInterfaceManager(ifaceManager)
	assert.NotNil(t, tc)

	netManager := tc.(*netlinkManager)

	ctx := t.Context()

	ifaceManager.Start(ctx)

	test := func(progName string, prog *ebpf.Program, attachType AttachmentType) {
		tc.AddProgram(progName, prog, attachType)

		// wait for links to come up
		assert.Eventually(t, func() bool {
			linked, err := isNetlinkFilterPresent(progName, attachType, netManager)
			require.NoError(t, err)
			return linked
		}, 5*time.Second, 100*time.Millisecond)
		tc.RemoveProgram(progName)

		prog.Close()

		assert.Eventually(t, func() bool {
			linked, err := isNetlinkFilterPresent(progName, attachType, netManager)
			require.NoError(t, err)
			return !linked
		}, 5*time.Second, 100*time.Millisecond)

		assert.Eventually(t, func() bool {
			loaded, err := isBpfProgLoaded(progName)
			require.NoError(t, err)
			return !loaded
		}, 5*time.Second, 100*time.Millisecond)
	}

	test("obi_ingress", progs.Ingress, AttachmentIngress)
	test("obi_egress", progs.Egress, AttachmentEgress)

	netManager.Shutdown()
}
