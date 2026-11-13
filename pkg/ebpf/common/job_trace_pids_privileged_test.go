// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpfcommon

import (
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func TestJobTracePIDsFollowTheService(t *testing.T) {
	original := readNamespacePIDs
	t.Cleanup(func() { readNamespacePIDs = original })
	readNamespacePIDs = func(app.PID) ([]app.PID, error) { return []app.PID{1234, 70, 1}, nil }

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(BpfPidInfoT{})),
		ValueSize:  1,
		MaxEntries: 4,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.Close()) })

	var pids JobTracePIDs
	key := BpfPidInfoT{UserPid: 1, Ns: 42}
	var opted uint8

	require.NoError(t, pids.Write(m, 1234, 42, false))
	require.ErrorIs(t, m.Lookup(key, &opted), ebpf.ErrKeyNotExist, "a service that didn't opt in has no entry")

	require.NoError(t, pids.Write(m, 1234, 42, true))
	require.NoError(t, m.Lookup(key, &opted), "keyed by the innermost namespaced pid")
	require.Equal(t, uint8(1), opted)

	require.NoError(t, pids.Write(m, 1234, 42, false))
	require.ErrorIs(t, m.Lookup(key, &opted), ebpf.ErrKeyNotExist, "a service that opts out loses its entry")

	require.NoError(t, pids.Write(m, 1234, 42, true))
	require.NoError(t, pids.Delete(m, 1234))
	require.ErrorIs(t, m.Lookup(key, &opted), ebpf.ErrKeyNotExist, "an exited process loses its entry")
	require.Empty(t, pids.keys)
}
