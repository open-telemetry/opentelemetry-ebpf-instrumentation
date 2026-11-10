// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpfcommon

import (
	"os"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
)

func TestPIDSamplersRemoveNamespaceKeysAfterExit(t *testing.T) {
	original := readNamespacePIDs
	t.Cleanup(func() { readNamespacePIDs = original })
	readNamespacePIDs = func(app.PID) ([]app.PID, error) { return []app.PID{1234, 70, 1}, nil }

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(BpfPidInfoT{})),
		ValueSize:  uint32(unsafe.Sizeof(BpfSamplerT{})),
		MaxEntries: 4,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.Close()) })

	var samplers PIDSamplers
	cfg := &services.SamplerConfig{Name: services.SamplerAlwaysOff}
	require.NoError(t, samplers.Write(m, 1234, 42, cfg, nil))
	var sampler BpfSamplerT
	oldKey := BpfPidInfoT{UserPid: 1, Ns: 42}
	require.NoError(t, m.Lookup(oldKey, &sampler))
	require.Zero(t, sampler.Threshold)

	require.NoError(t, samplers.Write(m, 1234, 43, cfg, nil))
	require.ErrorIs(t, m.Lookup(oldKey, &sampler), ebpf.ErrKeyNotExist)
	key := BpfPidInfoT{UserPid: 1, Ns: 43}
	require.NoError(t, m.Lookup(key, &sampler))

	readNamespacePIDs = func(app.PID) ([]app.PID, error) { return nil, os.ErrNotExist }
	require.NoError(t, samplers.Delete(m, 1234))
	require.ErrorIs(t, m.Lookup(key, &sampler), ebpf.ErrKeyNotExist)
	require.Empty(t, samplers.keys)
	require.NoError(t, samplers.Delete(m, 1234))

	require.NoError(t, samplers.Write(m, 1234, 43, nil, nil))
}
