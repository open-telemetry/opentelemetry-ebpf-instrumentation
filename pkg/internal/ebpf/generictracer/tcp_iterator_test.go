// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"maps"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestTCPIteratorConfigurationPreservesNetworkPrograms(t *testing.T) {
	for _, unsupported := range []bool{false, true} {
		t.Run(map[bool]string{false: "supported", true: "fallback"}[unsupported], func(t *testing.T) {
			spec, err := LoadBpf()
			require.NoError(t, err)
			original := maps.Clone(spec.Programs)
			tracer := &Tracer{log: tlog()}
			var supportErr error
			if unsupported {
				supportErr = ebpf.ErrNotSupported
			}
			require.NoError(t, tracer.configureTCPIterator(spec, supportErr))
			require.Len(t, spec.Programs, len(original))
			for name, prog := range original {
				if unsupported && name == "obi_iter_tcp" {
					continue
				}
				require.Same(t, prog, spec.Programs[name], "program %s must stay unchanged", name)
			}
			require.Equal(t, unsupported, tracer.listeningPortsFallback)
			if unsupported {
				require.Empty(t, tracer.Iters())
			}
		})
	}
}

func TestTCPIteratorProbeDoesNotHidePermissionErrors(t *testing.T) {
	for _, err := range []error{unix.EPERM, unix.EACCES} {
		require.ErrorIs(t, iteratorProbeError(err), err)
		require.NotErrorIs(t, iteratorProbeError(err), ebpf.ErrNotSupported)
		spec, loadErr := LoadBpf()
		require.NoError(t, loadErr)
		original := spec.Programs["obi_iter_tcp"]
		tracer := &Tracer{log: tlog()}
		require.ErrorIs(t, tracer.configureTCPIterator(spec, err), err)
		require.False(t, tracer.listeningPortsFallback)
		require.Same(t, original, spec.Programs["obi_iter_tcp"])
	}
}

func TestTCPIteratorFallbackMissingPID(t *testing.T) {
	ports, err := tcpListeningPorts(1 << 30)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Empty(t, ports)
}
