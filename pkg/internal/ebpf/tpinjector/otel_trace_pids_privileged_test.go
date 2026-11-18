// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector

import (
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func TestOTelTracePIDStates(t *testing.T) {
	spec, err := LoadBpf()
	require.NoError(t, err)
	mapSpec := spec.Maps["otel_traces_pids"]
	require.NotNil(t, mapSpec)
	require.Equal(t, otelPIDWords, mapSpec.MaxEntries)
	mapSpec.Pinning = ebpf.PinNone
	m, err := ebpf.NewMap(mapSpec)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.Close()) })

	var pids otelTracePIDs
	require.NoError(t, pids.set(m, 31, otelPIDNonExporter))
	require.NoError(t, pids.set(m, 32, otelPIDExporter))
	require.NoError(t, pids.set(m, 33, otelPIDExporter))
	require.True(t, pids.exporter(32))
	require.NoError(t, pids.set(m, 32, otelPIDNonExporter))
	require.False(t, pids.exporter(32))
	require.NoError(t, pids.set(m, 32, otelPIDUnknown))

	var states uint64
	require.NoError(t, m.Lookup(uint32(0), &states))
	require.Equal(t, otelPIDNonExporter<<(31*otelPIDBits), states)
	require.NoError(t, m.Lookup(uint32(1), &states))
	require.Equal(t, otelPIDExporter<<otelPIDBits, states,
		"forgetting one PID must preserve the neighboring classification")
	require.True(t, pids.exporter(33))
	require.False(t, pids.exporter(32))

	lastPID := app.PID(otelPIDWords)*otelPIDsPerWord - 1
	require.NoError(t, pids.set(m, lastPID, otelPIDExporter))
	require.True(t, pids.exporter(lastPID))
	require.Error(t, pids.set(m, lastPID+1, otelPIDExporter))
	require.False(t, pids.exporter(lastPID+1))

	var workers sync.WaitGroup
	errors := make(chan error, otelPIDsPerWord)
	for pid := range app.PID(otelPIDsPerWord) {
		workers.Go(func() { errors <- pids.set(m, pid, otelPIDExporter) })
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	require.NoError(t, m.Lookup(uint32(0), &states))
	require.Equal(t, uint64(0xaaaaaaaaaaaaaaaa), states,
		"concurrent marks must preserve all 32 exporter classifications")

	require.NoError(t, m.Close())
	require.Error(t, pids.set(m, 34, otelPIDExporter))
	require.False(t, pids.exporter(34), "failed writes must remain retryable")
}
