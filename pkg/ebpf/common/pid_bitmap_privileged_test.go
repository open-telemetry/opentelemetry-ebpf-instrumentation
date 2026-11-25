// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpfcommon

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func TestPIDBitmapSet(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: PIDBitmapWords,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.Close()) })

	var bitmap PIDBitmap
	require.NoError(t, bitmap.Set(m, 65, true))
	require.NoError(t, bitmap.Set(m, 66, true))
	require.NoError(t, bitmap.Set(m, 65, false))
	var bits uint64
	require.NoError(t, m.Lookup(uint32(1), &bits))
	require.Equal(t, uint64(1)<<2, bits)
	require.Error(t, bitmap.Set(m, app.PID(PIDBitmapWords)*64, true))

	require.NoError(t, m.Close())
	require.Error(t, bitmap.Set(m, 67, true))
	require.False(t, bitmap.contains(67), "failed updates must remain retryable")
}
