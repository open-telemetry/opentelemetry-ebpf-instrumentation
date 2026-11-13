// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"log/slog"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
)

func TestFilter_OtherKnownPidsNamespaceOrder(t *testing.T) {
	const namespace = 42
	want := []app.PID{120, 900, 1}
	original := readNamespacePIDs
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		require.Equal(t, want[0], pid)
		return slices.Clone(want), nil
	}
	t.Cleanup(func() { readNamespacePIDs = original })

	pf := NewPIDsFilter(&services.DiscoveryConfig{}, slog.Default(), nil)
	pf.AllowPID(want[0], namespace, exec.New(exec.Init{Pid: want[0], Ns: namespace}), PIDTypeKProbes)

	for _, pid := range want {
		info, ok := pf.current[namespace][pid]
		require.True(t, ok)
		require.Equal(t, want, info.otherKnownPids, "namespace order must be preserved for PID alias %d", pid)
	}
}
