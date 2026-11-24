// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfconvenience

import (
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDrainPinnedTraceContextMapHandlesEmptyAndMissingPaths(t *testing.T) {
	drainOnce = sync.Once{}
	t.Cleanup(func() { drainOnce = sync.Once{} })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	require.NotPanics(t, func() {
		DrainPinnedTraceContextMap[[24]byte](log, "")
	})
	require.NotPanics(t, func() {
		DrainPinnedTraceContextMap[[24]byte](log, t.TempDir())
	})
}
