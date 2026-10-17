// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func TestReadProcessCPUTimes(t *testing.T) {
	pid := app.PID(os.Getpid())
	startTime, err := procs.StartTime(pid)
	require.NoError(t, err)
	process, err := procs.OpenProcessHandle(pid, startTime)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, process.Close()) })

	// Accumulate enough CPU to distinguish seconds from raw clock ticks.
	deadline := time.Now().Add(30 * time.Millisecond)
	for time.Now().Before(deadline) {
	}
	var before, after unix.Rusage
	require.NoError(t, unix.Getrusage(unix.RUSAGE_SELF, &before))
	user, system, err := readProcessCPUTimes(process)
	require.NoError(t, err)
	require.NoError(t, unix.Getrusage(unix.RUSAGE_SELF, &after))
	for _, sample := range []struct {
		value  float64
		before unix.Timeval
		after  unix.Timeval
	}{
		{user, before.Utime, after.Utime},
		{system, before.Stime, after.Stime},
	} {
		// proc stat exposes whole ticks; getrusage has finer precision.
		require.GreaterOrEqual(t, sample.value, float64(sample.before.Nano())/1e9-0.02)
		require.LessOrEqual(t, sample.value, float64(sample.after.Nano())/1e9+0.02)
	}
	require.Positive(t, user+system)
	require.NoError(t, process.Close())
	user, system, err = readProcessCPUTimes(process)
	require.Error(t, err)
	require.Zero(t, user)
	require.Zero(t, system)
}
