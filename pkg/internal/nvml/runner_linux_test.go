// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nvml

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/nvml/sample"
)

const testHelper = `#!/bin/sh
echo '{"devices":[{"uuid":"GPU-aaaa"}]}'
echo "interval $2" >&2
exit 3
`

// Runs a stand-in for the helper the way OBI runs the real one: from an
// in-memory file, with the host filesystem as its root.
func TestRunOnce(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing the root directory of the helper requires root")
	}

	original := embeddedHelper
	embeddedHelper = []byte(testHelper)
	t.Cleanup(func() { embeddedHelper = original })

	var samples []sample.Sample
	err := runOnce(t.Context(), RunnerConfig{Interval: 7 * time.Second, HostRoot: "/"}, func(s sample.Sample) {
		samples = append(samples, s)
	})

	require.Len(t, samples, 1)
	require.Len(t, samples[0].Devices, 1)
	assert.Equal(t, "GPU-aaaa", samples[0].Devices[0].UUID)

	// The exit status and the error output of the helper explain why it stopped.
	require.Error(t, err)
	require.ErrorContains(t, err, "exit status 3")
	require.ErrorContains(t, err, "interval 7s")
}

func TestRunOnceReportsMissingLibrary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing the root directory of the helper requires root")
	}

	original := embeddedHelper
	embeddedHelper = []byte("#!/bin/sh\nexit 2\n")
	t.Cleanup(func() { embeddedHelper = original })

	err := runOnce(t.Context(), RunnerConfig{Interval: time.Second, HostRoot: "/"}, func(sample.Sample) {})
	assert.True(t, noLibrary(err), "error: %v", err)
}
