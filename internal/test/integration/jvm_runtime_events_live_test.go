// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestJVMRuntimeEventsLive(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-jvm-runtime-events-live.yml", path.Join(pathOutput, "test-suite-jvm-runtime-events-live.log"))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, compose.Close())
	})

	require.NoError(t, compose.Run("obi"))
}
