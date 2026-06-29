// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestRuntimeMetrics(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-runtime-metrics.yml", path.Join(pathOutput, "test-suite-runtime-metrics.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `TEST_SERVICE_PORTS=`+runtimeMetricsHostPort+`:8080`)
	require.NoError(t, compose.Up())
	t.Run("Go runtime metrics", testRuntimeMetricsGo)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}
