// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestRuntimeMetricsProm(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-runtime-metrics.yml", path.Join(pathOutput, "test-suite-runtime-metrics-prom.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env,
		`TEST_SERVICE_PORTS=`+runtimeMetricsHostPort+`:8080`,
		`INSTRUMENTER_CONFIG_SUFFIX=-prom`,
		`PROM_CONFIG_SUFFIX=`,
	)
	require.NoError(t, compose.Up())
	t.Run("Go runtime metrics with Prometheus export", testRuntimeMetricsGo)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestRuntimeMetricsOTel(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-runtime-metrics.yml", path.Join(pathOutput, "test-suite-runtime-metrics-otel.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env,
		`TEST_SERVICE_PORTS=`+runtimeMetricsHostPort+`:8080`,
		`INSTRUMENTER_CONFIG_SUFFIX=-otel`,
		`PROM_CONFIG_SUFFIX=-otel`,
	)
	require.NoError(t, compose.Up())
	t.Run("Go runtime metrics with OTel export", testRuntimeMetricsGo)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

func TestRuntimeMetricsPromGo117(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-runtime-metrics.yml", path.Join(pathOutput, "test-suite-runtime-metrics-prom-go-1-17.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env,
		`TEST_SERVICE_PORTS=`+runtimeMetricsGo117HostPort+`:8080`,
		`INSTRUMENTER_CONFIG_SUFFIX=-prom`,
		`PROM_CONFIG_SUFFIX=`,
		`RUNTIME_METRICS_TESTSERVER_DOCKERFILE=./internal/test/integration/components/go-runtime-metrics-server/Dockerfile_1.17`,
		`RUNTIME_METRICS_TESTSERVER_IMAGE=hatest-testserver-go-runtime-metrics-1-17`,
	)
	require.NoError(t, compose.Up())
	t.Run("Go 1.17 runtime metrics with Prometheus export", testRuntimeMetricsGo117)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}
