// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

const runtimeMetricsGo125BuilderImage = "golang:1.25.11@sha256:f188e8c16ea47a8b22d2bdcf6d9bcd07b63ea7876c199749c07bf31e0ab33bad"

type runtimeMetricsPromCompatibilityConfig struct {
	goVersion    string
	hostPort     string
	builderImage string
	dockerfile   string
	test         func(*testing.T)
}

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
	t.Run("Go goroutine count suppression above processor limit", testRuntimeGoroutineCountSuppressedAboveProcessorLimit)
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
	runRuntimeMetricsPromCompatibility(t, runtimeMetricsPromCompatibilityConfig{
		goVersion:  "1.17",
		hostPort:   runtimeMetricsGo117HostPort,
		dockerfile: "./internal/test/integration/components/go-runtime-metrics-server/Dockerfile_1.17",
		test:       testRuntimeMetricsGo117,
	})
}

func TestRuntimeMetricsPromGo125(t *testing.T) {
	runRuntimeMetricsPromCompatibility(t, runtimeMetricsPromCompatibilityConfig{
		goVersion:    "1.25",
		hostPort:     runtimeMetricsGo125HostPort,
		builderImage: runtimeMetricsGo125BuilderImage,
		test:         testRuntimeGoroutineCountGo125,
	})
}

func runRuntimeMetricsPromCompatibility(t *testing.T, cfg runtimeMetricsPromCompatibilityConfig) {
	versionSlug := strings.ReplaceAll(cfg.goVersion, ".", "-")
	compose, err := docker.ComposeSuite(
		"docker-compose-go-runtime-metrics.yml",
		path.Join(pathOutput, "test-suite-runtime-metrics-prom-go-"+versionSlug+".log"),
	)
	require.NoError(t, err)
	compose.Env = append(compose.Env,
		`TEST_SERVICE_PORTS=`+cfg.hostPort+`:8080`,
		`INSTRUMENTER_CONFIG_SUFFIX=-prom`,
		`PROM_CONFIG_SUFFIX=`,
		`RUNTIME_METRICS_TESTSERVER_IMAGE=hatest-testserver-go-runtime-metrics-`+versionSlug,
	)
	if cfg.builderImage != "" {
		compose.Env = append(
			compose.Env,
			`RUNTIME_METRICS_TESTSERVER_GO_IMAGE=`+cfg.builderImage,
		)
	}
	if cfg.dockerfile != "" {
		compose.Env = append(
			compose.Env,
			`RUNTIME_METRICS_TESTSERVER_DOCKERFILE=`+cfg.dockerfile,
		)
	}

	require.NoError(t, compose.Up())
	t.Run("Go "+cfg.goVersion+" runtime metrics with Prometheus export", cfg.test)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}
