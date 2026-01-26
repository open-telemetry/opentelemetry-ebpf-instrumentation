// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"fmt"
	"net/http"
	"path"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dockercompose "go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	"go.opentelemetry.io/obi/internal/test/tools"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

func TestInstrumentationErrors(t *testing.T) {
	compose, err := dockercompose.ComposeSuite("docker-compose-error-test.yml", path.Join(pathOutput, "test-suite-instrumentation-errors.log"))
	require.NoError(t, err)

	// Run OBI without privileged mode to force instrumentation errors
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`)
	require.NoError(t, compose.Up())

	t.Run("Instrumentation error metrics", func(t *testing.T) {
		checkInstrumentationErrorMetrics(t)
	})

	require.NoError(t, compose.Close())
}

func TestAvoidedServicesMetrics(t *testing.T) {
	pool, network := setupDockertest(t)
	var wg sync.WaitGroup
	wg.Go(func() {
		setupContainerPrometheus(t, pool, network, "prometheus-config.yml")
	})
	wg.Go(func() {
		setupContainerJaeger(t, pool, network)
	})
	wg.Go(func() {
		setupContainerCollector(t, pool, network, "otelcol-config.yml")
	})
	wg.Wait()
	if t.Failed() {
		return
	}

	// Build the test server image
	projectRoot := tools.ProjectDir()
	err := pool.Client.BuildImage(docker.BuildImageOptions{
		Name:         "hatest-testserver",
		ContextDir:   projectRoot,
		Dockerfile:   "internal/test/integration/components/go_otel/Dockerfile",
		OutputStream: t.Output(),
		ErrorStream:  t.Output(),
	})
	require.NoError(t, err, "could not build test server Docker image")

	// Start test server
	testserver, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "hatest-testserver",
		Tag:        "latest",
		Name:       fmt.Sprintf("testserver-otel-test-%d", time.Now().UnixNano()),
		Networks:   []*dockertest.Network{network},
		Env: []string{
			"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://otelcol:4318",
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://jaeger:4318",
		},
		ExposedPorts: []string{"8080/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"8080/tcp": {{HostIP: "localhost", HostPort: "8080"}},
		},
	})
	require.NoError(t, err, "could not start test server container")
	t.Cleanup(func() {
		require.NoError(t, pool.Purge(testserver), "could not remove test server container")
	})

	// Start OBI to instrument the test server
	obiConfig := obiConfig{
		Env: []string{
			"OTEL_EBPF_OPEN_PORT=8080",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT=8999",
		},
	}
	if !KernelLockdownMode() {
		obiConfig.SecurityConfigSuffix = "_none"
	}
	instrumentWithOBI(t, pool, network, testserver, obiConfig)

	t.Run("Avoided services metrics are recorded", func(t *testing.T) {
		// Wait for the service to start and make some requests to trigger OTLP detection
		otelWaitForTestComponents(t, "http://localhost:8080", "/smoke")

		// Give time for the service to export metrics/traces
		time.Sleep(15 * time.Second)

		// Make additional requests to ensure OTLP endpoints are hit
		for i := 0; i < 3; i++ {
			ti.DoHTTPGet(t, "http://localhost:8080/rolldice", 200)
			time.Sleep(1 * time.Second)
		}

		// Check that avoided services metrics are present
		checkAvoidedServicesMetrics(t)
	})
}

func checkInstrumentationErrorMetrics(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		results, err := pq.Query(`obi_instrumentation_errors_total`)
		require.NoError(t, err)

		require.GreaterOrEqual(t, len(results), 1, "obi_instrumentation_errors_total metric should be present")

		// Verify we have some errors and proper labels
		totalErrors := 0
		for _, result := range results {
			labels := result.Metric
			require.Contains(t, labels, "process_name", "process_name label should be present")
			require.Contains(t, labels, "error_type", "error_type label should be present")

			value, err := strconv.Atoi(result.Value[1].(string))
			require.NoError(t, err)
			totalErrors += value
		}

		// We should have at least some errors when running without privileges
		require.Positive(t, totalErrors, "Should have instrumentation errors when running without privileges")
	}, test.Interval(1000*time.Millisecond))
}

func checkAvoidedServicesMetrics(t *testing.T) {
	const internalMetricsURL = "http://localhost:8999/internal/metrics"

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		parser := expfmt.NewTextParser(model.UTF8Validation)
		resp, err := http.Get(internalMetricsURL)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		metrics, err := parser.TextToMetricFamilies(resp.Body)
		require.NoError(t, err)

		metricFamily, ok := metrics["obi_avoided_services"]
		require.True(t, ok, "Expected obi_avoided_services metric to be present")
		require.NotEmpty(t, metricFamily.Metric, "Expected avoided services metrics to have values")

		// Just check the first occurrence
		metric := metricFamily.Metric[0]
		labelMap := make(map[string]string)
		for _, label := range metric.Label {
			labelMap[label.GetName()] = label.GetValue()
		}

		// Assert specific values for service_name and service_namespace
		assert.Equal(t, "rolldice", labelMap["service_name"], "service_name label should be 'rolldice'")
		assert.Equal(t, "integration-test", labelMap["service_namespace"], "service_namespace label should be 'integration-test'")
		assert.NotEmpty(t, labelMap["telemetry_type"], "telemetry_type label should not be empty")
		assert.Condition(t, func() bool {
			return labelMap["telemetry_type"] == "metrics" || labelMap["telemetry_type"] == "traces"
		}, "telemetry_type label should be either 'metrics' or 'traces'")
		// service_instance_id can be empty, but should be present
		_, ok = labelMap["service_instance_id"]
		assert.True(t, ok, "service_instance_id label should be present")

		if metric.Gauge != nil {
			assert.Greater(t, metric.Gauge.GetValue(), float64(0), "Expected avoided service metric value to be > 0")
		}
	}, test.Interval(1000*time.Millisecond))
}
