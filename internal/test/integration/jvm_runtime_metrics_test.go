// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

const jvmRuntimeMetricsHostPort = "8386"

func TestJVMRuntimeMetrics(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-jvm-runtime-metrics.yml", path.Join(pathOutput, "test-suite-jvm-runtime-metrics.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `TEST_SERVICE_PORTS=`+jvmRuntimeMetricsHostPort+`:8085`)
	require.NoError(t, compose.Up())
	t.Cleanup(func() {
		require.NoError(t, compose.Close())
	})

	waitForJVMRuntimeService(t)
	pq := promtest.Client{HostPort: prometheusHostPort}
	t.Run("HotSpot memory used pool metric", func(t *testing.T) {
		testJVMRuntimeMemoryUsedPoolMetric(t, pq)
	})
	t.Run("HotSpot memory pool metric", func(t *testing.T) {
		testJVMRuntimeMemoryPoolMetric(t, pq)
	})
	runWeaverValidation(t)
}

func waitForJVMRuntimeService(t *testing.T) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, "http://localhost:"+jvmRuntimeMetricsHostPort+"/smoke", http.StatusOK)
	}, testTimeout, time.Second)
}

func testJVMRuntimeMemoryUsedPoolMetric(t *testing.T, pq promtest.Client) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, "http://localhost:"+jvmRuntimeMetricsHostPort+"/gc", http.StatusOK)

		results, err := pq.Query(`jvm_memory_used_bytes{service_name="jvm-runtime",service_namespace="integration-test",jvm_memory_type="heap",jvm_memory_pool_name!=""}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
		assertJVMRuntimeMetricService(ct, results)
		assertJVMRuntimeMemoryPoolNames(ct, results, "Eden Space", "Survivor Space", "Tenured Gen")
	}, testTimeout, 250*time.Millisecond)
}

func testJVMRuntimeMemoryPoolMetric(t *testing.T, pq promtest.Client) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, "http://localhost:"+jvmRuntimeMetricsHostPort+"/gc", http.StatusOK)

		results, err := pq.Query(`jvm_memory_committed_bytes{service_name="jvm-runtime",service_namespace="integration-test",jvm_memory_pool_name!=""}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
		assertJVMRuntimeMetricService(ct, results)
	}, testTimeout, 250*time.Millisecond)
}

func assertJVMRuntimeMetricService(t require.TestingT, results []promtest.Result) {
	for _, result := range results {
		require.Equal(t, "jvm-runtime", result.Metric["service_name"])
		require.Equal(t, "integration-test", result.Metric["service_namespace"])
	}
}

func assertJVMRuntimeMemoryPoolNames(t require.TestingT, results []promtest.Result, expected ...string) {
	pools := make(map[string]struct{}, len(results))
	for _, result := range results {
		pools[result.Metric["jvm_memory_pool_name"]] = struct{}{}
	}

	for _, pool := range expected {
		require.Contains(t, pools, pool)
	}
}
