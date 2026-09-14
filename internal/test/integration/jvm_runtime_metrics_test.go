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

const jvmRuntimeServiceLabels = `service_name="jvm-runtime",service_namespace="integration-test"`

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
	t.Run("Java agent runtime metrics", func(t *testing.T) {
		testJVMRuntimeAgentMetrics(t, pq)
	})
	t.Run("Java agent GC duration", func(t *testing.T) {
		testJVMGCDurationMetric(t, pq)
	})
	runWeaverValidation(t)
}

func testJVMGCDurationMetric(t *testing.T, pq promtest.Client) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, "http://localhost:"+jvmRuntimeMetricsHostPort+"/gc", http.StatusOK)

		count := queryJVMRuntimeMetric(ct, pq,
			`jvm_gc_duration_seconds_count{`+jvmRuntimeServiceLabels+`,jvm_gc_name!="",jvm_gc_action!=""}`)
		require.Positive(ct, count)
	}, testTimeout, 250*time.Millisecond)
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

func testJVMRuntimeAgentMetrics(t *testing.T, pq promtest.Client) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		loaded := queryJVMRuntimeMetric(ct, pq, `jvm_class_loaded_total{`+jvmRuntimeServiceLabels+`}`)
		require.Positive(ct, loaded)
		unloaded := queryJVMRuntimeMetric(ct, pq, `jvm_class_unloaded_total{`+jvmRuntimeServiceLabels+`}`)
		require.GreaterOrEqual(ct, unloaded, 0.0)
		classCount := queryJVMRuntimeMetric(ct, pq, `jvm_class_count{`+jvmRuntimeServiceLabels+`}`)
		require.Positive(ct, classCount)

		for _, daemon := range []string{"true", "false"} {
			threadCount := queryJVMRuntimeMetric(ct, pq,
				`jvm_thread_count{`+jvmRuntimeServiceLabels+`,jvm_thread_daemon="`+daemon+`"}`)
			require.GreaterOrEqual(ct, threadCount, 0.0)
		}

		cpuTime := queryJVMRuntimeMetric(ct, pq, `jvm_cpu_time_seconds_total{`+jvmRuntimeServiceLabels+`}`)
		require.Positive(ct, cpuTime)
		cpuCount := queryJVMRuntimeMetric(ct, pq, `jvm_cpu_count{`+jvmRuntimeServiceLabels+`}`)
		require.Positive(ct, cpuCount)
		cpuUtilization := queryJVMRuntimeMetric(ct, pq,
			`jvm_cpu_recent_utilization_ratio{`+jvmRuntimeServiceLabels+`}`)
		require.GreaterOrEqual(ct, cpuUtilization, 0.0)
		require.LessOrEqual(ct, cpuUtilization, 1.0)
	}, testTimeout, time.Second)
}

func queryJVMRuntimeMetric(t require.TestingT, pq promtest.Client, query string) float64 {
	results, err := pq.Query(query)
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assertJVMRuntimeMetricService(t, results)
	return promResultValue(t, results[0])
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
