// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"net/http"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
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
	t.Run("HotSpot heap summary event", func(t *testing.T) {
		testJVMRuntimeHeapSummaryEvent(t, compose)
	})
	t.Run("HotSpot memory pool event", func(t *testing.T) {
		testJVMRuntimeMemoryPoolEvent(t, compose)
	})
	runWeaverValidation(t)
}

func waitForJVMRuntimeService(t *testing.T) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, "http://localhost:"+jvmRuntimeMetricsHostPort+"/smoke", http.StatusOK)
	}, testTimeout, time.Second)
}

func testJVMRuntimeHeapSummaryEvent(t *testing.T, compose *docker.Compose) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, "http://localhost:"+jvmRuntimeMetricsHostPort+"/gc", http.StatusOK)

		logs, err := compose.LogsOutput("obi")
		require.NoError(ct, err)
		require.Contains(ct, logs, "received JVM GC heap summary event")
		require.Contains(ct, logs, "service=jvm-runtime")
		require.Contains(ct, logs, "namespace=integration-test")
		require.True(ct,
			strings.Contains(logs, "phase=before") || strings.Contains(logs, "phase=after"),
			"expected at least one before/after GC phase in OBI logs",
		)
	}, testTimeout, 250*time.Millisecond)
}

func testJVMRuntimeMemoryPoolEvent(t *testing.T, compose *docker.Compose) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, "http://localhost:"+jvmRuntimeMetricsHostPort+"/gc", http.StatusOK)

		logs, err := compose.LogsOutput("obi")
		require.NoError(ct, err)
		require.Contains(ct, logs, "received JVM memory pool event")
		require.Contains(ct, logs, "service=jvm-runtime")
		require.Contains(ct, logs, "namespace=integration-test")
		require.True(ct,
			strings.Contains(logs, "phase=before") || strings.Contains(logs, "phase=after"),
			"expected at least one before/after GC phase in OBI logs",
		)
	}, testTimeout, 250*time.Millisecond)
}
