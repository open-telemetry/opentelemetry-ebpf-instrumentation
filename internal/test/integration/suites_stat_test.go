// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestStat_GoStatMetrics(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-stat-metrics.yml", path.Join(pathOutput, "test-suite-go-stat-metrics.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `TEST_SERVICE_PORTS=8381:8080`, `OTEL_EBPF_CONFIG_SUFFIX=-go-stat-metrics`, `PROM_CONFIG_SUFFIX=-promscrape-otel`)
	require.NoError(t, compose.Up())
	t.Run("Go Stat Metrics TCP RTT tests", testStatMetricsTCPRttGo)
	t.Run("Go Stat Metrics TCP RTT role after shutdown tests", testStatMetricsTCPRttRoleAfterShutdownGo)
	t.Run("Go Stat Metrics TCP Failed Connection tests", testStatMetricsTCPFailedConnectionsGo)
	t.Run("Go Stat Metrics TCP Successful Connection tests", testStatMetricsTCPSuccessfulConnectionsGo)
	t.Run("Go Stat Metrics TCP Retransmits tests", testStatMetricsTCPRetransmitsGo)
	t.Run("Go Stat Metrics TCP IO tests", testStatMetricsTCPIoGo)
	t.Run("Go Stat Metrics TCP IO role tests", testStatMetricsTCPIoRoleGo)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

// TestStat_GoStatMetricsContextPropagation covers tcp_io transmit for sockets in the
// context propagation sockmap, whose sends skip tcp_sendmsg.
func TestStat_GoStatMetricsContextPropagation(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-stat-metrics.yml", path.Join(pathOutput, "test-suite-go-stat-metrics-cp.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `TEST_SERVICE_PORTS=8381:8080`, `OTEL_EBPF_CONFIG_SUFFIX=-go-stat-metrics-cp`, `PROM_CONFIG_SUFFIX=-promscrape-otel`, `STAT_CLIENT_START_DELAY=30s`)
	require.NoError(t, compose.Up())
	// without it, ordinary sends alone would pass the transmit check
	t.Run("Client socket in the sockmap", func(t *testing.T) {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			assert.NotEmpty(ct, cpBPFKeys(ct, compose, "sock_dir"))
		}, testTimeout, cpPollInterval)
	})
	t.Run("Go Stat Metrics TCP IO tests", testStatMetricsTCPIoGo)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}

// TestStat_GoStatMetricsV2 runs the same workload with a Config v2 file,
// because the tcp_resets stats feature is only selectable from Config v2.
func TestStat_GoStatMetricsV2(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-stat-metrics.yml", path.Join(pathOutput, "test-suite-go-stat-metrics-v2.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `TEST_SERVICE_PORTS=8381:8080`, `OTEL_EBPF_CONFIG_SUFFIX=-go-stat-metrics-v2`, `PROM_CONFIG_SUFFIX=-promscrape-otel`)
	require.NoError(t, compose.Up())
	t.Run("Go Stat Metrics TCP Resets tests", testStatMetricsTCPResetsGo)
	t.Run("Go Stat Metrics TCP Resets after shutdown tests", testStatMetricsTCPResetsAfterShutdownGo)
	runWeaverValidation(t)
	require.NoError(t, compose.Close())
}
