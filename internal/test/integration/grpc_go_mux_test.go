// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

func testREDMetricsForGRPCMuxLibrary(t *testing.T, route, svcNs, serverPort string) {
	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	require.Eventually(t, func() bool {
		var err error
		results, err = pq.Query(`rpc_server_duration_seconds_count{` +
			`rpc_grpc_status_code="0",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="server",` +
			`rpc_method="` + route + `",` +
			`server_port="` + serverPort + `"}`)
		if err != nil {
			return false
		}
		// check duration_count has 3 calls and all the arguments
		if len(results) == 0 {
			return false
		}
		val := totalPromCount(t, results)
		if val < 1 {
			return false
		}
		if len(results) > 0 {
			res := results[0]
			if res.Metric["server_port"] == nil {
				return false
			}
		}
		return true
	}, time.Duration(1)*time.Minute, time.Second, "GRPC mux metrics not found")
}

func TestGRPCMux(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-grpc-http2-mux.yml", path.Join(pathOutput, "test-suite-grpc-http2-mux.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`, `TARGET_URL=testserver:8080`, `TARGET_PORTS=8080:8080`)
	require.NoError(t, compose.Up())

	t.Run("Go RED metrics: grpc-http2 mux service", func(t *testing.T) {
		testREDMetricsForGRPCMuxLibrary(t, "/grpc.health.v1.Health/Check", "grpc-http2-go", "8080")
	})

	require.NoError(t, compose.Close())
}

func TestGRPCMuxTLS(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-grpc-http2-mux.yml", path.Join(pathOutput, "test-suite-grpc-http2-mux-tls.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`, `TARGET_URL=testserver:8383`, `TARGET_PORTS=8383:8383`, `TEST_SUFFIX=_tls`)
	require.NoError(t, compose.Up())

	t.Run("Go RED metrics: grpc-http2 mux service TLS", func(t *testing.T) {
		testREDMetricsForGRPCMuxLibrary(t, "/grpc.health.v1.Health/Check", "grpc-http2-go", "8383")
	})

	require.NoError(t, compose.Close())
}
