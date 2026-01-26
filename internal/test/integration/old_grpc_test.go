// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

func testREDMetricsTracesForOldGRPCLibrary(t *testing.T, svcNs string) {
	url := "http://localhost:8080"

	waitForTestComponentsSub(t, url, "/factorial/1")

	path := "/factorial/2"

	for i := 0; i < 4; i++ {
		doHTTPGetIgnoreStatus(t, url+path)
	}

	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	require.Eventually(t, func() bool {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="backend",` +
			`url_path="` + path + `"}`)
		if err != nil {
			return false
		}
		// check duration_count has 3 calls and all the arguments
		if !enoughPromResults(t, results) {
			return false
		}
		val := totalPromCount(t, results)
		if val < 1 {
			return false
		}
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
			if addr == nil {
				return false
			}
		}
		return true
	}, 1*time.Minute, 500*time.Millisecond, "Prometheus http_server_request_duration_seconds_count query failed")

	// Eventually, Prometheus would make this query visible
	require.Eventually(t, func() bool {
		var err error
		results, err = pq.Query(`rpc_server_duration_seconds_count{` +
			`service_namespace="integration-test",` +
			`service_name="worker",` +
			`rpc_method="/fib.Multiplier/Loop"}`)
		if err != nil {
			return false
		}
		// check duration_count has at least 3 calls and all the arguments
		if !enoughPromResults(t, results) {
			return false
		}
		val := totalPromCount(t, results)
		if val < 3 {
			return false
		}
		if len(results) > 0 {
			res := results[0]
			addr := res.Metric["client_address"]
			if addr == nil {
				return false
			}
		}
		return true
	}, testTimeout, 500*time.Millisecond, "Prometheus rpc_server_duration_seconds_count query failed")

	var trace jaeger.Trace
	require.Eventually(t, func() bool {
		resp, err := http.Get(jaegerQueryURL + "?service=backend&operation=GET%20%2Ffactorial%2F")
		if err != nil {
			return false
		}
		if resp == nil {
			return false
		}
		if resp.StatusCode != http.StatusOK {
			return false
		}
		var tq jaeger.TracesQuery
		if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
			return false
		}
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: path})
		if len(traces) < 1 {
			return false
		}
		trace = traces[0]
		return true
	}, 1*time.Minute, 100*time.Millisecond, "Jaeger trace not found")

	// Check the information of the python parent span
	res := trace.FindByOperationName("GET /factorial/", "server")
	require.Len(t, res, 1)
	parent := res[0]
	require.NotEmpty(t, parent.TraceID)
	require.NotEmpty(t, parent.SpanID)
	// check duration is at least 2us
	assert.Less(t, (2 * time.Microsecond).Microseconds(), parent.Duration)
	// check span attributes
	sd := parent.Diff(
		jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "url.path", Type: "string", Value: path},
		jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(8080)},
		jaeger.Tag{Key: "http.route", Type: "string", Value: "/factorial/"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
	)
	assert.Empty(t, sd, sd.String())
}

func testGRPCGoClientFailsToConnect(t *testing.T) {
	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result

	// Eventually, Prometheus would make this query visible
	require.Eventually(t, func() bool {
		var err error
		results, err = pq.Query(`rpc_client_duration_seconds_count{` +
			`service_namespace="integration-test",` +
			`service_name="grpcpinger",` +
			`rpc_grpc_status_code="2",` +
			`rpc_method="/routeguide.RouteGuide/GetFeature"}`)
		if err != nil {
			return false
		}
		if !enoughPromResults(t, results) {
			return false
		}
		val := totalPromCount(t, results)
		if val < 1 {
			return false
		}
		return true
	}, testTimeout, 500*time.Millisecond, "Prometheus rpc_client_duration_seconds_count query failed")
}

func TestSuiteOtherGRPCGo(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-other-grpc.yml", path.Join(pathOutput, "test-suite-other-grpc.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`)
	lockdown := KernelLockdownMode()

	if !lockdown {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, compose.Up())

	t.Run("Go RED metrics and traces: old grpc service", func(t *testing.T) {
		testREDMetricsTracesForOldGRPCLibrary(t, "integration-test")
	})

	t.Run("Go RED metrics and traces: grpc client fails to connect", func(t *testing.T) {
		testGRPCGoClientFailsToConnect(t)
	})

	require.NoError(t, compose.Close())
}
