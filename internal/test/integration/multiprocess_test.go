// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

func TestMultiProcess(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-multiexec.yml", path.Join(pathOutput, "test-suite-multiexec.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`)
	require.NoError(t, compose.Up())

	t.Run("Go RED metrics: usual service", func(t *testing.T) {
		waitForTestComponents(t, instrumentedServiceStdURL)
		testREDMetricsForHTTPLibrary(t, instrumentedServiceStdURL, "testserver", "initial-set")
		// checks that, instrumenting the process from this container,
		// it doesn't instrument too the process from the other container
		checkReportedOnlyOnce(t, instrumentedServiceStdURL, "testserver")
	})
	t.Run("Go RED metrics: service 1", func(t *testing.T) {
		waitForTestComponents(t, "http://localhost:8900")
		testREDMetricsForHTTPLibrary(t, "http://localhost:8900", "rename1", "initial-set")
		// checks that, instrumenting the process from this container,
		// it doesn't instrument too the process from the other container
		checkReportedOnlyOnce(t, "http://localhost:8900", "rename1")
	})
	t.Run("Go RED metrics: JSON RPC", func(t *testing.T) {
		waitForTestComponents(t, instrumentedServiceJSONRPCURL)
		testREDMetricsForJSONRPCHTTP(t, instrumentedServiceJSONRPCURL, "testserver", "initial-set")
		// checks that, instrumenting the process from this container,
		// it doesn't instrument too the process from the other container
		checkReportedOnlyOnce(t, instrumentedServiceJSONRPCURL, "rename1")
	})

	t.Run("Go RED metrics: rust service ssl", func(t *testing.T) {
		waitForTestComponents(t, "https://localhost:8491")
		testREDMetricsForRustHTTPLibrary(t, "https://localhost:8491", "rust-service-ssl", "multi-k", 8490, true)
		checkReportedRustEvents(t, "rust-service-ssl", "multi-k", 4)
	})

	t.Run("Go RED metrics: python service ssl", func(t *testing.T) {
		waitForTestComponents(t, "https://localhost:8381")
		testREDMetricsForPythonHTTPLibrary(t, "https://localhost:8381", "python-service-ssl", "multi-k")
		checkReportedPythonEvents(t, "python-service-ssl", "multi-k", 4)
	})

	t.Run("Go RED metrics: node service ssl", func(t *testing.T) {
		waitForTestComponents(t, "https://localhost:3034")
		testREDMetricsForNodeHTTPLibrary(t, "https://localhost:3034", "/greeting", "nodejs-service-ssl", "multi-k")
		checkReportedNodeJSEvents(t, "/greeting", "nodejs-service-ssl", "multi-k", 4)
	})

	t.Run("Go RED metrics: node service", func(t *testing.T) {
		waitForTestComponents(t, "http://localhost:3031")
		testREDMetricsForNodeHTTPLibrary(t, "http://localhost:3031", "/bye", "nodejs-service", "multi-k")
		checkReportedNodeJSEvents(t, "/bye", "nodejs-service", "multi-k", 4)
	})

	// do some requests to the server at port 18090, which must not be instrumented
	// as the obi-config-multiexec.yml file only selects the process with port 18080.
	// Doing it early to give time to generate the traces (in case the test failed)
	// while doing another test in between for the same container
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get("http://localhost:18090/dont-instrument")
		require.NoError(ct, err)
		assert.Equal(ct, http.StatusOK, resp.StatusCode)
	}, testTimeout, 100*time.Millisecond)

	t.Run("Processes in the same host are instrumented once and only once", func(t *testing.T) {
		waitForTestComponents(t, "http://localhost:18080")
		checkReportedOnlyOnce(t, "http://localhost:18080", "some-server")
	})

	// testing the earlier invocations to /dont-instrument
	t.Run("Non-selected processes must not be instrumented"+
		" even if they share the executable of another instrumented process", func(t *testing.T) {
		pq := promtest.Client{HostPort: prometheusHostPort}
		results, err := pq.Query(`http_server_request_duration_seconds_count{url_path="/dont-instrument"}`)
		require.NoError(t, err)
		assert.Empty(t, results)
	})

	t.Run("Nested traces with kprobes: rust -> java -> node -> go -> go jsonrpc -> python -> rails", func(t *testing.T) {
		testNestedHTTPTracesKProbes(t)
	})

	t.Run("Nested traces with kprobes: SSL node python rails", func(t *testing.T) {
		testNestedHTTPSTracesKProbes(t)
	})

	t.Run("Instrumented processes metric", func(t *testing.T) {
		checkInstrumentedProcessesMetric(t)
	})

	require.NoError(t, compose.Close())
}

func TestMultiProcessAppCP(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-multiexec-host.yml", path.Join(pathOutput, "test-suite-multiexec-app-cp.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_BPF_DISABLE_BLACK_BOX_CP=1`, `OTEL_EBPF_BPF_CONTEXT_PROPAGATION=all`, `OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS=1`)
	require.NoError(t, compose.Up())

	t.Run("Nested traces with kprobes: rust -> java -> node -> go -> go jsonrpc -> python -> rails", func(t *testing.T) {
		testNestedHTTPTracesKProbes(t)
	})
	require.NoError(t, compose.Close())
}

func TestMultiProcessAppCPHeadersOnly(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-multiexec-host.yml", path.Join(pathOutput, "test-suite-multiexec-app-cp-no-ip.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_BPF_DISABLE_BLACK_BOX_CP=1`, `OTEL_EBPF_BPF_CONTEXT_PROPAGATION=headers`, `OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS=1`)

	require.NoError(t, compose.Up())

	t.Run("Nested traces with kprobes: rust -> java -> node -> go -> go jsonrpc -> python -> rails", func(t *testing.T) {
		testNestedHTTPTracesKProbes(t)
	})

	require.NoError(t, compose.Close())
}

func TestMultiProcessAppCPTCPOnly(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-multiexec-host.yml", path.Join(pathOutput, "test-suite-multiexec-app-cp-tcp-only.log"))
	require.NoError(t, err)

	// Test TCP-only context propagation (no HTTP headers, only TCP options)
	// Explicitly disable request header tracking since we're not injecting HTTP headers
	compose.Env = append(compose.Env, `OTEL_EBPF_BPF_DISABLE_BLACK_BOX_CP=1`, `OTEL_EBPF_BPF_CONTEXT_PROPAGATION=tcp`, `OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS=false`)

	require.NoError(t, compose.Up())

	t.Run("Nested traces with TCP-only propagation", func(t *testing.T) {
		testNestedHTTPTracesKProbes(t)
	})

	require.NoError(t, compose.Close())
}

// Addresses bug https://github.com/grafana/beyla/issues/370 for Go executables
// Prevents that two instances of the same process report traces or metrics by duplicate
func checkReportedOnlyOnce(t *testing.T, baseURL, serviceName string) {
	const path = "/check-only-once"
	for i := 0; i < 3; i++ {
		resp, err := http.Get(baseURL + path)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_name="` + serviceName + `",` +
			`url_path="` + path + `"}`)
		require.NoError(ct, err)
		// check duration_count has 3 calls and all the arguments
		require.Len(ct, results, 1)
		assert.Equal(ct, 3, totalPromCount(ct, results))
	}, testTimeout, 1000*time.Millisecond)
}

func checkInstrumentedProcessesMetric(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// we expected to have this in Prometheus at this point
		processes := map[string]int{
			"python3.14":    10,
			"greetings":     2,
			"java":          1,
			"node":          2,
			"ruby":          2,
			"duped_service": 1,
			"testserver":    2,
			"rename1":       1,
		}

		for processName, expectedCount := range processes {
			results, err := pq.Query(fmt.Sprintf(`obi_instrumented_processes{process_name="%s"}`, processName))
			require.NoError(ct, err)
			require.NotEmpty(ct, results, "Expected to find instrumented processes metric for %s", processName)
			value, err := strconv.Atoi(results[0].Value[1].(string))
			require.NoError(ct, err)
			assert.Equal(ct, expectedCount, value)
		}
	}, testTimeout, 1000*time.Millisecond)
}

// We are instrumenting only the Rust and Ruby services, all other server span queries should come empty
func testPartialLanguageHTTPProbes(t *testing.T) {
	waitForTestComponentsSub(t, "http://localhost:8091", "/dist") // rust

	for i := 0; i < 100; i++ {
		ti.DoHTTPGet(t, "http://localhost:8091/dist", 200)
	}

	// check the rust service, it will not have any nested spans
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=greetings&operation=GET%20%2Fdist")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/dist"})
		require.LessOrEqual(ct, 5, len(traces))
		for _, trace := range traces {
			// Check the information of the rust parent span
			res := trace.FindByOperationName("GET /dist", "server")
			require.Len(ct, res, 1)
			parent := res[0]
			require.NotEmpty(ct, parent.TraceID)
			require.NotEmpty(ct, parent.SpanID)
			// check duration is at least 2us
			assert.Less(ct, (2 * time.Microsecond).Microseconds(), parent.Duration)
			// check span attributes
			sd := parent.Diff(
				jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
				jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)},
				jaeger.Tag{Key: "url.path", Type: "string", Value: "/dist"},
				jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(8090)},
				jaeger.Tag{Key: "http.route", Type: "string", Value: "/dist"},
				jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
			)
			assert.Empty(ct, sd, sd.String())

			// Check the information of the java parent span
			res = trace.FindByOperationName("GET /jtrace", "server")
			require.Empty(ct, res)

			// Check the information of the nodejs parent span
			res = trace.FindByOperationName("GET /traceme", "server")
			require.Empty(ct, res)

			// Check the information of the go parent span
			res = trace.FindByOperationName("GET /gotracemetoo", "server")
			require.Empty(ct, res)

			// Check the information of the python parent span
			res = trace.FindByOperationName("GET /tracemetoo", "server")
			require.Empty(t, res)

			// Check the information of the rails parent span
			res = trace.FindByOperationName("GET /users", "server")
			require.Empty(t, res)
		}
	}, testTimeout, 100*time.Millisecond)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=ruby&operation=GET%20%2Fusers")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/users"})
		require.LessOrEqual(ct, 5, len(traces))
		for _, trace := range traces {
			// Check the information of the rust parent span
			res := trace.FindByOperationName("GET /users", "server")
			require.Len(ct, res, 1)
		}
	}, testTimeout, 100*time.Millisecond)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=GET%20%2Fgotracemetoo")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/gotracemetoo"})
		require.Empty(ct, traces)
	}, testTimeout, 100*time.Millisecond)
}

func TestLanguageSelectors(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-multiexec.yml", path.Join(pathOutput, "test-suite-multiexec-lang.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file, choose the lang config file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`, `MULTI_TEST_MODE=-lang`)
	require.NoError(t, compose.Up())

	// We are testing with instrumenting only Ruby and Rust services, so from our call chain we should only see
	// traces for the two services written in the correct language
	t.Run("Partial traces: rust (OK) -> java (NO) -> node (NO) -> go (NO) -> python (NO) -> rails (OK)", func(t *testing.T) {
		testPartialLanguageHTTPProbes(t)
	})

	require.NoError(t, compose.Close())
}
