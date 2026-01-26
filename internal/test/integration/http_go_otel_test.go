// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

func testForHTTPGoOTelLibrary(t *testing.T, route, svcNs string) {
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, "http://localhost:8080"+route, 200)
	}

	// Eventually, Prometheus would make this query visible
	var (
		pq     = promtest.Client{HostPort: prometheusHostPort}
		labels = `http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="rolldice",` +
			`http_route="` + route + `",` +
			`url_path="` + route + `"`
	)

	require.Eventually(t, func() bool {
		query := fmt.Sprintf("http_server_request_duration_seconds_count{%s}", labels)
		results, err := pq.Query(query)
		if err != nil || len(results) == 0 {
			return false
		}
		val := totalPromCount(t, results)
		return val >= 1
	}, testTimeout, 500*time.Millisecond, "http server request duration not found")

	require.Eventually(t, func() bool {
		query := fmt.Sprintf("http_server_request_body_size_bytes_count{%s}", labels)
		results, err := pq.Query(query)
		if err != nil || len(results) == 0 {
			return false
		}
		val := totalPromCount(t, results)
		return val >= 3
	}, testTimeout, 500*time.Millisecond, "http server request body size not found")

	require.Eventually(t, func() bool {
		query := fmt.Sprintf("http_server_response_body_size_bytes_count{%s}", labels)
		results, err := pq.Query(query)
		if err != nil || len(results) == 0 {
			return false
		}
		val := totalPromCount(t, results)
		return val >= 3
	}, testTimeout, 500*time.Millisecond, "http server response body size not found")

	slug := route[1:]

	var trace jaeger.Trace
	require.Eventually(t, func() bool {
		resp, err := http.Get(jaegerQueryURL + "?service=rolldice&operation=GET%20%2F" + slug)
		if err != nil || resp == nil {
			return false
		}
		if resp.StatusCode != http.StatusOK {
			return false
		}
		var tq jaeger.TracesQuery
		if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
			return false
		}
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/" + slug})
		if len(traces) == 0 {
			return false
		}
		trace = traces[0]
		return len(trace.Spans) == 3 // parent - in queue - processing
	}, testTimeout, 100*time.Millisecond, "trace not found in jaeger")

	// Check the information of the parent span
	res := trace.FindByOperationName("GET /"+slug, "server")
	require.Len(t, res, 1)
	parent := res[0]
	require.NotEmpty(t, parent.TraceID)
}

func testInstrumentationMissing(t *testing.T, route, svcNs string) {
	for i := 0; i < 4; i++ {
		ti.DoHTTPGet(t, "http://localhost:8080"+route, 200)
	}

	require.Eventually(t, func() bool {
		resp, err := http.Get(jaegerQueryURL + "?service=dicer&operation=Roll")
		if err != nil || resp == nil {
			return false
		}
		if resp.StatusCode != http.StatusOK {
			return false
		}
		var tq jaeger.TracesQuery
		if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
			return false
		}
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.method", Type: "string", Value: "GET"})
		return len(traces) >= 1
	}, testTimeout, 100*time.Millisecond, "traces not found in jaeger")

	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result

	require.Eventually(t, func() bool {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="rolldice",` +
			`http_route="` + route + `",` +
			`url_path="` + route + `"`)
		return err == nil && len(results) == 0
	}, testTimeout, 500*time.Millisecond, "unexpected metrics found")

	slug := route[1:]

	require.Eventually(t, func() bool {
		resp, err := http.Get(jaegerQueryURL + "?service=rolldice&operation=GET%20%2F" + slug)
		if err != nil || resp == nil {
			return false
		}
		if resp.StatusCode != http.StatusOK {
			return false
		}
		var tq jaeger.TracesQuery
		if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
			return false
		}
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/" + slug})
		return len(traces) == 0
	}, testTimeout, 100*time.Millisecond, "unexpected traces found in jaeger")
}

func TestHTTPGoOTelInstrumentedApp(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-otel.yml", path.Join(pathOutput, "test-suite-go-otel.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=8080`, `APP_OTEL_ENDPOINT=http://localhost:1111`)
	lockdown := KernelLockdownMode()

	if !lockdown {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, compose.Up())

	t.Run("Go RED metrics: http service instrumented with OTel", func(t *testing.T) {
		waitForTestComponents(t, "http://localhost:8080")
		testForHTTPGoOTelLibrary(t, "/rolldice", "integration-test")
	})

	require.NoError(t, compose.Close())
}

func otelWaitForTestComponents(t *testing.T, url, subpath string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.Eventually(t, func() bool {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		if err != nil {
			return false
		}
		r, err := testHTTPClient.Do(req)
		if err != nil || r.StatusCode != http.StatusOK {
			return false
		}

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`http_server_duration_count{http_method="GET"}`)
		return err == nil && len(results) > 0
	}, 1*time.Minute, time.Second, "test components not ready")
}

func TestHTTPGoOTelAvoidsInstrumentedApp(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-otel.yml", path.Join(pathOutput, "test-suite-go-otel-avoids.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=8080`, `APP_OTEL_METRICS_ENDPOINT=http://otelcol:4318`, `APP_OTEL_TRACES_ENDPOINT=http://jaeger:4318`)
	lockdown := KernelLockdownMode()

	if !lockdown {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, compose.Up())

	t.Run("Go RED metrics: http service instrumented with OTel, no istrumentation", func(t *testing.T) {
		otelWaitForTestComponents(t, "http://localhost:8080", "/smoke")
		time.Sleep(15 * time.Second) // ensure we see some calls to /v1/metrics /v1/traces
		testInstrumentationMissing(t, "/rolldice", "integration-test")
	})

	require.NoError(t, compose.Close())
}

func TestHTTPGoOTelDisabledOptInstrumentedApp(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-otel.yml", path.Join(pathOutput, "test-suite-go-otel-disabled.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(
		compose.Env,
		`OTEL_EBPF_EXECUTABLE_PATH=`,
		`OTEL_EBPF_OPEN_PORT=8080`,
		`APP_OTEL_METRICS_ENDPOINT=http://otelcol:4318`,
		`APP_OTEL_TRACES_ENDPOINT=http://jaeger:4318`,
		`OTEL_EBPF_EXCLUDE_OTEL_INSTRUMENTED_SERVICES=false`,
	)

	lockdown := KernelLockdownMode()

	if !lockdown {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, compose.Up())

	t.Run("Go RED metrics: http service instrumented with OTel, option disabled", func(t *testing.T) {
		otelWaitForTestComponents(t, "http://localhost:8080", "/smoke")
		time.Sleep(15 * time.Second) // ensure we see some calls to /v1/metrics /v1/traces
		testForHTTPGoOTelLibrary(t, "/rolldice", "integration-test")
	})

	require.NoError(t, compose.Close())
}

func TestHTTPGoOTelInstrumentedAppGRPC(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-otel-grpc.yml", path.Join(pathOutput, "test-suite-go-otel-grpc.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=8080`, `APP_OTEL_ENDPOINT=http://localhost:1111`)
	lockdown := KernelLockdownMode()

	if !lockdown {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, compose.Up())

	t.Run("Go RED metrics: http service instrumented with OTel - GRPC", func(t *testing.T) {
		waitForTestComponents(t, "http://localhost:8080")
		testForHTTPGoOTelLibrary(t, "/rolldice", "integration-test")
	})

	require.NoError(t, compose.Close())
}

func otelWaitForTestComponentsTraces(t *testing.T, url, subpath string) {
	require.Eventually(t, func() bool {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		if err != nil {
			return false
		}
		r, err := testHTTPClient.Do(req)
		if err != nil || r.StatusCode != http.StatusOK {
			return false
		}

		resp, err := http.Get(jaegerQueryURL + "?service=dicer&operation=Smoke")
		if err != nil || resp == nil {
			return false
		}
		if resp.StatusCode != http.StatusOK {
			return false
		}
		var tq jaeger.TracesQuery
		if err := json.NewDecoder(resp.Body).Decode(&tq); err != nil {
			return false
		}
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.method", Type: "string", Value: "GET"})
		return len(traces) >= 1
	}, 1*time.Minute, time.Second, "test components with traces not ready")
}

func TestHTTPGoOTelAvoidsInstrumentedAppGRPC(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-go-otel-grpc.yml", path.Join(pathOutput, "test-suite-go-otel-avoids-grpc.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=8080`, `APP_OTEL_METRICS_ENDPOINT=http://otelcol:4317`, `APP_OTEL_TRACES_ENDPOINT=http://jaeger:4317`)
	lockdown := KernelLockdownMode()

	if !lockdown {
		compose.Env = append(compose.Env, `SECURITY_CONFIG_SUFFIX=_none`)
	}

	require.NoError(t, compose.Up())

	t.Run("Go RED metrics: http service instrumented with OTel, no istrumentation, GRPC", func(t *testing.T) {
		otelWaitForTestComponentsTraces(t, "http://localhost:8080", "/smoke")
		time.Sleep(15 * time.Second) // ensure we see some calls to /v1/metrics /v1/traces
		testInstrumentationMissing(t, "/rolldice", "integration-test")
	})

	require.NoError(t, compose.Close())
}
