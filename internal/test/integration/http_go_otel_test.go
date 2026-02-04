// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dockercompose "go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

var (
	buildGoOTelTestServerOnce sync.Once
	buildGoOTelTestServerErr  error
)

func setupGoOTelTestServer(t *testing.T, network *dockertest.Network, env []string) *dockertest.Resource {
	t.Helper()

	buildGoOTelTestServerOnce.Do(func() {
		t.Log("Building Go OpenTelemetry test server image...")
		buildGoOTelTestServerErr = dockerPool.Client.BuildImage(docker.BuildImageOptions{
			Name:         "hatest-testserver",
			ContextDir:   pathRoot,
			Dockerfile:   "internal/test/integration/components/go_otel/Dockerfile",
			OutputStream: t.Output(),
			ErrorStream:  t.Output(),
		})
		if buildGoOTelTestServerErr != nil {
			return
		}
		t.Log("Go OpenTelemetry test server image built successfully")
	})
	require.NoError(t, buildGoOTelTestServerErr, "could not build test server Docker image")

	t.Log("Starting Go OpenTelemetry test server container...")
	testserver, err := dockerPool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "hatest-testserver",
		Name:         fmt.Sprintf("testserver-otel-test-%d", time.Now().UnixNano()),
		Networks:     []*dockertest.Network{network},
		Env:          env,
		ExposedPorts: []string{"8080/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"8080/tcp": {{HostIP: "localhost", HostPort: "8080"}},
		},
	})
	require.NoError(t, err, "could not start test server container")
	t.Cleanup(func() {
		require.NoError(t, dockerPool.Purge(testserver), "could not remove test server container")
	})
	t.Log("Go OpenTelemetry test server container started")
	return testserver
}

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

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		query := fmt.Sprintf("http_server_request_duration_seconds_count{%s}", labels)
		checkServerPromQueryResult(ct, pq, query, 1)
	}, testTimeout, 100*time.Millisecond)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		query := fmt.Sprintf("http_server_request_body_size_bytes_count{%s}", labels)
		checkServerPromQueryResult(ct, pq, query, 3)
	}, testTimeout, 100*time.Millisecond)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		query := fmt.Sprintf("http_server_response_body_size_bytes_count{%s}", labels)
		checkServerPromQueryResult(ct, pq, query, 3)
	}, testTimeout, 100*time.Millisecond)

	slug := route[1:]

	var trace jaeger.Trace
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=rolldice&operation=GET%20%2F" + slug)
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/" + slug})
		require.NotEmpty(ct, traces)
		trace = traces[0]
		require.Len(ct, trace.Spans, 3) // parent - in queue - processing
	}, testTimeout, 100*time.Millisecond)

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

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=dicer&operation=Roll")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.method", Type: "string", Value: "GET"})
		assert.LessOrEqual(ct, 1, len(traces))
	}, testTimeout, 100*time.Millisecond)

	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="rolldice",` +
			`http_route="` + route + `",` +
			`url_path="` + route + `"}`)
		require.NoError(ct, err)
		require.Empty(ct, results)
	}, testTimeout, 100*time.Millisecond)

	slug := route[1:]

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := http.Get(jaegerQueryURL + "?service=rolldice&operation=GET%20%2F" + slug)
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/" + slug})
		require.Empty(ct, traces)
	}, testTimeout, 100*time.Millisecond)
}

func TestHTTPGoOTelInstrumentedApp(t *testing.T) {
	network := setupDockerNetwork(t)
	setupContainerPrometheus(t, network, "prometheus-config.yml")
	setupContainerJaeger(t, network)
	setupContainerCollector(t, network, "otelcol-config.yml")
	testserver := setupGoOTelTestServer(t, network, nil)

	if t.Failed() {
		return
	}

	// Start OBI to instrument the test server
	o := obi{
		Env: []string{
			"OTEL_EBPF_OPEN_PORT=8080",
		},
	}
	if !KernelLockdownMode() {
		o.SecurityConfigSuffix = "_none"
	}
	o.instrument(t, network, testserver, "obi-config-go-otel.yml")

	t.Run("Go RED metrics: http service instrumented with OTel", func(t *testing.T) {
		waitForTestComponents(t, "http://localhost:8080")
		testForHTTPGoOTelLibrary(t, "/rolldice", "integration-test")
	})
}

func otelWaitForTestComponents(t *testing.T, url, subpath string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(ct, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`http_server_duration_count{http_method="GET"}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
	}, 1*time.Minute, time.Second)
}

func TestHTTPGoOTelAvoidsInstrumentedApp(t *testing.T) {
	network := setupDockerNetwork(t)
	setupContainerPrometheus(t, network, "prometheus-config.yml")
	setupContainerJaeger(t, network)
	setupContainerCollector(t, network, "otelcol-config.yml")
	testserver := setupGoOTelTestServer(t, network, []string{
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://otelcol:4318",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://jaeger:4318",
	})

	if t.Failed() {
		return
	}

	// Start OBI to instrument the test server
	o := obi{
		Env: []string{
			"OTEL_EBPF_OPEN_PORT=8080",
		},
	}
	if !KernelLockdownMode() {
		o.SecurityConfigSuffix = "_none"
	}
	o.instrument(t, network, testserver, "obi-config-go-otel.yml")

	t.Run("Go RED metrics: http service instrumented with OTel, no istrumentation", func(t *testing.T) {
		otelWaitForTestComponents(t, "http://localhost:8080", "/smoke")
		time.Sleep(15 * time.Second) // ensure we see some calls to /v1/metrics /v1/traces
		testInstrumentationMissing(t, "/rolldice", "integration-test")
	})
}

func TestHTTPGoOTelDisabledOptInstrumentedApp(t *testing.T) {
	network := setupDockerNetwork(t)
	setupContainerPrometheus(t, network, "prometheus-config.yml")
	setupContainerJaeger(t, network)
	setupContainerCollector(t, network, "otelcol-config.yml")
	testserver := setupGoOTelTestServer(t, network, []string{
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://otelcol:4318",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://jaeger:4318",
	})

	if t.Failed() {
		return
	}

	// Start OBI to instrument the test server
	o := obi{
		Env: []string{
			"OTEL_EBPF_OPEN_PORT=8080",
			"OTEL_EBPF_EXCLUDE_OTEL_INSTRUMENTED_SERVICES=false",
		},
	}
	if !KernelLockdownMode() {
		o.SecurityConfigSuffix = "_none"
	}
	o.instrument(t, network, testserver, "obi-config-go-otel.yml")

	t.Run("Go RED metrics: http service instrumented with OTel, option disabled", func(t *testing.T) {
		otelWaitForTestComponents(t, "http://localhost:8080", "/smoke")
		time.Sleep(15 * time.Second) // ensure we see some calls to /v1/metrics /v1/traces
		testForHTTPGoOTelLibrary(t, "/rolldice", "integration-test")
	})
}

func TestHTTPGoOTelInstrumentedAppGRPC(t *testing.T) {
	compose, err := dockercompose.ComposeSuite("docker-compose-go-otel-grpc.yml", path.Join(pathOutput, "test-suite-go-otel-grpc.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=8080`)
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
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(ct, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(ct, err)
		require.Equal(ct, http.StatusOK, r.StatusCode)

		resp, err := http.Get(jaegerQueryURL + "?service=dicer&operation=Smoke")
		require.NoError(ct, err)
		if resp == nil {
			return
		}
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.method", Type: "string", Value: "GET"})
		assert.LessOrEqual(ct, 1, len(traces))
	}, 1*time.Minute, time.Second)
}

func TestHTTPGoOTelAvoidsInstrumentedAppGRPC(t *testing.T) {
	compose, err := dockercompose.ComposeSuite("docker-compose-go-otel-grpc.yml", path.Join(pathOutput, "test-suite-go-otel-avoids-grpc.log"))
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
