// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dockercompose "go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	"go.opentelemetry.io/obi/internal/test/tools"
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

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		query := fmt.Sprintf("http_server_request_duration_seconds_count{%s}", labels)
		checkServerPromQueryResult(t, pq, query, 1)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		query := fmt.Sprintf("http_server_request_body_size_bytes_count{%s}", labels)
		checkServerPromQueryResult(t, pq, query, 3)
	})

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		query := fmt.Sprintf("http_server_response_body_size_bytes_count{%s}", labels)
		checkServerPromQueryResult(t, pq, query, 3)
	})

	slug := route[1:]

	var trace jaeger.Trace
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=rolldice&operation=GET%20%2F" + slug)
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/" + slug})
		require.NotEmpty(t, traces)
		trace = traces[0]
		require.Len(t, trace.Spans, 3) // parent - in queue - processing
	}, test.Interval(100*time.Millisecond))

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

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=dicer&operation=Roll")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.method", Type: "string", Value: "GET"})
		assert.LessOrEqual(t, 1, len(traces))
	}, test.Interval(100*time.Millisecond))

	// Eventually, Prometheus would make this query visible
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`http_server_request_duration_seconds_count{` +
			`http_request_method="GET",` +
			`http_response_status_code="200",` +
			`service_namespace="` + svcNs + `",` +
			`service_name="rolldice",` +
			`http_route="` + route + `",` +
			`url_path="` + route + `"}`)
		require.NoError(t, err)
		require.Empty(t, results)
	})

	slug := route[1:]

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=rolldice&operation=GET%20%2F" + slug)
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/" + slug})
		require.Empty(t, traces)
	}, test.Interval(100*time.Millisecond))
}

func setupHTTPGoOTelTest(t *testing.T) {
	pool, err := dockertest.NewPool("")
	require.NoError(t, err)
	require.NoError(t, pool.Client.Ping())

	// Create a unique network name
	networkName := fmt.Sprintf("obi-test-network-%d", time.Now().UnixNano())
	network, err := pool.CreateNetwork(networkName)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, pool.RemoveNetwork(network))
	})

	projectRoot := tools.ProjectDir()

	// Use unique container names based on timestamp
	timestamp := time.Now().UnixNano()

	// Start Prometheus
	prometheus, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "quay.io/prometheus/prometheus",
		Tag:        "v2.55.1",
		Name:       fmt.Sprintf("prometheus-otel-test-%d", timestamp),
		Networks:   []*dockertest.Network{network},
		Mounts: []string{
			filepath.Join(projectRoot, "internal/test/integration/configs") + ":/etc/prometheus",
		},
		Cmd: []string{
			"--config.file=/etc/prometheus/prometheus-config.yml",
			"--web.enable-lifecycle",
			"--web.route-prefix=/",
		},
		ExposedPorts: []string{"9090/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"9090/tcp": {{HostIP: "localhost", HostPort: "9090"}},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, pool.Purge(prometheus))
	})

	// Start Jaeger with network alias
	jaegerRes, err := pool.Client.CreateContainer(docker.CreateContainerOptions{
		Name: fmt.Sprintf("jaeger-otel-test-%d", timestamp),
		Config: &docker.Config{
			Image: "jaegertracing/all-in-one:1.60",
			Env: []string{
				"COLLECTOR_OTLP_ENABLED=true",
				"LOG_LEVEL=debug",
			},
			ExposedPorts: map[docker.Port]struct{}{
				"16686/tcp": {},
				"4317/tcp":  {},
				"4318/tcp":  {},
			},
		},
		HostConfig: &docker.HostConfig{
			PortBindings: map[docker.Port][]docker.PortBinding{
				"16686/tcp": {{HostIP: "localhost", HostPort: "16686"}},
			},
			PublishAllPorts: true,
		},
		NetworkingConfig: &docker.NetworkingConfig{
			EndpointsConfig: map[string]*docker.EndpointConfig{
				networkName: {
					Aliases: []string{"jaeger"},
				},
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, pool.Client.StartContainer(jaegerRes.ID, nil))
	jaeger := &dockertest.Resource{Container: jaegerRes}
	t.Cleanup(func() {
		require.NoError(t, pool.Purge(jaeger))
	})

	// Start OpenTelemetry Collector with network alias
	otelcolRes, err := pool.Client.CreateContainer(docker.CreateContainerOptions{
		Name: fmt.Sprintf("otelcol-otel-test-%d", timestamp),
		Config: &docker.Config{
			Image: "otel/opentelemetry-collector-contrib:0.104.0",
			Cmd:   []string{"--config=/etc/otelcol-config/otelcol-config.yml"},
			ExposedPorts: map[docker.Port]struct{}{
				"4317/tcp": {},
				"4318/tcp": {},
				"9464/tcp": {},
				"8888/tcp": {},
			},
		},
		HostConfig: &docker.HostConfig{
			Mounts: []docker.HostMount{
				{
					Target: "/etc/otelcol-config",
					Source: filepath.Join(projectRoot, "internal/test/integration/configs"),
					Type:   "bind",
				},
			},
			PublishAllPorts: true,
		},
		NetworkingConfig: &docker.NetworkingConfig{
			EndpointsConfig: map[string]*docker.EndpointConfig{
				networkName: {
					Aliases: []string{"otelcol"},
				},
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, pool.Client.StartContainer(otelcolRes.ID, nil))
	otelcol := &dockertest.Resource{Container: otelcolRes}
	t.Cleanup(func() {
		require.NoError(t, pool.Purge(otelcol))
	})

	// Build the test server image
	err = pool.Client.BuildImage(docker.BuildImageOptions{
		Name:         "hatest-testserver",
		ContextDir:   projectRoot,
		Dockerfile:   "internal/test/integration/components/go_otel/Dockerfile",
		OutputStream: t.Output(),
		ErrorStream:  t.Output(),
	})
	require.NoError(t, err)

	// Start test server
	testserver, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "hatest-testserver",
		Tag:        "latest",
		Name:       fmt.Sprintf("testserver-otel-test-%d", timestamp),
		Networks:   []*dockertest.Network{network},
		Env: []string{
			"LOG_LEVEL=DEBUG",
			"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=",
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=",
		},
		ExposedPorts: []string{"8080/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"8080/tcp": {{HostIP: "localhost", HostPort: "8080"}},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, pool.Purge(testserver))
	})

	// Build the OBI (ebpf-instrument) image
	err = pool.Client.BuildImage(docker.BuildImageOptions{
		Name:         "hatest-obi",
		ContextDir:   projectRoot,
		Dockerfile:   "internal/test/integration/components/ebpf-instrument/Dockerfile",
		OutputStream: t.Output(),
		ErrorStream:  t.Output(),
		BuildArgs: []docker.BuildArg{
			{Name: "TARGETARCH", Value: "amd64"},
		},
	})
	require.NoError(t, err)

	lockdown := KernelLockdownMode()
	securitySuffix := ""
	if !lockdown {
		securitySuffix = "_none"
	}

	// Start OBI container with PID namespace sharing
	coverageDir := filepath.Join(projectRoot, "testoutput")
	runOtelDir := filepath.Join(projectRoot, "testoutput/run-otel")
	os.MkdirAll(coverageDir, 0755)
	os.MkdirAll(runOtelDir, 0755)

	obi, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "hatest-obi",
		Tag:        "latest",
		Name:       fmt.Sprintf("obi-otel-test-%d", timestamp),
		Networks:   []*dockertest.Network{network},
		Cmd: []string{
			"--config=/configs/obi-config-go-otel.yml",
		},
		Mounts: []string{
			filepath.Join(projectRoot, "internal/test/integration/configs") + ":/configs",
			filepath.Join(projectRoot, "internal/test/integration/system/sys/kernel/security"+securitySuffix) + ":/sys/kernel/security",
			coverageDir + ":/coverage",
			runOtelDir + ":/var/run/beyla",
		},
		Env: []string{
			"GOCOVERDIR=/coverage",
			"OTEL_EBPF_TRACE_PRINTER=text",
			"OTEL_EBPF_OPEN_PORT=8080",
			"OTEL_EBPF_METRICS_FEATURES=application,application_span",
			"OTEL_EBPF_PROMETHEUS_FEATURES=application,application_span",
			"OTEL_EBPF_DISCOVERY_POLL_INTERVAL=500ms",
			"OTEL_EBPF_EXECUTABLE_PATH=",
			"OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT=1ms",
			"OTEL_EBPF_SERVICE_NAMESPACE=integration-test",
			"OTEL_EBPF_METRICS_INTERVAL=10ms",
			"OTEL_EBPF_BPF_BATCH_TIMEOUT=10ms",
			"OTEL_EBPF_LOG_LEVEL=DEBUG",
			"OTEL_EBPF_BPF_DEBUG=TRUE",
			"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT=8999",
			"OTEL_EBPF_PROCESSES_INTERVAL=100ms",
			"OTEL_EBPF_HOSTNAME=beyla",
		},
		Privileged:   true,
		ExposedPorts: []string{"8999/tcp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"8999/tcp": {{HostIP: "localhost", HostPort: ""}}, // Let Docker assign port
		},
	}, func(hc *docker.HostConfig) {
		hc.PidMode = "container:" + testserver.Container.ID
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, pool.Purge(obi))
	})
}

func TestHTTPGoOTelInstrumentedApp(t *testing.T) {
	setupHTTPGoOTelTest(t)

	t.Run("Go RED metrics: http service instrumented with OTel", func(t *testing.T) {
		waitForTestComponents(t, "http://localhost:8080")
		testForHTTPGoOTelLibrary(t, "/rolldice", "integration-test")
	})
}

func otelWaitForTestComponents(t *testing.T, url, subpath string) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	test.Eventually(t, 1*time.Minute, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(t, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode)

		// now, verify that the metric has been reported.
		// we don't really care that this metric could be from a previous
		// test. Once one it is visible, it means that Otel and Prometheus are healthy
		results, err := pq.Query(`http_server_duration_count{http_method="GET"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	}, test.Interval(time.Second))
}

func TestHTTPGoOTelAvoidsInstrumentedApp(t *testing.T) {
	compose, err := dockercompose.ComposeSuite("docker-compose-go-otel.yml", path.Join(pathOutput, "test-suite-go-otel-avoids.log"))
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
	compose, err := dockercompose.ComposeSuite("docker-compose-go-otel.yml", path.Join(pathOutput, "test-suite-go-otel-disabled.log"))
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
	compose, err := dockercompose.ComposeSuite("docker-compose-go-otel-grpc.yml", path.Join(pathOutput, "test-suite-go-otel-grpc.log"))
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
	test.Eventually(t, 1*time.Minute, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, url+subpath, nil)
		require.NoError(t, err)
		r, err := testHTTPClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, r.StatusCode)

		resp, err := http.Get(jaegerQueryURL + "?service=dicer&operation=Smoke")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.method", Type: "string", Value: "GET"})
		assert.LessOrEqual(t, 1, len(traces))
	}, test.Interval(time.Second))
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
