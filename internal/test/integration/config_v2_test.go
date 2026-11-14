// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

func TestSuite_ConfigV2Standalone(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-config-v2-standalone.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-v2")
	require.NoError(t, compose.Up())
	t.Cleanup(func() {
		require.NoError(t, compose.Close())
	})

	waitForTestComponentsNoMetrics(t, instrumentedServiceStdURL+"/smoke")

	requireOBIConfigV2(t, compose, `"cmd":"/testserver"`)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		appResp, err := http.Get(instrumentedServiceStdURL + "/smoke")
		require.NoError(ct, err)
		if err != nil {
			return
		}
		appResp.Body.Close()
		require.Equal(ct, http.StatusOK, appResp.StatusCode)

		metricsResp, err := http.Get("http://localhost:8999/metrics")
		require.NoError(ct, err)
		if err != nil {
			return
		}
		defer metricsResp.Body.Close()
		require.Equal(ct, http.StatusOK, metricsResp.StatusCode)

		body, err := io.ReadAll(metricsResp.Body)
		require.NoError(ct, err)
		require.Contains(ct, string(body), "http_server_request_duration_seconds_count")
		require.Contains(ct, string(body), `http_route="/smoke"`)
	}, 2*testTimeout, time.Second)

	const requestPath = "/request-phases"
	traceID := createTraceID()
	doHTTPGetWithTraceparent(t, instrumentedServiceStdURL+requestPath+"?delay=10ms", http.StatusOK,
		createTraceparent(traceID, createParentID()))

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		trace, err := latestTraceMatching("testserver", func(trace jaeger.Trace) bool {
			return trace.TraceID == traceID
		})
		require.NoError(ct, err)
		require.Len(ct, trace.Spans, 3)
		assert.Len(ct, trace.FindByOperationName("GET "+requestPath, "server"), 1)
		assert.Len(ct, trace.FindByOperationName("in queue", "internal"), 1)
		assert.Len(ct, trace.FindByOperationName("processing", "internal"), 1)
	}, testTimeout, 100*time.Millisecond)
}

func TestSuite_ConfigV2RequestPhaseSpansDisabled(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-config-v2-request-phase-spans-disabled.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-v2-disable-request-phase-spans")
	require.NoError(t, compose.Up())
	t.Cleanup(func() {
		require.NoError(t, compose.Close())
	})

	waitForHTTPServerTrace(t, instrumentedServiceStdURL, "testserver")

	requireOBIConfigV2(t, compose, `"cmd":"/testserver"`)

	const requestPath = "/request-phases-disabled"
	traceID := createTraceID()
	doHTTPGetWithTraceparent(t, instrumentedServiceStdURL+requestPath+"?delay=10ms", http.StatusOK,
		createTraceparent(traceID, createParentID()))

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		trace, err := latestTraceMatching("testserver", func(trace jaeger.Trace) bool {
			return trace.TraceID == traceID
		})
		require.NoError(ct, err)
		require.Len(ct, trace.Spans, 1, "only the HTTP server span should be exported when request phase spans are disabled")
		assert.Len(ct, trace.FindByOperationName("GET "+requestPath, "server"), 1)
	}, testTimeout, 100*time.Millisecond)
}

func TestSuite_HTTPServerActiveRequests(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", path.Join(pathOutput, "test-suite-http-server-active-requests.log"))
	require.NoError(t, err)

	compose.Env = append(compose.Env, "INSTRUMENTER_CONFIG_SUFFIX=-v2-active-requests")
	require.NoError(t, compose.Up())

	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	t.Cleanup(func() { runWeaverValidation(t) })

	waitForTestComponentsNoMetrics(t, instrumentedServiceStdURL+"/smoke")
	requireOBIConfigV2(t, compose, `"cmd":"/testserver"`)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		response, err := http.Post(instrumentedServiceStdURL+"/active-requests", "", nil)
		require.NoError(ct, err)
		response.Body.Close()

		response, err = http.Get("http://localhost:8999/metrics")
		require.NoError(ct, err)
		defer response.Body.Close()

		body, err := io.ReadAll(response.Body)
		require.NoError(ct, err)
		assert.Regexp(ct, `http_server_active_requests\{[^\n]*http_request_method="POST"[^\n]*\} 0\n`, string(body))
	}, testTimeout, 250*time.Millisecond)

	// POST isolates the held requests from the suite's GET health checks.
	completed := make(chan error, 2)
	for range 2 {
		go func() {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, instrumentedServiceStdURL+"/active-requests?delay=15s", nil)
			if err != nil {
				completed <- err
				return
			}
			req.Host = "api.example.com"

			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					err = fmt.Errorf("unexpected response: %s", resp.Status)
				}
			}

			completed <- err
		}()
	}

	prom := promtest.Client{HostPort: prometheusHostPort}
	check := func(want string) {
		t.Helper()

		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			response, err := http.Get("http://localhost:8999/metrics")
			require.NoError(ct, err)
			defer response.Body.Close()

			body, err := io.ReadAll(response.Body)
			require.NoError(ct, err)
			assert.Regexp(ct, `http_server_active_requests\{[^\n]*http_request_method="POST"[^\n]*server_address="api.example.com"[^\n]*\} `+want+`\n`, string(body))

			results, err := prom.Query(`http_server_active_requests{http_request_method="POST",url_scheme="http",server_address="api.example.com",otel_scope_name!=""}`)
			require.NoError(ct, err)
			require.NotEmpty(ct, results)

			for _, result := range results {
				require.Len(ct, result.Value, 2)
				assert.Equal(ct, want, result.Value[1])
				assert.NotContains(ct, result.Metric, "http_route")
				assert.NotContains(ct, result.Metric, "http_response_status_code")
			}
		}, 10*time.Second, 250*time.Millisecond)
	}

	check("2")

	for range 2 {
		select {
		case err := <-completed:
			require.NoError(t, err)
		case <-time.After(testTimeout):
			t.Fatal("held HTTP request did not finish")
		}
	}

	check("0")
}

func requireOBIConfigV2(t *testing.T, compose *docker.Compose, target string) {
	t.Helper()

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		obiLogs, err := compose.LogsOutput("obi")
		require.NoError(ct, err)

		var configV2Loaded, targetInstrumented bool
		for line := range strings.Lines(obiLogs) {
			if strings.Contains(line, "configuration loaded") &&
				(strings.Contains(line, `"version":"v2"`) || strings.Contains(line, "version=v2")) {
				configV2Loaded = true
			}
			if strings.Contains(line, "instrumenting process") && strings.Contains(line, target) {
				targetInstrumented = true
			}
		}

		require.True(ct, configV2Loaded, "OBI did not report loading Config v2")
		require.True(ct, targetInstrumented, "OBI did not report instrumenting %s", target)
	}, testTimeout, time.Second)
}
