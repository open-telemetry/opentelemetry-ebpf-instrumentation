// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"path"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/obi/internal/test/integration/components/prom"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestPerAppFeatures_OTEL(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-perapp.yml",
		path.Join(pathOutput, "test-suite-multiexec-perapp-otel.log"))
	require.NoError(t, err)

	require.NoError(t, compose.Up())

	t.Run("all the services have span metrics", func(t *testing.T) {
		checkSpanMetric(t, 3*time.Minute, "node", 3031, "/testing-node")
		checkSpanMetric(t, time.Minute, "ruby", 3041, "/testing-rails")
		checkSpanMetric(t, time.Minute, "pytestserver", 7773, "/testing-python")
		checkSpanMetric(t, time.Minute, "testserver", 8080, "/testing-go")
		checkSpanMetric(t, time.Minute, "jtestserver", 8086, "/testing-java")
		checkSpanMetric(t, time.Minute, "rtestserver", 8091, "/testing-rust")
	})
	t.Run("node, rails and python have RED metrics", func(t *testing.T) {
		hasREDMetrics(t, "node", "/testing-node")
		hasREDMetrics(t, "ruby", "/testing-rails")
		hasREDMetrics(t, "pytestserver", "/testing-python")
	})
	t.Run("rest of services don't have RED metrics", func(t *testing.T) {
		hasNotREDMetrics(t, "testserver")
		hasNotREDMetrics(t, "jtestserver")
		hasNotREDMetrics(t, "rtestserver")
	})

	require.NoError(t, compose.Close())
}

var pq = prom.Client{HostPort: prometheusHostPort}

func checkSpanMetric(t *testing.T, timeout time.Duration, serviceName string, port int, path string) {
	test.Eventually(t, timeout, func(t require.TestingT) {
		// first, verify that the test service endpoint is healthy
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%d%s", port, path), nil)
		require.NoError(t, err)
		_, err = testHTTPClient.Do(req)
		require.NoError(t, err)

		results, err := pq.Query(`traces_spanmetrics_latency_sum{service_name="` + serviceName + `",span_name="GET ` + path + `"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	}, test.Interval(time.Second))
}

func hasREDMetrics(t *testing.T, serviceName string, path string) {
	test.Eventually(t, time.Minute, func(t require.TestingT) {
		results, err := pq.Query(`http_server_request_body_size_bytes_sum{service_name="` + serviceName + `",http_route="` + path + `"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	}, test.Interval(time.Second))
}

func hasNotREDMetrics(t *testing.T, serviceName string) {
	results, err := pq.Query(`http_server_request_body_size_bytes_sum{service_name="` + serviceName + `"}`)
	require.NoError(t, err)
	require.Empty(t, results)
}