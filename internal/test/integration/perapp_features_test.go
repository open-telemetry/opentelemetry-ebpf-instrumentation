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

func TestPerAppFeatures(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-multiexec.yml",
		path.Join(pathOutput, "test-suite-multiexec-perapp.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`,
		"OTEL_EBPF_CONFIG_SUFFIX", "-perapp")
	require.NoError(t, compose.Up())

	t.Run("all the services have span metrics", func(t *testing.T) {
		checkSpanMetric(t, 3*time.Minute, "nodejs-service", 3031, "/testing-node")
		checkSpanMetric(t, time.Minute, "rails-service", 3041, "/testing-rails")
		checkSpanMetric(t, time.Minute, "testserver", 8080, "/testing-go")
		checkSpanMetric(t, time.Minute, "java-service", 8086, "/testing-java")
		checkSpanMetric(t, time.Minute, "rust-service", 8091, "/testing-rust")
	})
	t.Run("node and rails have RED metrics", func(t *testing.T) {
		t.Fail()
	})
	t.Run("rest of services don't have RED metrics", func(t *testing.T) {
		t.Fail()
	})

	require.NoError(t, compose.Close())
}

func checkSpanMetric(t *testing.T, timeout time.Duration, serviceName string, port int, path string) {
	pq := prom.Client{HostPort: prometheusHostPort}
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

//func checkApp
