// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

func testSampler(t *testing.T) {
	waitForTestComponents(t, "http://localhost:5000")
	waitForTestComponents(t, "http://localhost:5001")
	waitForTestComponents(t, "http://localhost:5002")
	waitForTestComponents(t, "http://localhost:5003")

	// give enough time for the NodeJS injector to finish
	// TODO: once we implement the instrumentation status query API, replace
	// this with  a proper check to see if the target process has finished
	// being instrumented
	time.Sleep(60 * time.Second)

	for i := 0; i < 10; i++ {
		ti.DoHTTPGet(t, "http://localhost:5000/a", 200)
	}
	for i := 0; i < 3; i++ {
		ti.DoHTTPGet(t, "http://localhost:5003/smoke", 200)
	}
	testParentBasedRemoteDelegates(t)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		countA, err := samplerTraceCount("service-a", "GET /a", "/a")
		require.NoError(ct, err)
		require.GreaterOrEqual(ct, countA, 10)
		countD, err := samplerTraceCount("service-d", "GET /smoke", "/smoke")
		require.NoError(ct, err)
		require.GreaterOrEqual(ct, countD, 1)
	}, testTimeout, 1500*time.Millisecond)

	var queryErr error
	assert.Never(t, func() bool {
		for _, query := range []struct {
			service   string
			operation string
			path      string
		}{
			{service: "service-c", operation: "GET /c", path: "/c"},
			{service: "service-d", operation: "GET /d", path: "/d"},
		} {
			count, err := samplerTraceCount(query.service, query.operation, query.path)
			if err != nil {
				queryErr = err
				return false
			}
			if count > 0 {
				return true
			}
		}
		return false
	}, 5*time.Second, 100*time.Millisecond)
	require.NoError(t, queryErr)
}

func testParentBasedRemoteDelegates(t *testing.T) {
	const (
		remoteSampledTraceID   = "13579bdf2468ace0fedcba9876543210"
		remoteUnsampledTraceID = "fedcba987654321013579bdf2468ace0"
		remoteParentSpanID     = "1234567890123456"
	)

	// ParentBased(always_off) must select the sampled-remote AlwaysOn delegate,
	// while ParentBased(always_on) must select the unsampled-remote AlwaysOff delegate.
	doHTTPGetWithTraceparent(t, "http://localhost:5001/remote-parent-sampled", http.StatusNotFound,
		fmt.Sprintf("00-%s-%s-01", remoteSampledTraceID, remoteParentSpanID))
	doHTTPGetWithTraceparent(t, "http://localhost:5003/remote-parent-unsampled", http.StatusNotFound,
		fmt.Sprintf("00-%s-%s-00", remoteUnsampledTraceID, remoteParentSpanID))

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		count, err := samplerTraceCountByID("service-b", remoteSampledTraceID)
		require.NoError(ct, err)
		require.GreaterOrEqual(ct, count, 1)
	}, testTimeout, 1500*time.Millisecond)

	var queryErr error
	assert.Never(t, func() bool {
		count, err := samplerTraceCount(
			"service-d", "GET /remote-parent-unsampled", "/remote-parent-unsampled",
		)
		if err != nil {
			queryErr = err
			return false
		}
		return count > 0
	}, 5*time.Second, 100*time.Millisecond)
	require.NoError(t, queryErr)
}

func samplerTraceCount(service, operation, urlPath string) (int, error) {
	params := url.Values{}
	params.Set("service", service)
	params.Set("operation", operation)
	resp, err := http.Get(jaegerQueryURL + "?" + params.Encode())
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("Jaeger query returned status %d", resp.StatusCode)
	}

	var traces jaeger.TracesQuery
	if err := json.NewDecoder(resp.Body).Decode(&traces); err != nil {
		return 0, err
	}
	return len(traces.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: urlPath})), nil
}

func samplerTraceCountByID(service, traceID string) (int, error) {
	params := url.Values{}
	params.Set("service", service)
	params.Set("traceID", traceID)
	resp, err := http.Get(jaegerQueryURL + "?" + params.Encode())
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("Jaeger query returned status %d", resp.StatusCode)
	}

	var traces jaeger.TracesQuery
	if err := json.NewDecoder(resp.Body).Decode(&traces); err != nil {
		return 0, err
	}
	return len(traces.Data), nil
}

func TestSampler(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-sampler.yml", path.Join(pathOutput, "test-suite-sampler.log"))
	require.NoError(t, err)

	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `OTEL_EBPF_EXECUTABLE_PATH=`, `OTEL_EBPF_OPEN_PORT=`)
	require.NoError(t, compose.Up())

	t.Run("Sampler", testSampler)

	runWeaverValidation(t)

	require.NoError(t, compose.Close())
}
