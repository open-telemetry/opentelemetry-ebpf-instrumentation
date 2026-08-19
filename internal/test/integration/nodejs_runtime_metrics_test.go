// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"net/http"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

const nodejsRuntimeMetricsHostPort = "8396"

const nodejsRuntimeServiceLabels = `service_name="nodejs-runtime",service_namespace="integration-test"`

func TestNodejsRuntimeMetrics(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-nodejs-runtime-metrics.yml",
		path.Join(pathOutput, "test-suite-nodejs-runtime-metrics.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, `TEST_SERVICE_PORTS=`+nodejsRuntimeMetricsHostPort+`:3030`)
	require.NoError(t, compose.Up())
	t.Cleanup(func() {
		require.NoError(t, compose.Close())
	})

	waitForNodejsRuntimeService(t)
	pq := promtest.Client{HostPort: prometheusHostPort}
	t.Run("event loop time counters", func(t *testing.T) {
		testNodejsEventLoopTime(t, pq)
	})
	t.Run("event loop utilization", func(t *testing.T) {
		testNodejsEventLoopUtilization(t, pq)
	})
	t.Run("event loop delay reacts to a blocked loop", func(t *testing.T) {
		testNodejsEventLoopDelay(t, pq)
	})
	t.Run("exported values match the app's perf_hooks ground truth", func(t *testing.T) {
		testNodejsGroundTruth(t, pq)
	})
	runWeaverValidation(t)
}

func waitForNodejsRuntimeService(t *testing.T) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, "http://localhost:"+nodejsRuntimeMetricsHostPort+"/smoke", http.StatusOK)
	}, testTimeout, time.Second)
}

func testNodejsEventLoopTime(t *testing.T, pq promtest.Client) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// keep the loop alternating between idle waits and work
		ti.DoHTTPGet(ct, "http://localhost:"+nodejsRuntimeMetricsHostPort+"/async?ms=50", http.StatusOK)

		for _, state := range []string{"idle", "active"} {
			results, err := pq.Query(`nodejs_eventloop_time_seconds_total{` + nodejsRuntimeServiceLabels + `,nodejs_eventloop_state="` + state + `"}`)
			require.NoError(ct, err)
			require.NotEmpty(ct, results, "expected %s eventloop time series", state)
			assertNodejsRuntimeMetricService(ct, results)
			require.Positive(ct, promResultValue(ct, results[0]), "expected %s eventloop time > 0", state)
		}
	}, testTimeout, 250*time.Millisecond)
}

func testNodejsEventLoopUtilization(t *testing.T, pq promtest.Client) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, "http://localhost:"+nodejsRuntimeMetricsHostPort+"/busy?ms=100", http.StatusOK)

		results, err := pq.Query(`nodejs_eventloop_utilization_ratio{` + nodejsRuntimeServiceLabels + `}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
		assertNodejsRuntimeMetricService(ct, results)
		value := promResultValue(ct, results[0])
		require.Positive(ct, value)
		require.LessOrEqual(ct, value, 1.0)
	}, testTimeout, 250*time.Millisecond)
}

func testNodejsEventLoopDelay(t *testing.T, pq promtest.Client) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		// block the loop for 200ms: the delay histogram of the current
		// 1s sampling window must catch it
		ti.DoHTTPGet(ct, "http://localhost:"+nodejsRuntimeMetricsHostPort+"/busy?ms=200", http.StatusOK)

		results, err := pq.Query(`nodejs_eventloop_delay_max_seconds{` + nodejsRuntimeServiceLabels + `}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
		require.Greater(ct, promResultValue(ct, results[0]), 0.1,
			"expected a ~200ms loop block to show up in delay max")

		results, err = pq.Query(`nodejs_eventloop_delay_p99_seconds{` + nodejsRuntimeServiceLabels + `}`)
		require.NoError(ct, err)
		require.NotEmpty(ct, results)
		require.Positive(ct, promResultValue(ct, results[0]))
	}, testTimeout, 250*time.Millisecond)
}

type nodejsGroundTruth struct {
	ELU struct {
		IdleS   float64 `json:"idle_s"`
		ActiveS float64 `json:"active_s"`
	} `json:"elu"`
	Delay struct {
		P50S float64 `json:"p50_s"`
	} `json:"delay"`
}

// testNodejsGroundTruth compares the exported metrics against the
// application's own perf_hooks readings (/ground-truth). The plausibility
// assertions above cannot catch unit errors (ms vs ns is 10^6 off) or an
// encode/decode field-order swap; comparing against the in-process truth
// does, without requiring precision the two unsynchronized readings can't
// provide.
func testNodejsGroundTruth(t *testing.T, pq promtest.Client) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		gt := fetchNodejsGroundTruth(ct)

		promIdle := queryNodejsValue(ct, pq,
			`nodejs_eventloop_time_seconds_total{`+nodejsRuntimeServiceLabels+`,nodejs_eventloop_state="idle"}`)
		promActive := queryNodejsValue(ct, pq,
			`nodejs_eventloop_time_seconds_total{`+nodejsRuntimeServiceLabels+`,nodejs_eventloop_state="active"}`)

		// OBI samples at 1Hz and the two readings are not simultaneous:
		// allow a few seconds of drift. A units bug or an idle/active swap
		// is orders of magnitude off and cannot pass.
		require.InDelta(ct, gt.ELU.IdleS, promIdle, 5.0)
		require.InDelta(ct, gt.ELU.ActiveS, promActive, 5.0)

		// delay windows differ (OBI: last 1s interval; app: since start),
		// so only require the same order of magnitude
		if gt.Delay.P50S > 0 {
			promP50 := queryNodejsValue(ct, pq,
				`nodejs_eventloop_delay_p50_seconds{`+nodejsRuntimeServiceLabels+`}`)
			require.Greater(ct, promP50, gt.Delay.P50S/3)
			require.Less(ct, promP50, gt.Delay.P50S*3)
		}
	}, testTimeout, time.Second)
}

func fetchNodejsGroundTruth(t require.TestingT) nodejsGroundTruth {
	var gt nodejsGroundTruth
	resp, err := http.Get("http://localhost:" + nodejsRuntimeMetricsHostPort + "/ground-truth")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&gt))
	return gt
}

func queryNodejsValue(t require.TestingT, pq promtest.Client, query string) float64 {
	results, err := pq.Query(query)
	require.NoError(t, err)
	require.NotEmpty(t, results)
	return promResultValue(t, results[0])
}

func assertNodejsRuntimeMetricService(t require.TestingT, results []promtest.Result) {
	for _, result := range results {
		require.Equal(t, "nodejs-runtime", result.Metric["service_name"])
		require.Equal(t, "integration-test", result.Metric["service_namespace"])
	}
}

// promResultValue extracts the sample value from a prometheus instant-query
// result ([timestamp, "value"]).
func promResultValue(t require.TestingT, result promtest.Result) float64 {
	require.Len(t, result.Value, 2)
	str, ok := result.Value[1].(string)
	require.True(t, ok, "unexpected prometheus value type %T", result.Value[1])
	value, err := strconv.ParseFloat(str, 64)
	require.NoError(t, err)
	return value
}
