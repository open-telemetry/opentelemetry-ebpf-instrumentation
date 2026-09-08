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
	t.Run("v8js heap space metrics", func(t *testing.T) {
		testV8HeapSpaceMetrics(t, pq)
	})
	t.Run("v8js heap used grows after retained allocations", func(t *testing.T) {
		testV8HeapGrowth(t, pq)
	})
	t.Run("v8js gc duration histogram counts forced major collections", func(t *testing.T) {
		testV8GCDuration(t, pq)
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

type nodejsHeapSpaceTruth struct {
	Size      float64 `json:"size"`
	Used      float64 `json:"used"`
	Available float64 `json:"available"`
	Physical  float64 `json:"physical"`
}

type nodejsGroundTruth struct {
	ELU struct {
		IdleS   float64 `json:"idle_s"`
		ActiveS float64 `json:"active_s"`
	} `json:"elu"`
	Delay struct {
		P50S float64 `json:"p50_s"`
	} `json:"delay"`
	HeapSpaces map[string]nodejsHeapSpaceTruth `json:"heap_spaces"`
	GCCounts   map[string]float64              `json:"gc_counts"`
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

// testV8HeapSpaceMetrics asserts the per-space heap gauges exist and are
// coherent: old_space is present in every V8 version, its used size is
// positive, and used never exceeds the pre-allocated size. Space names are
// engine-defined and version-dependent, so only old_space is pinned.
func testV8HeapSpaceMetrics(t *testing.T, pq promtest.Client) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		used := queryNodejsValue(ct, pq,
			`v8js_memory_heap_used_bytes{`+nodejsRuntimeServiceLabels+`,v8js_heap_space_name="old_space"}`)
		require.Positive(ct, used, "old_space used must be positive")

		limit := queryNodejsValue(ct, pq,
			`v8js_memory_heap_limit_bytes{`+nodejsRuntimeServiceLabels+`,v8js_heap_space_name="old_space"}`)
		require.GreaterOrEqual(ct, limit, used, "old_space pre-allocated size must be >= used")

		// the in-process truth pins the values, not just their existence
		gt := fetchNodejsGroundTruth(ct)
		gtOldSpace, ok := gt.HeapSpaces["old_space"]
		require.True(ct, ok, "ground truth must report old_space")
		// both readings move (allocations, GC) between the two samples:
		// same order of magnitude is enough to catch unit or field-order bugs
		require.Greater(ct, used, gtOldSpace.Used/3)
		require.Less(ct, used, gtOldSpace.Used*3)
	}, testTimeout, time.Second)
}

// testV8HeapGrowth retains ~30 MB of heap objects and expects the total used
// heap (summed over spaces — V8 decides which space the arrays land in) to
// grow accordingly.
func testV8HeapGrowth(t *testing.T, pq promtest.Client) {
	var baseline float64
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		baseline = queryNodejsValue(ct, pq,
			`sum(v8js_memory_heap_used_bytes{`+nodejsRuntimeServiceLabels+`})`)
		require.Positive(ct, baseline)
	}, testTimeout, time.Second)

	ti.DoHTTPGet(t, "http://localhost:"+nodejsRuntimeMetricsHostPort+"/alloc?mb=30", http.StatusOK)

	const twentyMB = 20 * 1024 * 1024
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		used := queryNodejsValue(ct, pq,
			`sum(v8js_memory_heap_used_bytes{`+nodejsRuntimeServiceLabels+`})`)
		require.Greater(ct, used, baseline+twentyMB,
			"retaining 30MB must grow the exported used heap by at least 20MB")
	}, testTimeout, time.Second)
}

// testV8GCDuration forces major collections and expects the gc duration
// histogram to count them under v8js_gc_type="major", in step with the
// app's own PerformanceObserver counts.
func testV8GCDuration(t *testing.T, pq promtest.Client) {
	majorCount := func(t require.TestingT) float64 {
		results, err := pq.Query(
			`v8js_gc_duration_seconds_count{` + nodejsRuntimeServiceLabels + `,v8js_gc_type="major"}`)
		require.NoError(t, err)
		if len(results) == 0 {
			return 0 // no major GC observed yet: series absent
		}
		return promResultValue(t, results[0])
	}

	baseline := majorCount(t)

	ti.DoHTTPGet(t, "http://localhost:"+nodejsRuntimeMetricsHostPort+"/gc", http.StatusOK)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		require.Greater(ct, majorCount(ct), baseline,
			"a forced global.gc() must be counted as a major collection")

		gt := fetchNodejsGroundTruth(ct)
		require.Positive(ct, gt.GCCounts["major"],
			"the app's own observer must have seen the major GC")
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
