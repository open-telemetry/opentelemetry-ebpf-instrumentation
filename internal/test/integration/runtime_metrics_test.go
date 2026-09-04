// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

const (
	prometheusInstantVectorValueLen = 2
	runtimeMetricsHostPort          = "8392"
	runtimeMetricsGo117HostPort     = "8393"
	runtimeMetricsGo125HostPort     = "8394"
	runtimeHistogramFiniteBounds    = 161
	runtimeMemoryGaugeTolerance     = 16 * 1024 * 1024
	runtimeGoroutineGaugeTolerance  = 4
	runtimeMetricsReadIterations    = 12
	// ARM can expose 1 ULP drift between /runtime/metrics and OBI counters
	// (e.g. 2.2400000000000002e-07 vs 2.24e-07).
	runtimeMetricAcceptableDrift = 1e-12
)

type runtimeHistogram struct {
	Counts []uint64  `json:"counts"`
	Bounds []float64 `json:"bounds"`
}

type runtimeHistogramMetric struct {
	runtimeName string
	obiName     string
}

type runtimeHistogramPrometheusResult struct {
	count          float64
	finiteBuckets  map[float64]float64
	infinityBucket float64
}

func TestParseRuntimeHistogramPrometheusResults(t *testing.T) {
	const metricName = "go_schedule_duration_seconds"
	results := []promtest.Result{
		{
			Metric: map[string]string{"__name__": metricName + "_bucket", "le": "1"},
			Value:  []any{float64(1), "3"},
		},
		{
			Metric: map[string]string{"__name__": metricName + "_count"},
			Value:  []any{float64(1), "4"},
		},
		{
			Metric: map[string]string{"__name__": metricName + "_bucket", "le": "+Inf"},
			Value:  []any{float64(1), "4"},
		},
		{
			Metric: map[string]string{"__name__": metricName + "_bucket", "le": "0"},
			Value:  []any{float64(1), "2"},
		},
	}

	histogram := parseRuntimeHistogramPrometheusResults(t, results, metricName, 2)

	assert.InDelta(t, 4.0, histogram.count, 0)
	assert.Equal(t, map[float64]float64{0: 2, 1: 3}, histogram.finiteBuckets)
	assert.InDelta(t, 4.0, histogram.infinityBucket, 0)
}

func TestRuntimeHistogramPrometheusQueryUsesOneEvaluation(t *testing.T) {
	assert.Equal(t,
		"go_schedule_duration_seconds_bucket or go_schedule_duration_seconds_count",
		runtimeHistogramPrometheusQuery("go_schedule_duration_seconds"),
	)
}

func testRuntimeMetricsGo(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	monotonicMetrics := []struct {
		runtimeName string
		obiName     string
	}{
		{runtimeName: "/gc/gomemlimit:bytes", obiName: "go_memory_limit_bytes"},
		{runtimeName: "/sched/gomaxprocs:threads", obiName: "go_processor_limit"},
		{runtimeName: "/gc/gogc:percent", obiName: "go_config_gogc_percent"},
		{runtimeName: "/gc/cycles/total:gc-cycles", obiName: "go_memory_gc_cycles_total"},
		{runtimeName: "/gc/heap/allocs:bytes", obiName: "go_memory_allocated_bytes_total"},
		{runtimeName: "/gc/heap/allocs:objects", obiName: "go_memory_allocations_total"},
	}
	cpuMetrics := []struct {
		runtimeName     string
		obiQuery        string
		requirePositive bool
	}{
		{
			runtimeName: "/cpu/classes/gc/mark/assist:cpu-seconds",
			obiQuery:    `go_cpu_time_seconds_total{go_cpu_state="gc",go_cpu_detailed_state="gc/mark/assist"}`,
		},
		{
			runtimeName: "/cpu/classes/gc/mark/dedicated:cpu-seconds",
			obiQuery:    `go_cpu_time_seconds_total{go_cpu_state="gc",go_cpu_detailed_state="gc/mark/dedicated"}`,
		},
		{
			runtimeName: "/cpu/classes/gc/mark/idle:cpu-seconds",
			obiQuery:    `go_cpu_time_seconds_total{go_cpu_state="gc",go_cpu_detailed_state="gc/mark/idle"}`,
		},
		{
			runtimeName: "/cpu/classes/gc/pause:cpu-seconds",
			obiQuery:    `go_cpu_time_seconds_total{go_cpu_state="gc",go_cpu_detailed_state="gc/pause"}`,
		},
		{
			runtimeName: "/cpu/classes/scavenge/assist:cpu-seconds",
			obiQuery:    `go_cpu_time_seconds_total{go_cpu_state="scavenge",go_cpu_detailed_state="scavenge/assist"}`,
		},
		{
			runtimeName: "/cpu/classes/scavenge/background:cpu-seconds",
			obiQuery:    `go_cpu_time_seconds_total{go_cpu_state="scavenge",go_cpu_detailed_state="scavenge/background"}`,
		},
		{
			runtimeName: "/cpu/classes/idle:cpu-seconds",
			obiQuery:    `go_cpu_time_seconds_total{go_cpu_state="idle",go_cpu_detailed_state=""}`,
		},
		{
			runtimeName:     "/cpu/classes/user:cpu-seconds",
			obiQuery:        `go_cpu_time_seconds_total{go_cpu_state="user",go_cpu_detailed_state=""}`,
			requirePositive: true,
		},
	}
	gaugeMetrics := []struct {
		runtimeName string
		obiQuery    string
		tolerance   float64
	}{
		{
			runtimeName: "/gc/heap/goal:bytes",
			obiQuery:    "go_memory_gc_goal_bytes",
		},
		{
			runtimeName: "go.memory.used/stack",
			obiQuery:    `go_memory_used_bytes{go_memory_type="stack"}`,
			tolerance:   runtimeMemoryGaugeTolerance,
		},
		{
			runtimeName: "go.memory.used/other",
			obiQuery:    `go_memory_used_bytes{go_memory_type="other"}`,
			tolerance:   runtimeMemoryGaugeTolerance,
		},
		{
			runtimeName: "/sched/goroutines:goroutines",
			obiQuery:    "go_goroutine_count",
			tolerance:   runtimeGoroutineGaugeTolerance,
		},
	}
	histogramMetrics := []runtimeHistogramMetric{
		{
			runtimeName: "/sched/pauses/total/gc:seconds",
			obiName:     "go_memory_gc_pause_duration_seconds",
		},
		{
			runtimeName: "/sched/latencies:seconds",
			obiName:     "go_schedule_duration_seconds",
		},
	}

	forceRuntimeGC(t)
	expected := readRuntimeMetrics(t)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		forceRuntimeGC(ct)
		current := readRuntimeMetrics(ct)
		for _, metric := range monotonicMetrics {
			obiValue := runtimeMetricValue(ct, pq, metric.obiName)
			assertRuntimeMetricObserved(ct, expected, current, metric.runtimeName, obiValue, metric.obiName)
		}
		for _, metric := range cpuMetrics {
			obiValue := runtimeMetricValue(ct, pq, metric.obiQuery)
			assertRuntimeMetricCounterObserved(
				ct,
				expected,
				current,
				metric.runtimeName,
				obiValue,
				metric.obiQuery,
				metric.requirePositive,
			)
		}
		for _, metric := range gaugeMetrics {
			obiValue := runtimeMetricValue(ct, pq, metric.obiQuery)
			assertRuntimeMetricGaugeObserved(
				ct,
				current,
				metric.runtimeName,
				obiValue,
				metric.obiQuery,
				metric.tolerance,
			)
		}
	}, testTimeout, 250*time.Millisecond)

	expectedHistograms := readRuntimeHistograms(t)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		generateRuntimeHistograms(ct)
		currentHistograms := readRuntimeHistograms(ct)
		for _, metric := range histogramMetrics {
			assertRuntimeHistogramObserved(ct, pq, expectedHistograms, currentHistograms, metric)
		}
	}, testTimeout, 250*time.Millisecond)

	assertRuntimeMemoryMetricsDuringConcurrentReads(t, pq)
}

func testRuntimeGoroutineCountSuppressedAboveProcessorLimit(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	assert.Positive(t, runtimeMetricValue(t, pq, "go_goroutine_count"))

	setGOMAXPROCSAboveRuntimeMetricLimit(t)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		forceRuntimeGC(ct)
		results, err := pq.Query("go_goroutine_count")
		require.NoError(ct, err)
		assert.Empty(ct, results, "go_goroutine_count should be removed after collection is suppressed")
	}, testTimeout, 250*time.Millisecond)
}

func testRuntimeGoroutineCountGo125(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}

	forceRuntimeGCAtPort(t, runtimeMetricsGo125HostPort)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		forceRuntimeGCAtPort(ct, runtimeMetricsGo125HostPort)
		current := readRuntimeMetricsAtPort(ct, runtimeMetricsGo125HostPort)
		assertRuntimeMetricGaugeObserved(
			ct,
			current,
			"/sched/goroutines:goroutines",
			runtimeMetricValue(ct, pq, "go_goroutine_count"),
			"go_goroutine_count",
			runtimeGoroutineGaugeTolerance,
		)
	}, testTimeout, 250*time.Millisecond)
}

func testRuntimeMetricsGo117(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	availableMetrics := []string{
		"go_memory_gc_cycles_total",
		"go_processor_limit",
		"go_config_gogc_percent",
		"go_memory_gc_goal_bytes",
	}
	unavailableMetrics := []string{
		"go_memory_limit_bytes",
		"go_cpu_time_seconds_total",
		"go_memory_used_bytes",
		"go_memory_allocated_bytes_total",
		"go_memory_allocations_total",
		"go_goroutine_count",
		"go_memory_gc_pause_duration_seconds_count",
		"go_schedule_duration_seconds_count",
	}

	forceRuntimeGCAtPort(t, runtimeMetricsGo117HostPort)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		forceRuntimeGCAtPort(ct, runtimeMetricsGo117HostPort)
		current := readRuntimeMetricsAtPort(ct, runtimeMetricsGo117HostPort)
		for _, metric := range availableMetrics {
			assert.Positivef(ct, runtimeMetricValue(ct, pq, metric), "OBI %s should be positive", metric)
		}
		for _, metric := range unavailableMetrics {
			results, err := pq.Query(metric)
			require.NoError(ct, err)
			assert.Emptyf(ct, results, "OBI %s should not be exported", metric)
		}
		assertRuntimeMetricGaugeObserved(
			ct,
			current,
			"/gc/heap/goal:bytes",
			runtimeMetricValue(ct, pq, "go_memory_gc_goal_bytes"),
			"go_memory_gc_goal_bytes",
			0,
		)
	}, testTimeout, 250*time.Millisecond)
}

// Repeated runtime/metrics.Read calls exercise Go's consistentHeapStats slot rotation
// while GC runs, ensuring OBI does not export counters from a partial rotation.
func assertRuntimeMemoryMetricsDuringConcurrentReads(t *testing.T, pq promtest.Client) {
	setRuntimeMetricsReadLoop(t, true)
	defer setRuntimeMetricsReadLoop(t, false)

	queries := []string{"go_memory_allocated_bytes_total", "go_memory_allocations_total"}
	previous := make(map[string]float64, len(queries))
	for _, query := range queries {
		previous[query] = runtimeMetricValue(t, pq, query)
	}

	for range runtimeMetricsReadIterations {
		forceRuntimeGC(t)
		time.Sleep(300 * time.Millisecond)
		for _, query := range queries {
			current := runtimeMetricValue(t, pq, query)
			assert.GreaterOrEqualf(t, current, previous[query], "%s regressed during concurrent runtime/metrics reads", query)
			previous[query] = current
		}
	}
}

func assertRuntimeMetricObserved(
	t require.TestingT,
	expected map[string]float64,
	current map[string]float64,
	runtimeName string,
	obiValue float64,
	obiName string,
) {
	expectedValue := directRuntimeMetricValue(t, expected, runtimeName)
	currentValue := directRuntimeMetricValue(t, current, runtimeName)

	assert.Positivef(t, expectedValue, "service runtime/metrics %s should be positive", runtimeName)
	assert.Positivef(t, obiValue, "OBI %s should be positive", obiName)
	assertRuntimeMetricLessOrEqual(t, expectedValue, currentValue,
		"service runtime/metrics %s should not go backwards", runtimeName)
	assertRuntimeMetricLessOrEqual(t, expectedValue, obiValue,
		"OBI %s should not be older than the captured service runtime/metrics value for %s", obiName, runtimeName)
	assertRuntimeMetricLessOrEqual(t, obiValue, currentValue,
		"OBI %s should not be newer than the current service runtime/metrics value for %s", obiName, runtimeName)
}

func assertRuntimeMetricCounterObserved(
	t require.TestingT,
	expected map[string]float64,
	current map[string]float64,
	runtimeName string,
	obiValue float64,
	obiName string,
	requirePositive bool,
) {
	expectedValue := directRuntimeMetricValue(t, expected, runtimeName)
	currentValue := directRuntimeMetricValue(t, current, runtimeName)

	assert.GreaterOrEqualf(t, expectedValue, 0.0, "service runtime/metrics %s should not be negative", runtimeName)
	assert.GreaterOrEqualf(t, obiValue, 0.0, "OBI %s should not be negative", obiName)
	if requirePositive {
		assert.Positivef(t, expectedValue, "service runtime/metrics %s should be positive", runtimeName)
		assert.Positivef(t, obiValue, "OBI %s should be positive", obiName)
	}
	assertRuntimeMetricLessOrEqual(t, expectedValue, currentValue,
		"service runtime/metrics %s should not go backwards", runtimeName)
	assertRuntimeMetricLessOrEqual(t, expectedValue, obiValue,
		"OBI %s should not be older than the captured service runtime/metrics value for %s", obiName, runtimeName)
	assertRuntimeMetricLessOrEqual(t, obiValue, currentValue,
		"OBI %s should not be newer than the current service runtime/metrics value for %s", obiName, runtimeName)
}

func assertRuntimeMetricLessOrEqual(t require.TestingT, older, newer float64, msg string, args ...any) {
	assert.LessOrEqualf(t, older, newer+runtimeMetricAcceptableDrift, msg, args...)
}

func assertRuntimeMetricGaugeObserved(
	t require.TestingT,
	current map[string]float64,
	runtimeName string,
	obiValue float64,
	obiName string,
	tolerance float64,
) {
	currentValue := directRuntimeMetricValue(t, current, runtimeName)

	assert.Positivef(t, currentValue, "service runtime/metrics %s should be positive", runtimeName)
	assert.Positivef(t, obiValue, "OBI %s should be positive", obiName)
	assert.InDeltaf(t, currentValue, obiValue, tolerance,
		"OBI %s should match service runtime/metrics value for %s within tolerance", obiName, runtimeName)
}

func assertRuntimeHistogramObserved(
	t require.TestingT,
	pq promtest.Client,
	expectedHistograms map[string]runtimeHistogram,
	currentHistograms map[string]runtimeHistogram,
	metric runtimeHistogramMetric,
) {
	expected := directRuntimeHistogram(t, expectedHistograms, metric.runtimeName)
	current := directRuntimeHistogram(t, currentHistograms, metric.runtimeName)
	require.Equalf(t, expected.Bounds, current.Bounds,
		"service runtime/metrics %s boundaries changed", metric.runtimeName)
	require.Lenf(t, expected.Counts, len(expected.Bounds)+1,
		"service runtime/metrics %s has inconsistent expected counts and bounds", metric.runtimeName)
	require.Lenf(t, current.Counts, len(current.Bounds)+1,
		"service runtime/metrics %s has inconsistent current counts and bounds", metric.runtimeName)
	require.Lenf(t, current.Bounds, runtimeHistogramFiniteBounds,
		"service runtime/metrics %s should expose every finite histogram boundary", metric.runtimeName)

	expectedCount := runtimeHistogramPopulation(expected)
	currentCount := runtimeHistogramPopulation(current)
	assert.Greaterf(t, currentCount, expectedCount,
		"service runtime/metrics %s population did not increase after generation", metric.runtimeName)

	prometheusHistogram := queryRuntimeHistogramPrometheus(t, pq, metric.obiName, len(current.Bounds))
	countQuery := metric.obiName + "_count"
	obiCount := prometheusHistogram.count
	assert.Positivef(t, obiCount, "OBI %s should be positive after generation", countQuery)
	assert.LessOrEqualf(t, float64(expectedCount), obiCount,
		"OBI %s should not be older than the captured service histogram %s", countQuery, metric.runtimeName)
	assert.LessOrEqualf(t, obiCount, float64(currentCount),
		"OBI %s should not be newer than the current service histogram %s", countQuery, metric.runtimeName)

	var expectedCumulative uint64
	var currentCumulative uint64
	for i, bound := range current.Bounds {
		expectedCumulative += expected.Counts[i]
		currentCumulative += current.Counts[i]
		obiCumulative, ok := prometheusHistogram.finiteBuckets[bound]
		require.Truef(t, ok, "OBI %s bucket %d with le=%g is missing", metric.obiName, i, bound)
		assert.LessOrEqualf(t, float64(expectedCumulative), obiCumulative,
			"OBI %s bucket %d with le=%g is older than the captured service histogram", metric.obiName, i, bound)
		assert.LessOrEqualf(t, obiCumulative, float64(currentCumulative),
			"OBI %s bucket %d with le=%g is newer than the current service histogram", metric.obiName, i, bound)
	}
	assert.InDeltaf(t, obiCount, prometheusHistogram.infinityBucket, 0,
		"OBI %s +Inf bucket should equal _count and include the overflow population", metric.obiName)
}

func directRuntimeHistogram(
	t require.TestingT,
	histograms map[string]runtimeHistogram,
	name string,
) runtimeHistogram {
	histogram, ok := histograms[name]
	require.Truef(t, ok, "service runtime/metrics missing histogram %s", name)
	return histogram
}

func runtimeHistogramPopulation(histogram runtimeHistogram) uint64 {
	var population uint64
	for _, count := range histogram.Counts {
		population += count
	}
	return population
}

func runtimeHistogramPrometheusQuery(metricName string) string {
	return metricName + "_bucket or " + metricName + "_count"
}

func queryRuntimeHistogramPrometheus(
	t require.TestingT,
	pq promtest.Client,
	metricName string,
	wantFiniteBuckets int,
) runtimeHistogramPrometheusResult {
	query := runtimeHistogramPrometheusQuery(metricName)
	results, err := pq.Query(query)
	require.NoError(t, err)
	return parseRuntimeHistogramPrometheusResults(t, results, metricName, wantFiniteBuckets)
}

func parseRuntimeHistogramPrometheusResults(
	t require.TestingT,
	results []promtest.Result,
	metricName string,
	wantFiniteBuckets int,
) runtimeHistogramPrometheusResult {
	require.Lenf(t, results, wantFiniteBuckets+2,
		"expected one count, %d finite buckets, and one +Inf bucket for %s", wantFiniteBuckets, metricName)

	finiteBuckets := make(map[float64]float64, wantFiniteBuckets)
	var count float64
	foundCount := false
	var infinityBucket float64
	foundInfinity := false
	for _, result := range results {
		seriesName, ok := result.Metric["__name__"]
		require.Truef(t, ok, "Prometheus histogram result for %s is missing __name__", metricName)
		require.Lenf(t, result.Value, prometheusInstantVectorValueLen,
			"unexpected Prometheus value for %s", seriesName)
		value, err := strconv.ParseFloat(fmt.Sprint(result.Value[1]), 64)
		require.NoErrorf(t, err, "parse Prometheus value for %s", seriesName)

		boundText, hasBound := result.Metric["le"]
		if seriesName == metricName+"_count" {
			require.Falsef(t, hasBound, "Prometheus count result for %s unexpectedly has le=%s", metricName, boundText)
			require.Falsef(t, foundCount, "duplicate count result for %s", metricName)
			count = value
			foundCount = true
			continue
		}

		require.Equalf(t, metricName+"_bucket", seriesName,
			"unexpected Prometheus histogram series for %s", metricName)
		require.Truef(t, hasBound, "Prometheus bucket result for %s is missing the le label", metricName)
		bound, err := strconv.ParseFloat(boundText, 64)
		require.NoErrorf(t, err, "parse le=%q for %s", boundText, metricName)

		if math.IsInf(bound, 1) {
			require.Falsef(t, foundInfinity, "duplicate +Inf bucket for %s", metricName)
			infinityBucket = value
			foundInfinity = true
			continue
		}
		require.Falsef(t, math.IsInf(bound, -1), "unexpected -Inf bucket for %s", metricName)
		_, duplicate := finiteBuckets[bound]
		require.Falsef(t, duplicate, "duplicate bucket le=%s for %s", boundText, metricName)
		finiteBuckets[bound] = value
	}
	require.Truef(t, foundCount, "Prometheus count result is missing for %s", metricName)
	require.Truef(t, foundInfinity, "Prometheus implicit +Inf bucket is missing for %s", metricName)
	require.Lenf(t, finiteBuckets, wantFiniteBuckets, "unexpected finite bucket boundaries for %s", metricName)
	return runtimeHistogramPrometheusResult{
		count:          count,
		finiteBuckets:  finiteBuckets,
		infinityBucket: infinityBucket,
	}
}

func directRuntimeMetricValue(t require.TestingT, runtimeMetrics map[string]float64, name string) float64 {
	value, ok := runtimeMetrics[name]
	require.Truef(t, ok, "service runtime/metrics missing %s", name)
	return value
}

func runtimeMetricValue(
	t require.TestingT,
	pq promtest.Client,
	query string,
) float64 {
	results, err := pq.Query(query)
	require.NoError(t, err)
	require.Lenf(t, results, 1, "expected one Prometheus result for %s", query)

	require.Len(t, results[0].Value, prometheusInstantVectorValueLen)
	value, err := strconv.ParseFloat(fmt.Sprint(results[0].Value[1]), 64)
	require.NoError(t, err)
	return value
}

func forceRuntimeGC(t require.TestingT) {
	forceRuntimeGCAtPort(t, runtimeMetricsHostPort)
}

func forceRuntimeGCAtPort(t require.TestingT, port string) {
	conn := runtimeMetricsConnAtPort(t, port)
	defer conn.Close()

	_, err := conn.Write([]byte("FORCE_GC\n"))
	require.NoError(t, err)

	_, err = bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
}

func setGOMAXPROCSAboveRuntimeMetricLimit(t require.TestingT) {
	conn := runtimeMetricsConnAtPort(t, runtimeMetricsHostPort)
	defer conn.Close()

	_, err := conn.Write([]byte("SET_GOMAXPROCS_ABOVE_RUNTIME_METRIC_LIMIT\n"))
	require.NoError(t, err)

	_, err = bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
}

func setRuntimeMetricsReadLoop(t require.TestingT, enabled bool) {
	conn := runtimeMetricsConnAtPort(t, runtimeMetricsHostPort)
	defer conn.Close()

	command := "STOP_RUNTIME_METRICS_READ_LOOP\n"
	if enabled {
		command = "START_RUNTIME_METRICS_READ_LOOP\n"
	}
	_, err := conn.Write([]byte(command))
	require.NoError(t, err)

	_, err = bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
}

func readRuntimeMetrics(t require.TestingT) map[string]float64 {
	return readRuntimeMetricsAtPort(t, runtimeMetricsHostPort)
}

func readRuntimeMetricsAtPort(t require.TestingT, port string) map[string]float64 {
	conn := runtimeMetricsConnAtPort(t, port)
	defer conn.Close()

	_, err := conn.Write([]byte("RUNTIME_METRICS\n"))
	require.NoError(t, err)

	var values map[string]float64
	require.NoError(t, json.NewDecoder(conn).Decode(&values))
	return values
}

func generateRuntimeHistograms(t require.TestingT) {
	conn := runtimeMetricsConnAtPort(t, runtimeMetricsHostPort)
	defer conn.Close()

	_, err := conn.Write([]byte("GENERATE_RUNTIME_HISTOGRAMS\n"))
	require.NoError(t, err)

	_, err = bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
}

func readRuntimeHistograms(t require.TestingT) map[string]runtimeHistogram {
	conn := runtimeMetricsConnAtPort(t, runtimeMetricsHostPort)
	defer conn.Close()

	_, err := conn.Write([]byte("RUNTIME_HISTOGRAMS\n"))
	require.NoError(t, err)

	var values map[string]runtimeHistogram
	require.NoError(t, json.NewDecoder(conn).Decode(&values))
	return values
}

func runtimeMetricsConnAtPort(t require.TestingT, port string) net.Conn {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("localhost", port), 2*time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
	return conn
}
