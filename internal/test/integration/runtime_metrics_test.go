// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"bufio"
	"encoding/json"
	"fmt"
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
	runtimeMemoryGaugeTolerance     = 16 * 1024 * 1024
	runtimeGoroutineGaugeTolerance  = 10
)

func testRuntimeMetricsGo(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	monotonicMetrics := []struct {
		runtimeName string
		obiQuery    string
		obiName     string
	}{
		{runtimeName: "/gc/gomemlimit:bytes", obiQuery: "go_memory_limit_bytes", obiName: "go_memory_limit_bytes"},
		{runtimeName: "/sched/gomaxprocs:threads", obiQuery: "go_processor_limit", obiName: "go_processor_limit"},
		{runtimeName: "/gc/gogc:percent", obiQuery: "go_config_gogc_percent", obiName: "go_config_gogc_percent"},
		{runtimeName: "/gc/cycles/total:gc-cycles", obiQuery: "go_memory_gc_cycles_total", obiName: "go_memory_gc_cycles_total"},
		{runtimeName: "/gc/heap/allocs:bytes", obiQuery: "go_memory_allocated_bytes_total", obiName: "go_memory_allocated_bytes_total"},
		{runtimeName: "/gc/heap/allocs:objects", obiQuery: "go_memory_allocations_total", obiName: "go_memory_allocations_total"},
	}
	cpuMetrics := []struct {
		runtimeName string
		obiQuery    string
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
			runtimeName: "/cpu/classes/user:cpu-seconds",
			obiQuery:    `go_cpu_time_seconds_total{go_cpu_state="user",go_cpu_detailed_state=""}`,
		},
	}
	gaugeMetrics := []struct {
		runtimeName string
		obiQuery    string
		obiName     string
		tolerance   float64
	}{
		{
			runtimeName: "go.memory.used/stack",
			obiQuery:    `go_memory_used_bytes{go_memory_type="stack"}`,
			obiName:     `go_memory_used_bytes{go_memory_type="stack"}`,
			tolerance:   runtimeMemoryGaugeTolerance,
		},
		{
			runtimeName: "go.memory.used/other",
			obiQuery:    `go_memory_used_bytes{go_memory_type="other"}`,
			obiName:     `go_memory_used_bytes{go_memory_type="other"}`,
			tolerance:   runtimeMemoryGaugeTolerance,
		},
		{
			runtimeName: "/sched/goroutines:goroutines",
			obiQuery:    "go_goroutine_count",
			obiName:     "go_goroutine_count",
			tolerance:   runtimeGoroutineGaugeTolerance,
		},
	}

	forceRuntimeGC(t)
	expected := readRuntimeMetrics(t)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		forceRuntimeGC(ct)
		current := readRuntimeMetrics(ct)
		for _, metric := range monotonicMetrics {
			obiValue := runtimeMetricValue(ct, pq, metric.obiQuery)
			assertRuntimeMetricObserved(ct, expected, current, metric.runtimeName, obiValue, metric.obiName)
		}
		for _, metric := range cpuMetrics {
			obiValue := runtimeMetricValue(ct, pq, metric.obiQuery)
			assertRuntimeMetricCounterObserved(ct, expected, current, metric.runtimeName, obiValue, metric.obiQuery)
		}
		for _, metric := range gaugeMetrics {
			obiValue := runtimeMetricValue(ct, pq, metric.obiQuery)
			assertRuntimeMetricGaugeObserved(ct, current, metric.runtimeName, obiValue, metric.obiName, metric.tolerance)
		}
	}, testTimeout, 250*time.Millisecond)
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
	assert.LessOrEqualf(t, expectedValue, currentValue,
		"service runtime/metrics %s should not go backwards", runtimeName)
	assert.LessOrEqualf(t, expectedValue, obiValue,
		"OBI %s should not be older than the captured service runtime/metrics value for %s", obiName, runtimeName)
	assert.LessOrEqualf(t, obiValue, currentValue,
		"OBI %s should not be newer than the current service runtime/metrics value for %s", obiName, runtimeName)
}

func assertRuntimeMetricCounterObserved(
	t require.TestingT,
	expected map[string]float64,
	current map[string]float64,
	runtimeName string,
	obiValue float64,
	obiName string,
) {
	expectedValue := directRuntimeMetricValue(t, expected, runtimeName)
	currentValue := directRuntimeMetricValue(t, current, runtimeName)

	assert.GreaterOrEqualf(t, expectedValue, 0.0, "service runtime/metrics %s should not be negative", runtimeName)
	assert.GreaterOrEqualf(t, obiValue, 0.0, "OBI %s should not be negative", obiName)
	assert.LessOrEqualf(t, expectedValue, currentValue,
		"service runtime/metrics %s should not go backwards", runtimeName)
	assert.LessOrEqualf(t, expectedValue, obiValue,
		"OBI %s should not be older than the captured service runtime/metrics value for %s", obiName, runtimeName)
	assert.LessOrEqualf(t, obiValue, currentValue,
		"OBI %s should not be newer than the current service runtime/metrics value for %s", obiName, runtimeName)
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
	conn := runtimeMetricsConn(t)
	defer conn.Close()

	_, err := conn.Write([]byte("FORCE_GC\n"))
	require.NoError(t, err)

	_, err = bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
}

func readRuntimeMetrics(t require.TestingT) map[string]float64 {
	conn := runtimeMetricsConn(t)
	defer conn.Close()

	_, err := conn.Write([]byte("RUNTIME_METRICS\n"))
	require.NoError(t, err)

	var values map[string]float64
	require.NoError(t, json.NewDecoder(conn).Decode(&values))
	return values
}

func runtimeMetricsConn(t require.TestingT) net.Conn {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("localhost", runtimeMetricsHostPort), 2*time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
	return conn
}
