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

const prometheusInstantVectorValueLen = 2

func testRuntimeMetricsGo(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		before := readRuntimeMetrics(ct)
		forceRuntimeGC(ct)

		memoryLimit := runtimeMetricValue(ct, pq, "go_memory_limit_bytes")
		processorLimit := runtimeMetricValue(ct, pq, "go_processor_limit")
		gogc := runtimeMetricValue(ct, pq, "go_config_gogc_percent")
		gcCycles := runtimeMetricValue(ct, pq, "go_memory_gc_cycles_total")

		after := readRuntimeMetrics(ct)

		assertStaticRuntimeMetric(ct, before, after, "/gc/gomemlimit:bytes", memoryLimit, "go_memory_limit_bytes")
		assertStaticRuntimeMetric(ct, before, after, "/sched/gomaxprocs:threads", processorLimit, "go_processor_limit")
		assertStaticRuntimeMetric(ct, before, after, "/gc/gogc:percent", gogc, "go_config_gogc_percent")
		assertRuntimeMetricBetweenReads(ct, before, after, "/gc/cycles/total:gc-cycles", gcCycles, "go_memory_gc_cycles_total")
		assert.Positive(ct, gcCycles)
	}, testTimeout, 250*time.Millisecond)
}

func assertStaticRuntimeMetric(
	t require.TestingT,
	before map[string]float64,
	after map[string]float64,
	runtimeName string,
	obiValue float64,
	obiName string,
) {
	beforeValue := directRuntimeMetricValue(t, before, runtimeName)
	afterValue := directRuntimeMetricValue(t, after, runtimeName)

	assert.Positivef(t, beforeValue, "service runtime/metrics %s should be positive", runtimeName)
	assert.Positivef(t, obiValue, "OBI %s should be positive", obiName)
	assert.Equalf(t, beforeValue, afterValue,
		"service runtime/metrics %s changed during comparison", runtimeName)
	assert.Equalf(t, beforeValue, obiValue,
		"OBI %s should match service runtime/metrics %s", obiName, runtimeName)
}

func assertRuntimeMetricBetweenReads(
	t require.TestingT,
	before map[string]float64,
	after map[string]float64,
	runtimeName string,
	obiValue float64,
	obiName string,
) {
	beforeValue := directRuntimeMetricValue(t, before, runtimeName)
	afterValue := directRuntimeMetricValue(t, after, runtimeName)

	assert.LessOrEqualf(t, beforeValue, obiValue,
		"OBI %s should not be older than the first service runtime/metrics read for %s", obiName, runtimeName)
	assert.LessOrEqualf(t, obiValue, afterValue,
		"OBI %s should not be newer than the second service runtime/metrics read for %s", obiName, runtimeName)
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
	conn, err := net.DialTimeout("tcp", "localhost:8381", 2*time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
	return conn
}
