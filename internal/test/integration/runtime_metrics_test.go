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
)

func testRuntimeMetricsGo(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	metrics := []struct {
		runtimeName string
		obiName     string
	}{
		{runtimeName: "/gc/gomemlimit:bytes", obiName: "go_memory_limit_bytes"},
		{runtimeName: "/sched/gomaxprocs:threads", obiName: "go_processor_limit"},
		{runtimeName: "/gc/gogc:percent", obiName: "go_config_gogc_percent"},
		{runtimeName: "/gc/cycles/total:gc-cycles", obiName: "go_memory_gc_cycles_total"},
	}

	forceRuntimeGC(t)
	expected := readRuntimeMetrics(t)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		forceRuntimeGC(ct)
		current := readRuntimeMetrics(ct)
		for _, metric := range metrics {
			obiValue := runtimeMetricValue(ct, pq, metric.obiName)
			assertRuntimeMetricObserved(ct, expected, current, metric.runtimeName, obiValue, metric.obiName)
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
