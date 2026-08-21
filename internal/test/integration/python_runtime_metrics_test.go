// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/promtest"
)

const pythonRuntimeMetricsHostPort = "8395"

type pythonRuntimeMetricsImage struct {
	version            string
	image              string
	otelRepresentative bool
}

var pythonRuntimeMetricsImages = []pythonRuntimeMetricsImage{
	{
		version:            "3.9.25",
		image:              "python:3.9.25@sha256:da5aee29682d12a6649f51c8d6f15b87deb3e6c524b923c41d0cb3304d07c913",
		otelRepresentative: true,
	},
	{
		version: "3.10.20",
		image:   "python:3.10.20@sha256:db9dfbd4f3385e3d56790c8f3b811d8eb979e26a674c8032deb862f2e36b3d21",
	},
	{
		version: "3.11.15",
		image:   "python:3.11.15@sha256:d0199e2a90bf7a206a485b115323a75bc946f30b463d704c5435a454aca084dd",
	},
	{
		version: "3.12.7",
		image:   "python:3.12.7@sha256:8d97a0ab83113f8984517f14492f57186d943db7815682cab9d820c9c0a8c998",
	},
	{
		version:            "3.12.12",
		image:              "python:3.12.12@sha256:cb770de9f47e77715f13434d96f7ebaae7ad3a1f4fd9c8b338549bf99c9980ab",
		otelRepresentative: true,
	},
	{
		version: "3.13.14",
		image:   "python:3.13.14@sha256:36f5673ec01bd1001d7cbb8f12215101aa4ee5d70ddbbb72e01b2930d7c12f19",
	},
	{
		version:            "3.14.6",
		image:              "python:3.14.6@sha256:51570a50616289f78f340811c34ca4384985f9e891819cbe7620f738d6ca8525",
		otelRepresentative: true,
	},
}

var unsupportedPythonRuntimeMetricsImage = pythonRuntimeMetricsImage{
	version: "3.8.20-unsupported",
	image:   "python:3.8.20-slim@sha256:314bc2fb0714b7807bf5699c98f0c73817e579799f2d91567ab7e9510f5601a5",
}

type pythonGCStats [3]struct {
	Collections   uint64 `json:"collections"`
	Collected     uint64 `json:"collected"`
	Uncollectable uint64 `json:"uncollectable"`
}

type pythonForkStats struct {
	PID   int           `json:"pid"`
	Stats pythonGCStats `json:"stats"`
}

type pythonForkPID struct {
	PID int `json:"pid"`
}

func TestPythonRuntimeMetricsProm(t *testing.T) {
	runPythonRuntimeMetricsMatrix(t, "prom", pythonRuntimeMetricsImages)
}

func TestPythonRuntimeMetricsOTel(t *testing.T) {
	images := make([]pythonRuntimeMetricsImage, 0, len(pythonRuntimeMetricsImages))
	for _, image := range pythonRuntimeMetricsImages {
		if image.otelRepresentative {
			images = append(images, image)
		}
	}
	runPythonRuntimeMetricsMatrix(t, "otel", images)
}

func TestPythonRuntimeMetricsUnsupported(t *testing.T) {
	compose, pq := startPythonRuntimeMetricsIntegration(t, "prom", unsupportedPythonRuntimeMetricsImage)

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		logs, err := compose.LogsTail(20000, "obi")
		require.NoError(ct, err)
		assert.Contains(ct, logs, "Python runtime metrics target resolution failed")
		assert.Contains(ct, logs, "unsupported CPython runtime layout")
	}, testTimeout, 100*time.Millisecond)

	query := `{__name__=~"cpython_gc_.*",service_name="python-runtime-metrics"}`
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(query)
		require.NoError(ct, err)
		assert.Empty(ct, results)
	}, testTimeout, 100*time.Millisecond)

	var pollingErr error
	assert.Never(t, func() bool {
		logs, err := compose.LogsTail(20000, "obi")
		if err != nil {
			pollingErr = err
			return true
		}
		results, err := pq.Query(query)
		if err != nil {
			pollingErr = err
			return true
		}
		running, err := compose.ServiceRunning("obi")
		if err != nil {
			pollingErr = err
			return true
		}
		return strings.Count(logs, "Python runtime metrics target resolution failed") > 1 || len(results) != 0 || !running
	}, time.Second, 100*time.Millisecond)
	require.NoError(t, pollingErr)

	logs, err := compose.LogsOutput("obi")
	require.NoError(t, err)
	assert.NotContains(t, logs, "panic:")
}

func runPythonRuntimeMetricsMatrix(t *testing.T, exporter string, images []pythonRuntimeMetricsImage) {
	for _, image := range images {
		t.Run("Python "+image.version, func(t *testing.T) {
			runPythonRuntimeMetricsIntegration(t, exporter, image)
		})
	}
}

func runPythonRuntimeMetricsIntegration(t *testing.T, exporter string, image pythonRuntimeMetricsImage) {
	compose, pq := startPythonRuntimeMetricsIntegration(t, exporter, image)
	waitForPythonRuntimeMetricsAttachment(t, compose)

	expectedStats := readPythonGCStats(t, compose, "/collect/0")
	assertPythonRuntimeMetricsEventuallyMatch(t, pq, expectedStats)

	for generation := range expectedStats {
		expectedStats = readPythonGCStats(t, compose, "/collect/"+strconv.Itoa(generation))
		assertPythonRuntimeMetricsEventuallyMatch(t, pq, expectedStats)
		assert.Positive(t, expectedStats[generation].Collections)
		assert.Positive(t, expectedStats[generation].Collected)
	}

	logs, err := compose.LogsTail(20000, "obi")
	require.NoError(t, err)
	attachedBefore := strings.Count(logs, "Python runtime metrics attached")
	forkPID := readPythonForkPID(t, compose, "/fork")
	waitForPythonRuntimeMetricsAttachmentCount(t, compose, attachedBefore+1)
	fork := readPythonForkStats(t, compose, forkPID)
	expectedParentStats := readPythonGCStats(t, compose, "/stats")
	assertPythonRuntimeWorkersEventuallyMatch(t, pq, expectedParentStats, fork.Stats)
	expectedStats = readPythonGCStats(t, compose, "/stop-children")
	if exporter == "prom" {
		assertAutomaticPythonGCEventuallyIncreases(t, compose, pq)
	}

	exportedBeforeExit := waitForPythonRuntimeMetricsStable(t, pq)
	finalStats := readPythonGCStats(t, compose, "/exit")
	expectedExport := addPythonRuntimeMetricDelta(t, exportedBeforeExit, expectedStats, finalStats)
	assertPythonRuntimeMetricsEventuallyMatch(t, pq, expectedExport)
	runWeaverValidation(t)
}

func waitForPythonRuntimeMetricsAttachment(t *testing.T, compose *docker.Compose) {
	t.Helper()
	waitForPythonRuntimeMetricsAttachmentCount(t, compose, 1)
}

func waitForPythonRuntimeMetricsAttachmentCount(t *testing.T, compose *docker.Compose, count int) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		logs, err := compose.LogsTail(20000, "obi")
		require.NoError(ct, err)
		assert.GreaterOrEqual(ct, strings.Count(logs, "Python runtime metrics attached"), count)
	}, testTimeout, 250*time.Millisecond)
}

func startPythonRuntimeMetricsIntegration(
	t *testing.T,
	exporter string,
	image pythonRuntimeMetricsImage,
) (*docker.Compose, pythonRuntimePrometheus) {
	t.Helper()
	versionSlug := strings.ReplaceAll(image.version, ".", "-")
	compose, err := docker.ComposeSuite(
		"docker-compose-python-runtime-metrics.yml",
		path.Join(pathOutput, "test-suite-python-runtime-metrics-"+exporter+"-"+versionSlug+".log"),
	)
	require.NoError(t, err)
	compose.Env = append(compose.Env,
		`TEST_SERVICE_PORTS=`+pythonRuntimeMetricsHostPort+`:8080`,
		`INSTRUMENTER_CONFIG_SUFFIX=-`+exporter,
		`PYTHON_RUNTIME_METRICS_IMAGE=`+image.image,
		`PYTHON_RUNTIME_METRICS_TESTSERVER_IMAGE=hatest-testserver-python-runtime-metrics-`+versionSlug,
	)
	if exporter == "otel" {
		compose.Env = append(compose.Env, `PROM_CONFIG_SUFFIX=-otel`)
	} else {
		compose.Env = append(compose.Env, `PROM_CONFIG_SUFFIX=`)
	}
	require.NoError(t, compose.Up())
	t.Cleanup(func() {
		require.NoError(t, compose.Close())
	})

	waitForPythonRuntimeMetricsService(t, compose)
	return compose, pythonRuntimePrometheus{compose: compose}
}

func readPythonForkPID(t require.TestingT, compose *docker.Compose, endpoint string) int {
	output, err := pythonGCStatsOutput(compose, endpoint)
	require.NoError(t, err)
	var child pythonForkPID
	require.NoError(t, json.Unmarshal([]byte(output), &child))
	require.Positive(t, child.PID)
	return child.PID
}

func readPythonForkStats(t require.TestingT, compose *docker.Compose, pid int) pythonForkStats {
	output, err := pythonGCStatsOutput(compose, "/collect-child/"+strconv.Itoa(pid))
	require.NoError(t, err)
	var stats pythonForkStats
	require.NoError(t, json.Unmarshal([]byte(output), &stats))
	return stats
}

func assertAutomaticPythonGCEventuallyIncreases(
	t *testing.T,
	compose *docker.Compose,
	pq pythonRuntimePrometheus,
) {
	logs, err := compose.LogsTail(20000, "obi")
	require.NoError(t, err)
	attachedBefore := strings.Count(logs, "Python runtime metrics attached")

	childPID := readPythonForkPID(t, compose, "/fork-automatic")

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		logs, err := compose.LogsTail(20000, "obi")
		require.NoError(ct, err)
		assert.Greater(ct, strings.Count(logs, "Python runtime metrics attached"), attachedBefore)
	}, testTimeout, 250*time.Millisecond)
	assert.Positive(t, childPID)

	query := `cpython_gc_collections_total{service_name="python-runtime-metrics"}`
	baseline := pythonRuntimeMetricValue(t, pq, query)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.Greater(ct, pythonRuntimeMetricValue(ct, pq, query), baseline)
	}, testTimeout, 250*time.Millisecond)

	readPythonGCStats(t, compose, "/stop-children")
}

func waitForPythonRuntimeMetricsService(t *testing.T, compose *docker.Compose) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		_, err := pythonGCStatsOutput(compose, "/stats")
		assert.NoError(ct, err)
	}, testTimeout, 250*time.Millisecond)
}

func readPythonGCStats(t require.TestingT, compose *docker.Compose, endpoint string) pythonGCStats {
	output, err := pythonGCStatsOutput(compose, endpoint)
	require.NoError(t, err)

	var stats pythonGCStats
	require.NoError(t, json.Unmarshal([]byte(output), &stats))
	return stats
}

func pythonGCStatsOutput(compose *docker.Compose, endpoint string) (string, error) {
	return compose.ExecOutput(
		"testserver",
		"python3",
		"-c",
		`import sys, urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8080" + sys.argv[1]).read().decode())`,
		endpoint,
	)
}

func assertPythonRuntimeMetricsEventuallyMatch(t *testing.T, pq pythonRuntimePrometheus, expected pythonGCStats) {
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		for generation, stats := range expected {
			labels := fmt.Sprintf(
				`{service_name="python-runtime-metrics",service_namespace="integration-test",cpython_gc_generation="%d"}`,
				generation,
			)
			assert.Equal(ct, stats.Collections, pythonRuntimeMetricValue(ct, pq, "cpython_gc_collections_total"+labels))
			assert.Equal(ct, stats.Collected, pythonRuntimeMetricValue(ct, pq, "cpython_gc_collected_objects_total"+labels))
			assert.Equal(ct, stats.Uncollectable, pythonRuntimeMetricValue(ct, pq, "cpython_gc_uncollectable_objects_total"+labels))
		}
	}, testTimeout, 250*time.Millisecond)
}

func waitForPythonRuntimeMetricsStable(t *testing.T, pq pythonRuntimePrometheus) pythonGCStats {
	var previous pythonGCStats
	var stableSince time.Time
	require.Eventually(t, func() bool {
		current := readPythonRuntimeMetricStats(t, pq)
		if current != previous {
			previous = current
			stableSince = time.Now()
			return false
		}
		return time.Since(stableSince) >= time.Second
	}, testTimeout, 250*time.Millisecond)
	return previous
}

func readPythonRuntimeMetricStats(t require.TestingT, pq pythonRuntimePrometheus) pythonGCStats {
	var stats pythonGCStats
	for generation := range stats {
		labels := fmt.Sprintf(
			`{service_name="python-runtime-metrics",service_namespace="integration-test",cpython_gc_generation="%d"}`,
			generation,
		)
		stats[generation].Collections = pythonRuntimeMetricValue(t, pq, "cpython_gc_collections_total"+labels)
		stats[generation].Collected = pythonRuntimeMetricValue(t, pq, "cpython_gc_collected_objects_total"+labels)
		stats[generation].Uncollectable = pythonRuntimeMetricValue(t, pq, "cpython_gc_uncollectable_objects_total"+labels)
	}
	return stats
}

func addPythonRuntimeMetricDelta(
	t *testing.T,
	exportedBeforeExit pythonGCStats,
	parentBeforeExit pythonGCStats,
	parentAfterExit pythonGCStats,
) pythonGCStats {
	for generation := range exportedBeforeExit {
		require.GreaterOrEqual(t, parentAfterExit[generation].Collections, parentBeforeExit[generation].Collections)
		require.GreaterOrEqual(t, parentAfterExit[generation].Collected, parentBeforeExit[generation].Collected)
		require.GreaterOrEqual(t, parentAfterExit[generation].Uncollectable, parentBeforeExit[generation].Uncollectable)
		exportedBeforeExit[generation].Collections += parentAfterExit[generation].Collections - parentBeforeExit[generation].Collections
		exportedBeforeExit[generation].Collected += parentAfterExit[generation].Collected - parentBeforeExit[generation].Collected
		exportedBeforeExit[generation].Uncollectable += parentAfterExit[generation].Uncollectable - parentBeforeExit[generation].Uncollectable
	}
	return exportedBeforeExit
}

func assertPythonRuntimeWorkersEventuallyMatch(
	t *testing.T,
	pq pythonRuntimePrometheus,
	parent pythonGCStats,
	child pythonGCStats,
) {
	type metricKey struct {
		name       string
		generation int
	}

	query := `{__name__=~"cpython_gc_(collections|collected_objects|uncollectable_objects)_total",` +
		`service_name="python-runtime-metrics",service_namespace="integration-test"}`
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		results, err := pq.Query(query)
		require.NoError(ct, err)

		values := make(map[metricKey]uint64)
		for _, result := range results {
			require.Len(ct, result.Value, prometheusInstantVectorValueLen)
			value, err := strconv.ParseUint(fmt.Sprint(result.Value[1]), 10, 64)
			require.NoError(ct, err)
			generation, err := strconv.Atoi(result.Metric["cpython_gc_generation"])
			require.NoError(ct, err)
			assert.NotContains(ct, result.Metric, "process_pid")

			key := metricKey{name: result.Metric["__name__"], generation: generation}
			values[key] += value
		}

		for generation := range parent {
			for metric, want := range map[string]uint64{
				"cpython_gc_collections_total":           parent[generation].Collections + child[generation].Collections,
				"cpython_gc_collected_objects_total":     parent[generation].Collected + child[generation].Collected,
				"cpython_gc_uncollectable_objects_total": parent[generation].Uncollectable + child[generation].Uncollectable,
			} {
				key := metricKey{name: metric, generation: generation}
				assert.Equal(ct, want, values[key])
			}
		}
	}, testTimeout, 250*time.Millisecond)
}

func pythonRuntimeMetricValue(t require.TestingT, pq pythonRuntimePrometheus, query string) uint64 {
	values := pythonRuntimeMetricValues(t, pq, query)
	require.NotEmptyf(t, values, "expected Prometheus results for %s", query)

	var total uint64
	for _, value := range values {
		total += value
	}
	return total
}

func pythonRuntimeMetricValues(t require.TestingT, pq pythonRuntimePrometheus, query string) []uint64 {
	results, err := pq.Query(query)
	require.NoError(t, err)

	values := make([]uint64, 0, len(results))
	for _, result := range results {
		require.Len(t, result.Value, prometheusInstantVectorValueLen)
		value, parseErr := strconv.ParseUint(fmt.Sprint(result.Value[1]), 10, 64)
		require.NoError(t, parseErr)
		values = append(values, value)
	}
	return values
}

type pythonRuntimePrometheus struct {
	compose *docker.Compose
}

func (p pythonRuntimePrometheus) Query(query string) ([]promtest.Result, error) {
	output, err := p.compose.ExecOutput(
		"queryclient",
		"python3",
		"-c",
		`import sys, urllib.parse, urllib.request; print(urllib.request.urlopen("http://prometheus:9090/api/v1/query?query=" + urllib.parse.quote(sys.argv[1]), timeout=2).read().decode())`,
		query,
	)
	if err != nil {
		return nil, err
	}
	response := struct {
		Status string `json:"status"`
		Data   struct {
			Result []promtest.Result `json:"result"`
		} `json:"data"`
	}{}
	if err := json.Unmarshal([]byte(output), &response); err != nil {
		return nil, err
	}
	if response.Status != "success" {
		return nil, fmt.Errorf("Prometheus query failed with status %q", response.Status)
	}
	return response.Data.Result, nil
}
