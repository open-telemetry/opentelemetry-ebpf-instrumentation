// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type dotnetHeapSnapshot struct {
	GCIndex   int64     `json:"gcIndex"`
	HeapSizes []float64 `json:"heapSizes"`
}

func testDotnetHeapMetrics(t *testing.T, client *http.Client, workload string, endpoints []string, reconnect func()) {
	t.Helper()
	command := func(path string) dotnetHeapSnapshot {
		t.Helper()
		response, err := client.Post(workload+path, "application/json", nil)
		require.NoError(t, err)
		defer response.Body.Close()
		require.Equal(t, http.StatusOK, response.StatusCode)
		var snapshot dotnetHeapSnapshot
		require.NoError(t, json.NewDecoder(response.Body).Decode(&snapshot))
		require.Len(t, snapshot.HeapSizes, runtimemetrics.DotnetHeapGenerationCount)
		return snapshot
	}
	check := func(expected dotnetHeapSnapshot) {
		t.Helper()
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			for _, endpoint := range endpoints {
				values, err := scrapeDotnetHeap(client, endpoint)
				require.NoError(ct, err)
				require.Equal(ct, expected.HeapSizes, values, endpoint)
			}
			response, err := client.Get(workload + "/snapshot")
			require.NoError(ct, err)
			defer response.Body.Close()
			var after dotnetHeapSnapshot
			require.NoError(ct, json.NewDecoder(response.Body).Decode(&after))
			require.Equal(ct, expected.GCIndex, after.GCIndex, "comparison must refer to the same collection")
		}, testTimeout, time.Second)
	}
	before := command("/heap-release")
	check(before)
	loaded := command("/heap-load")
	for _, generation := range []int{1, 2, 3, 4} {
		require.Greater(t, loaded.HeapSizes[generation], before.HeapSizes[generation])
	}
	check(loaded)
	reconnect()
	check(loaded)
	released := command("/heap-release")
	// LOH and POH can retain fragmented space. Small-object generations must shrink.
	for _, generation := range []int{1, 2} {
		require.Less(t, released.HeapSizes[generation], loaded.HeapSizes[generation])
	}
	check(released)
	t.Logf("heap sizes match managed reference on both exporters: before %v, loaded %v, released %v", before.HeapSizes, loaded.HeapSizes, released.HeapSizes)
}

func scrapeDotnetHeap(client *http.Client, endpoint string) ([]float64, error) {
	response, err := client.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics response: %s", response.Status)
	}
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(response.Body)
	if err != nil {
		return nil, err
	}
	family := families[attributes.DotnetGCHeapSize.Prom]
	if family == nil || family.GetType() != dto.MetricType_GAUGE {
		return nil, fmt.Errorf("missing heap size gauge from %s", endpoint)
	}
	values := make([]float64, runtimemetrics.DotnetHeapGenerationCount)
	seen := [runtimemetrics.DotnetHeapGenerationCount]bool{}
	for _, metric := range family.Metric {
		labels := map[string]string{}
		for _, label := range metric.Label {
			labels[label.GetName()] = label.GetValue()
		}
		if labels["service_name"] != "dotnet-runtime" || labels["service_namespace"] != "integration-test" {
			continue
		}
		for generation, name := range runtimemetrics.DotnetHeapGenerations() {
			if labels["dotnet_gc_heap_generation"] == name {
				if seen[generation] || metric.Gauge == nil {
					return nil, fmt.Errorf("invalid or duplicate heap generation %s", name)
				}
				seen[generation] = true
				values[generation] = metric.GetGauge().GetValue()
			}
		}
	}
	for generation, found := range seen {
		if !found {
			return nil, fmt.Errorf("missing heap generation %d", generation)
		}
	}
	return values, nil
}
