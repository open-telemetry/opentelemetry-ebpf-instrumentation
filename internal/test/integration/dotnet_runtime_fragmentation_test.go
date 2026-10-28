// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type dotnetFragmentationSnapshot struct {
	GCIndex           int64     `json:"gcIndex"`
	HeapFragmentation []float64 `json:"heapFragmentation"`
	ServerGC          bool      `json:"serverGC"`
	BackgroundGCIndex int64     `json:"backgroundGCIndex"`
}

func testDotnetFragmentationMetrics(t *testing.T, client *http.Client, workload string, endpoints []string, reconnect func(), server, background bool) {
	t.Helper()
	command := func(path string) dotnetFragmentationSnapshot {
		t.Helper()
		response, err := client.Post(workload+path, "application/json", nil)
		require.NoError(t, err)
		defer response.Body.Close()
		require.Equal(t, http.StatusOK, response.StatusCode)
		var snapshot dotnetFragmentationSnapshot
		require.NoError(t, json.NewDecoder(response.Body).Decode(&snapshot))
		require.Len(t, snapshot.HeapFragmentation, runtimemetrics.DotnetHeapGenerationCount)
		require.Equal(t, server, snapshot.ServerGC, "the runtime must use the requested GC mode")
		return snapshot
	}
	check := func(expected dotnetFragmentationSnapshot) {
		t.Helper()
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			for _, endpoint := range endpoints {
				values, err := scrapeDotnetHeapMetric(client, endpoint, attributes.DotnetGCHeapFragmentation.Prom)
				require.NoError(ct, err)
				require.Equal(ct, expected.HeapFragmentation, values, endpoint)
			}
			response, err := client.Get(workload + "/snapshot")
			require.NoError(ct, err)
			defer response.Body.Close()
			var after dotnetFragmentationSnapshot
			require.NoError(ct, json.NewDecoder(response.Body).Decode(&after))
			require.Equal(ct, expected.GCIndex, after.GCIndex, "comparison must refer to the same collection")
		}, testTimeout, time.Second)
		t.Logf("GC %d fragmentation matches both exporters: %v", expected.GCIndex, expected.HeapFragmentation)
	}
	loaded := command("/fragmentation-load")
	require.Positive(t, loaded.HeapFragmentation[3], "the workload must create LOH holes")
	require.Positive(t, loaded.HeapFragmentation[4], "the workload must create POH holes")
	check(loaded)
	if background {
		concurrent := command("/fragmentation-background")
		require.Greater(t, concurrent.BackgroundGCIndex, loaded.BackgroundGCIndex, "a background GC must actually complete")
		check(concurrent)
	} else {
		require.Zero(t, loaded.BackgroundGCIndex)
	}
	reconnect()
	// This source needs a new complete GC after subscription resumes.
	fresh := command("/gc")
	require.Greater(t, fresh.GCIndex, loaded.GCIndex)
	check(fresh)
	released := command("/fragmentation-release")
	require.Less(t, released.HeapFragmentation[3], loaded.HeapFragmentation[3], "LOH fragmentation must decrease")
	require.Less(t, released.HeapFragmentation[4], loaded.HeapFragmentation[4], "POH fragmentation must decrease")
	check(released)
}
