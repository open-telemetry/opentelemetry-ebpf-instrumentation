// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && dotnet_live

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

// TestDotnetRuntimeEventsLive validates the managed EventPipe reference reader.
// The resulting fixtures are inputs for the OBI Go reader implementation.
func TestDotnetRuntimeEventsLive(t *testing.T) {
	require.NoError(t, os.MkdirAll(pathOutput, 0o755))
	output, err := os.MkdirTemp(pathOutput, "dotnet-runtime-events-") //nolint:usetesting // Retain reference fixtures after the test for Go decoder development.
	require.NoError(t, err)
	t.Logf("EventPipe fixtures: %s", output)
	compose, err := docker.ComposeSuite("docker-compose-dotnet-runtime-events-live.yml",
		filepath.Join(output, "compose.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env,
		"DOTNET_RUNTIME_OUTPUT="+output,
		"COMPOSE_PROJECT_NAME=obi-"+filepath.Base(output),
	)
	t.Cleanup(func() {
		require.NoError(t, compose.Close())
	})
	require.NoError(t, compose.Run("collector"), "see %s", filepath.Join(output, "compose.log"))

	data, err := os.ReadFile(filepath.Join(output, "result.json"))
	require.NoError(t, err)
	var result struct {
		RuntimeVersion    string    `json:"runtimeVersion"`
		ForcedCollections int       `json:"forcedCollections"`
		Expected          []float64 `json:"expected"`
		Observed          []float64 `json:"observed"`
		ProcessorCount    float64   `json:"processorCount"`
		WorkingSetMB      float64   `json:"workingSetMB"`
		AllocatedBytes    float64   `json:"allocatedBytes"`
		EventsLost        int       `json:"eventsLost"`
		EventCount        int       `json:"eventCount"`
	}
	require.NoError(t, json.Unmarshal(data, &result))
	require.Contains(t, result.RuntimeVersion, "8.0.")
	require.Equal(t, 3, result.ForcedCollections)
	require.Len(t, result.Expected, 3)
	require.Equal(t, result.Expected, result.Observed)
	for _, count := range result.Expected {
		require.GreaterOrEqual(t, count, float64(result.ForcedCollections))
	}
	require.Positive(t, result.ProcessorCount)
	require.Positive(t, result.WorkingSetMB)
	require.Positive(t, result.AllocatedBytes)
	require.Zero(t, result.EventsLost)
	require.Positive(t, result.EventCount)
	for _, name := range []string{"runtime.nettrace", "events.jsonl", "workload.jsonl"} {
		info, err := os.Stat(filepath.Join(output, name))
		require.NoError(t, err)
		require.Positive(t, info.Size(), "%s is empty", name)
	}
}
