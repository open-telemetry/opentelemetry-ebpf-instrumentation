// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/pkg/export/attributes"
)

func TestDotnetRuntimeMetrics(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-dotnet-runtime-metrics.yml",
		filepath.Join(pathOutput, "test-suite-dotnet-runtime-metrics.log"))
	require.NoError(t, err)
	socketDir := t.TempDir()
	compose.Env = append(compose.Env, "COMPOSE_PROJECT_NAME=obi-dotnet-runtime-metrics",
		"DOTNET_RUNTIME_SOCKET_DIR="+socketDir,
		fmt.Sprintf("DOTNET_RUNTIME_USER=%d:%d", os.Getuid(), os.Getgid()))
	t.Cleanup(func() { require.NoError(t, compose.Close()) })
	require.NoError(t, compose.Up())

	client := &http.Client{Timeout: 2 * time.Second}
	const workload = "http://localhost:18080"
	var before struct {
		PID            int    `json:"pid"`
		RuntimeVersion string `json:"runtimeVersion"`
		Gen0           int    `json:"gen0"`
		Gen1           int    `json:"gen1"`
		Gen2           int    `json:"gen2"`
	}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		response, err := client.Get(workload + "/snapshot")
		require.NoError(ct, err)
		defer response.Body.Close()
		require.Equal(ct, http.StatusOK, response.StatusCode)
		require.NoError(ct, json.NewDecoder(response.Body).Decode(&before))
		require.Contains(ct, before.RuntimeVersion, "8.0.")
	}, testTimeout, time.Second)

	endpoints := []string{"http://localhost:18999/metrics", "http://localhost:19464/metrics"}
	baseline := make([][3]float64, len(endpoints))
	for index, endpoint := range endpoints {
		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			values, err := scrapeDotnetGC(client, endpoint)
			require.NoError(ct, err)
			baseline[index] = values
		}, testTimeout, time.Second)
	}

	initialPID := before.PID
	sessionPattern := regexp.MustCompile(`started EventPipe GC collection[^\n]* session=([0-9]+)`)
	currentSession := func() (uint64, error) {
		logs, err := compose.LogsOutput("obi")
		if err != nil {
			return 0, err
		}
		matches := sessionPattern.FindAllStringSubmatch(logs, -1)
		if len(matches) == 0 {
			return 0, fmt.Errorf("no EventPipe session found in OBI logs")
		}
		return strconv.ParseUint(matches[len(matches)-1][1], 10, 64)
	}
	for round := range 2 {
		if round == 1 {
			previousSession, err := currentSession()
			require.NoError(t, err)
			stopDotnetDiagnosticSession(t, socketDir, previousSession)
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				session, err := currentSession()
				require.NoError(ct, err)
				require.NotEqual(ct, previousSession, session, "OBI must open a replacement EventPipe session")
			}, testTimeout, time.Second)

			// Allow baseline samples and both export intervals to pass, checking
			// that reconnecting preserves the totals before another forced GC.
			for range 5 {
				select {
				case <-time.After(time.Second):
				case <-t.Context().Done():
					t.Fatal(t.Context().Err())
				}
				for index, endpoint := range endpoints {
					values, err := scrapeDotnetGC(client, endpoint)
					require.NoError(t, err)
					require.Equal(t, baseline[index], values)
				}
			}
		}
		// Read the runtime's own counters immediately around the forced full GC.
		response, err := client.Get(workload + "/snapshot")
		require.NoError(t, err)
		require.NoError(t, json.NewDecoder(response.Body).Decode(&before))
		require.Equal(t, initialPID, before.PID)
		require.NoError(t, response.Body.Close())
		response, err = client.Post(workload+"/gc", "application/json", nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		after := before
		require.NoError(t, json.NewDecoder(response.Body).Decode(&after))
		require.NoError(t, response.Body.Close())
		require.Equal(t, before.PID, after.PID)
		require.Equal(t, before.Gen2+1, after.Gen2)
		delta := [3]float64{
			float64((after.Gen0 - before.Gen0) - (after.Gen1 - before.Gen1)),
			float64((after.Gen1 - before.Gen1) - (after.Gen2 - before.Gen2)),
			float64(after.Gen2 - before.Gen2),
		}
		for index, endpoint := range endpoints {
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				values, err := scrapeDotnetGC(client, endpoint)
				require.NoError(ct, err)
				for generation := range values {
					require.InDelta(ct, baseline[index][generation]+delta[generation], values[generation], 0)
				}
			}, testTimeout, time.Second)
			for generation := range delta {
				baseline[index][generation] += delta[generation]
			}
		}
		t.Logf("GC round %d: PID %d, Prometheus %v, OTLP %v", round+1, before.PID, baseline[0], baseline[1])
	}
}

// scrapeDotnetGC requires all three exclusive generation series and the service
// identity on both OBI's endpoint and the OTLP collector's Prometheus exporter.
func scrapeDotnetGC(client *http.Client, endpoint string) ([3]float64, error) {
	var values [3]float64
	response, err := client.Get(endpoint)
	if err != nil {
		return values, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return values, fmt.Errorf("metrics endpoint returned %s", response.Status)
	}
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(response.Body)
	if err != nil {
		return values, err
	}
	family := families[attributes.DotnetGCCollections.Prom]
	var seen [3]bool
	for _, metric := range family.GetMetric() {
		labels := make(map[string]string)
		for _, label := range metric.GetLabel() {
			labels[label.GetName()] = label.GetValue()
		}
		if labels["service_name"] != "dotnet-runtime" || labels["service_namespace"] != "integration-test" {
			continue
		}
		for generation := range values {
			if labels["dotnet_gc_heap_generation"] == fmt.Sprintf("gen%d", generation) {
				if seen[generation] || metric.Counter == nil {
					return values, fmt.Errorf("invalid or duplicate GC generation %d series", generation)
				}
				seen[generation] = true
				values[generation] = metric.GetCounter().GetValue()
			}
		}
	}
	if seen != [3]bool{true, true, true} {
		return values, fmt.Errorf("missing GC generation series: found %v", seen)
	}
	return values, nil
}

// StopTracing ends OBI's active stream without restarting the application.
func stopDotnetDiagnosticSession(t *testing.T, directory string, sessionID uint64) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(directory, "dotnet-diagnostic-*-socket"))
	require.NoError(t, err)
	require.Len(t, paths, 1)
	root, err := os.Open(directory)
	require.NoError(t, err)
	defer root.Close()
	// Use the directory FD to stay below Unix socket path length limits.
	path := fmt.Sprintf("/proc/self/fd/%d/%s", root.Fd(), filepath.Base(paths[0]))
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	// Diagnostic IPC v1: 28-byte message, EventPipe command set 2, StopTracing 1.
	header, err := hex.DecodeString("444f544e45545f4950435f5631001c0002010000")
	require.NoError(t, err)
	request := binary.LittleEndian.AppendUint64(header, sessionID)
	written, err := conn.Write(request)
	require.NoError(t, err)
	require.Equal(t, len(request), written)
	response := make([]byte, len(request))
	_, err = io.ReadFull(conn, response)
	require.NoError(t, err)
	// A successful server reply echoes the stopped session ID.
	request[16], request[17] = 0xff, 0
	require.Equal(t, request, response)
}
