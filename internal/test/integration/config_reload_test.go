// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

const (
	configReloadServerA   = "http://localhost:28060"
	configReloadServerB   = "http://localhost:28061"
	configReloadFirstRule = `        - action: include
          match:
            process:
              open_ports: "18060"`
)

func TestConfigReload(t *testing.T) {
	initial, err := os.ReadFile("configs/obi-config-reload-v2.yml")
	require.NoError(t, err)
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "obi.yml")
	replaceReloadConfig(t, configPath, initial)

	compose, err := docker.ComposeSuite("docker-compose-config-reload.yml", filepath.Join(pathOutput, "test-suite-config-reload.log"))
	require.NoError(t, err)
	compose.Env = append(compose.Env, "CONFIG_RELOAD_DIR="+configDir)
	t.Cleanup(func() { assert.NoError(t, compose.Close()) })
	require.NoError(t, compose.Up())

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, configReloadServerB+"/ready", http.StatusOK)
	}, testTimeout, 250*time.Millisecond)
	waitForReloadTrace(t, "config-reload-a", configReloadServerA, "/initial-selection")
	assertNoReloadTrace(t, "config-reload-b", configReloadServerB, "/initially-excluded")

	cl, err := client.New(client.FromEnv)
	require.NoError(t, err)
	defer cl.Close()
	obiID := testContainerID(t, cl, "hatest-obi")
	require.NotEmpty(t, obiID)
	before, err := cl.ContainerInspect(t.Context(), obiID, client.ContainerInspectOptions{})
	require.NoError(t, err)
	serverPIDs := map[string]uint64{
		"server-a": reloadServerPID(t, compose, "server-a"),
		"server-b": reloadServerPID(t, compose, "server-b"),
	}
	waitForReloadSelection(t, compose, serverPIDs, "server-a")

	secondRule := bytes.ReplaceAll([]byte(configReloadFirstRule), []byte("18060"), []byte("18061"))
	both := bytes.Replace(initial, []byte(configReloadFirstRule), append([]byte(configReloadFirstRule+"\n"), secondRule...), 1)
	replaceReloadConfig(t, configPath, both)
	waitForReloadSelection(t, compose, serverPIDs, "server-a", "server-b")
	waitForReloadTrace(t, "config-reload-b", configReloadServerB, "/added-selection")
	waitForReloadTrace(t, "config-reload-a", configReloadServerA, "/retained-selection")

	t.Log("remove the first definition while retaining the second")
	onlyB := bytes.Replace(initial, []byte(configReloadFirstRule), secondRule, 1)
	replaceReloadConfig(t, configPath, onlyB)
	waitForReloadSelection(t, compose, serverPIDs, "server-b")
	waitForReloadTrace(t, "config-reload-b", configReloadServerB, "/retained-after-removal")
	assertNoReloadTrace(t, "config-reload-a", configReloadServerA, "/removed-selection")

	t.Log("reject a sampler change together with a selection change")
	incompatible := bytes.Replace(initial, []byte("always_on:"), []byte("always_off:"), 1)
	replaceReloadConfig(t, configPath, incompatible)
	waitForReloadRejection(t, compose)
	waitForReloadTrace(t, "config-reload-b", configReloadServerB, "/after-rejection")
	assertNoReloadTrace(t, "config-reload-a", configReloadServerA, "/rejected-selection")

	t.Log("accept a compatible edit after the rejection")
	replaceReloadConfig(t, configPath, initial)
	waitForReloadSelection(t, compose, serverPIDs, "server-a")
	waitForReloadTrace(t, "config-reload-a", configReloadServerA, "/recovered-selection")
	assertNoReloadTrace(t, "config-reload-b", configReloadServerB, "/excluded-after-recovery")

	after, err := cl.ContainerInspect(t.Context(), obiID, client.ContainerInspectOptions{})
	require.NoError(t, err)
	assert.True(t, after.Container.State.Running)
	assert.Equal(t, before.Container.State.StartedAt, after.Container.State.StartedAt)
	assert.Zero(t, after.Container.RestartCount)
}

// Replace the mounted file just as an editor saving through a new inode would.
func replaceReloadConfig(t *testing.T, path string, data []byte) {
	t.Helper()
	replacement := path + ".new"
	require.NoError(t, os.WriteFile(replacement, data, 0o644))
	require.NoError(t, os.Rename(replacement, path))
}

func reloadServerPID(t *testing.T, compose *docker.Compose, service string) uint64 {
	t.Helper()
	// Each server runs as PID 1; OBI's filters use the host PID namespace.
	namespace, err := compose.ExecOutput(service, "python", "-c", "import os; print(os.stat('/proc/1/ns/pid').st_ino)")
	require.NoError(t, err, namespace)
	pids := obiTestToolValues(t, compose, "host-pid", namespace, "1")
	require.Len(t, pids, 1, service)
	for pid := range pids {
		return pid
	}
	return 0
}

func waitForReloadSelection(t *testing.T, compose *docker.Compose, serverPIDs map[string]uint64, selected ...string) {
	t.Helper()
	// A refresh only queues matcher events. The kernel filter changes after the
	// attacher processes them, so negative probes must wait for this exact selection.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		pids := obiTestToolValues(ct, compose, "bitmap-pids", "valid_pids")
		for service, pid := range serverPIDs {
			assert.Equal(ct, slices.Contains(selected, service), pids[pid], "instrumentation state for %s (PID %d)", service, pid)
		}
	}, testTimeout, 250*time.Millisecond)
}

func waitForReloadTrace(t *testing.T, service, server, path string) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		ti.DoHTTPGet(ct, server+path, http.StatusOK)
		trace, err := reloadTrace(service, path)
		require.NoError(ct, err)
		require.NotEmpty(ct, trace.TraceID, "no trace from %s for %s", service, path)
	}, testTimeout, 250*time.Millisecond)
}

func reloadTrace(service, path string) (jaeger.Trace, error) {
	return latestTraceMatching(service, func(trace jaeger.Trace) bool {
		return traceHasSpanTags(trace,
			jaeger.Tag{Key: "url.path", Type: "string", Value: path},
			jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
		)
	})
}

func assertNoReloadTrace(t *testing.T, service, server, path string) {
	t.Helper()
	for range 5 {
		ti.DoHTTPGet(t, server+path, http.StatusOK)
	}
	require.Never(t, func() bool {
		trace, err := reloadTrace(service, path)
		if !assert.NoError(t, err) {
			return true
		}
		return trace.TraceID != ""
	}, 3*time.Second, 250*time.Millisecond, "%s is still instrumented for %s", service, path)
}

func waitForReloadRejection(t *testing.T, compose *docker.Compose) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		logs, err := compose.LogsTail(200, "obi")
		require.NoError(ct, err)
		for line := range strings.SplitSeq(logs, "\n") {
			if strings.Contains(line, "level=ERROR") &&
				strings.Contains(line, "can't refresh configuration") &&
				strings.Contains(line, "restart OBI") {
				return
			}
		}
		assert.Fail(ct, "OBI did not log a refresh rejection requiring a restart")
	}, testTimeout, 250*time.Millisecond)
}
