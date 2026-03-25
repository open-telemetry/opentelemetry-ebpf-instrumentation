// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"os"
	"os/exec"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	weaverOutputDir = "weaver"
	weaverImage     = "otel/weaver:v0.22.1"
)

// weaverOutputPath returns the path to the directory where the OTEL Collector
// file exporter writes OTLP JSON data for weaver validation.
func weaverOutputPath() string {
	return path.Join(pathOutput, weaverOutputDir)
}

// prepareWeaverOutput creates (or cleans) the weaver output directory so
// the OTEL Collector file exporter can write fresh data for this test run.
func prepareWeaverOutput(t *testing.T) {
	t.Helper()
	dir := weaverOutputPath()
	// Remove any stale data from a previous run.
	_ = os.RemoveAll(dir)
	require.NoError(t, os.MkdirAll(dir, 0o755))
}

// runWeaverValidation runs `weaver registry live-check` on the OTLP JSON
// files captured by the OTEL Collector file exporter during the integration
// test. It validates that all emitted spans and metrics conform to the
// OpenTelemetry semantic conventions.
//
// Weaver runs inside a Docker container (otel/weaver), so no host installation
// is required — only Docker, which is already available in the test environment.
func runWeaverValidation(t *testing.T) {
	t.Helper()

	dir := weaverOutputPath()

	t.Run("traces", func(t *testing.T) {
		weaverLiveCheck(t, dir, "traces.jsonl")
	})
	t.Run("metrics", func(t *testing.T) {
		weaverLiveCheck(t, dir, "metrics.jsonl")
	})
}

func weaverLiveCheck(t *testing.T, hostDir, filename string) {
	t.Helper()

	hostFile := path.Join(hostDir, filename)
	info, err := os.Stat(hostFile)
	if os.IsNotExist(err) || (err == nil && info.Size() == 0) {
		t.Skipf("no OTLP data captured at %s", hostFile)
	}
	require.NoError(t, err)

	containerInput := path.Join("/data", filename)
	cmd := exec.Command("docker", "run", "--rm",
		"-v", hostDir+":/data:ro",
		weaverImage,
		"registry", "live-check",
		"--input-source", containerInput,
		"--format", "ansi",
	)
	output, err := cmd.CombinedOutput()
	t.Logf("weaver output for %s:\n%s", filename, string(output))
	if err != nil {
		t.Errorf("weaver semantic convention validation failed for %s: %s", filename, err)
	}
}
