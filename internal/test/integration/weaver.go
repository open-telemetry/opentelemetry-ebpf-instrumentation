// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/internal/test/integration"

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/weavercheck"
)

const (
	weaverContainer = "weaver"
	weaverAdminPort = 4320
	// weaverTimeout bounds the entire post-/stop sequence (HTTP /stop,
	// docker wait, docker cp of the report file, parse). The drain after
	// /stop scales with the unique signal count — heavy multi-language
	// suites need real headroom.
	weaverTimeout = 3 * time.Minute
)

func SemconvVersion() string {
	// semconv.SchemaURL is "https://opentelemetry.io/schemas/1.41.0"
	return semconv.SchemaURL[strings.LastIndex(semconv.SchemaURL, "/")+1:]
}

func weaverReportPath(t *testing.T) string {
	t.Helper()
	name := strings.ReplaceAll(t.Name(), "/", "_")
	return path.Join(pathOutput, fmt.Sprintf("weaver-report-%s.json", name))
}

// runWeaverValidation stops the weaver container (Docker transport) and
// validates that the emitted telemetry conforms to OpenTelemetry semantic
// conventions, FAILING the test on any actionable advisory (enforce mode).
// This is the entry point for the docker-compose suites and must be called
// while the Docker Compose stack is still running.
func runWeaverValidation(t *testing.T) {
	t.Helper()

	report, ok := fetchWeaverReportDocker(t)
	if !ok {
		return
	}
	weavercheck.Validate(t, report)
}

// fetchWeaverReportDocker stops the weaver container (which runs as a service
// in the Docker Compose stack receiving OTLP from the collector), reads its
// live-check report from the host bind mount, archives it, and parses it. It
// returns the parsed report and ok=true on success. On any failure it records
// the error (or, when a prior test failure is detected, simply tears weaver
// down so the surrounding compose teardown stays clean) and returns ok=false.
//
// This must be called while the Docker Compose stack is still running.
func fetchWeaverReportDocker(t *testing.T) (*weavercheck.Report, bool) {
	t.Helper()

	priorFailure := t.Failed()
	if priorFailure {
		t.Logf("skipping weaver validation: prior test failure detected; " +
			"only stopping the weaver container so compose teardown is clean")
	}

	// weaver writes the report as root; delete via docker exec, not os.Remove.
	const hostReport = "/tmp/obi-weaver-out/live_check.json"
	const containerReport = "/tmp/weaver-out/live_check.json"
	rmCtx, rmCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer rmCancel()
	if _, err := docker.Exec(rmCtx, weaverContainer, "rm", "-f", containerReport); err != nil {
		t.Errorf("removing stale weaver report: %v", err)
		return nil, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), weaverTimeout)
	defer cancel()

	// Signal weaver to stop accepting data and produce its report. If any
	// post-/stop step fails (timeout, container already killed, …) we record
	// the failure and force-remove the container so the surrounding
	// `compose.Close()` still runs and the next test invocation starts from
	// a clean slate.
	url := fmt.Sprintf("http://127.0.0.1:%d/stop", weaverAdminPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("failed to stop weaver (is it running?): %v", err)
		forceRemoveWeaverContainer(t)
		return nil, false
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.Errorf("weaver /stop returned HTTP %d", resp.StatusCode)
		forceRemoveWeaverContainer(t)
		return nil, false
	}

	// Wait for the weaver container to finish processing and exit.
	if _, err = exec.CommandContext(ctx, "docker", "wait", weaverContainer).Output(); err != nil {
		t.Errorf("failed to wait for weaver container: %v", err)
		forceRemoveWeaverContainer(t)
		return nil, false
	}

	if priorFailure {
		return nil, false
	}

	rawReport, err := os.ReadFile(hostReport)
	if err != nil {
		t.Errorf("failed to read weaver report at %s: %v", hostReport, err)
		return nil, false
	}
	return archiveAndParseWeaverReport(t, rawReport)
}

// archiveAndParseWeaverReport archives the raw report next to the other test
// output and parses it into a weavercheck.Report.
func archiveAndParseWeaverReport(t *testing.T, rawReport []byte) (*weavercheck.Report, bool) {
	t.Helper()
	if len(rawReport) == 0 {
		t.Errorf("weaver report is empty")
		return nil, false
	}
	reportPath := weaverReportPath(t)
	if err := os.WriteFile(reportPath, rawReport, 0o644); err != nil {
		t.Logf("warn: failed to archive weaver report to %s: %v", reportPath, err)
	} else {
		t.Logf("weaver report saved to %s", reportPath)
	}
	report, err := weavercheck.Parse(rawReport)
	if err != nil {
		t.Errorf("failed to parse weaver JSON report: %v", err)
		return nil, false
	}
	return report, true
}

// forceRemoveWeaverContainer is the best-effort cleanup we use when the normal
// /stop + docker-wait sequence couldn't finish. Without this, a stuck or
// killed weaver container survives the failed test invocation and the next
// run hits "container name already in use" (or, worse, a half-broken admin
// port that returns "connection reset by peer").
func forceRemoveWeaverContainer(t *testing.T) {
	t.Helper()
	rmCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(rmCtx, "docker", "rm", "-f", weaverContainer).CombinedOutput(); err != nil {
		t.Logf("failed to force-remove weaver container (already gone?): %v; output: %s", err, strings.TrimSpace(string(out)))
	}
}
