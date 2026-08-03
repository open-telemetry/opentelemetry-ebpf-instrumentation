// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package weavercheck holds the transport-agnostic parsing and validation of
// the OpenTelemetry weaver live-check report. The Docker-Compose integration
// suites (package integration) and the OATS suites feed weaver the same OTLP
// stream and read back the same JSON report; this package owns the shared
// report schema and the assertion logic so the transports stay in lockstep.
//
// Weaver runs with `--output http` and the `compact` output template;
// FetchReport POSTs the admin `/stop` endpoint and reads the report back from
// the response body (kept small enough by the template to avoid truncation).
// Which advisories are suppressed (the accepted `server`/`client`/`iface`
// namespace collisions) and which information-level advice is promoted to a
// failure (`extends_namespace`, `undefined_enum_variant`) is declared in
// `schemas/obi/.weaver.toml` via `[[live-check.finding_filters]]` and
// `[[live-check.finding_level_overrides]]`, so weaver applies both before the
// report reaches this package. What remains here is a single rule: fail on any
// `violation`-level advisory.
package weavercheck // import "go.opentelemetry.io/obi/internal/test/weavercheck"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"syscall"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestingT is the minimal test-reporter interface Validate needs. Both
// *testing.T (the Docker-Compose integration suites) and ginkgo.GinkgoT() (the
// OATS suites) satisfy it, so the exact same enforce logic runs across every
// transport rather than being reimplemented per suite.
type TestingT interface {
	Helper()
	Logf(format string, args ...any)
	Errorf(format string, args ...any)
	FailNow()
}

// Report is the top-level JSON structure emitted by weaver's `compact`
// live-check template: the statistics block plus a deduplicated findings list.
// The per-sample bodies weaver's builtin `--format json` would emit (attribute
// values, exemplars, data points) are dropped, and the advisories are collapsed
// by message, keeping the report small while preserving every finding's level
// and the signals that triggered it.
type Report struct {
	Findings   []Finding  `json:"findings"`
	Statistics Statistics `json:"statistics"`
}

// Finding is one deduplicated advisory: a message reported at a given level and
// advice type, how many times it occurred, and the distinct signals
// (`<signal_type>:<signal_name>`) that triggered it.
type Finding struct {
	Message string   `json:"message"`
	Level   string   `json:"level"`
	Type    string   `json:"type"`
	Count   int      `json:"count"`
	Signals []string `json:"signals"`
}

type Statistics struct {
	TotalEntities       int            `json:"total_entities"`
	TotalEntitiesByType map[string]int `json:"total_entities_by_type"`
	TotalAdvisories     int            `json:"total_advisories"`
	AdviceLevelCounts   map[string]int `json:"advice_level_counts"`
	RegistryCoverage    float64        `json:"registry_coverage"`
}

// Parse unmarshals a raw weaver JSON report.
func Parse(rawReport []byte) (*Report, error) {
	if len(rawReport) == 0 {
		return nil, errors.New("weaver report is empty")
	}
	var report Report
	if err := json.Unmarshal(rawReport, &report); err != nil {
		return nil, fmt.Errorf("parsing weaver JSON report: %w", err)
	}
	return &report, nil
}

// FetchReport stops the weaver live-check container via its admin /stop
// endpoint and returns the parsed report from the /stop response body (weaver
// runs with `--output http`). The `compact` template keeps that body small
// enough to clear the socket buffer before weaver exits, so the response is not
// truncated. A refused connection (weaver never came up / admin port unmapped)
// is reported distinctly so callers can hint at a mis-wired stack. It is
// transport-agnostic and logging-agnostic (returns an error rather than failing
// a test).
func FetchReport(ctx context.Context, adminURL string) (*Report, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, adminURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building weaver /stop request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("stopping weaver (is it running and the admin port mapped?): %w", err)
		}
		return nil, fmt.Errorf("posting weaver /stop: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("weaver /stop returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading weaver /stop response body: %w", err)
	}
	return Parse(raw)
}

// Validate logs the full advisory breakdown and asserts that weaver reported no
// `violation`-level advisory. Suppression of the accepted namespace collisions
// and promotion of `extends_namespace` / `undefined_enum_variant` to
// `violation` are configured in `schemas/obi/.weaver.toml`, so the level counts
// weaver reports here already reflect them; enforcement is simply "zero
// violations".
func Validate(t TestingT, report *Report) {
	t.Helper()

	stats := &report.Statistics

	// Weaver must have received telemetry data. The `compact` report drops the
	// per-sample bodies, so assert on the entity count rather than sample count.
	require.Positivef(t, stats.TotalEntities,
		"weaver received no telemetry — OTLP data did not reach weaver")

	violations := stats.AdviceLevelCounts["violation"]

	t.Logf("weaver statistics:")
	t.Logf("  total entities:   %d", stats.TotalEntities)
	for _, typ := range sortedKeys(stats.TotalEntitiesByType) {
		t.Logf("    %-15s %d", typ, stats.TotalEntitiesByType[typ])
	}
	t.Logf("  total advisories: %d", stats.TotalAdvisories)
	for _, level := range sortedKeys(stats.AdviceLevelCounts) {
		t.Logf("    %-15s %d", level, stats.AdviceLevelCounts[level])
	}
	t.Logf("  registry coverage: %.1f%%", stats.RegistryCoverage*100)

	// Surface the violation-level advisories first so the cause of a failure is
	// obvious, then log every finding grouped by level. Findings arrive sorted
	// by message (weaver's group_by), so the output is stable.
	if violations > 0 {
		t.Logf("  violation advisories:")
		for i := range report.Findings {
			if f := &report.Findings[i]; f.Level == "violation" {
				t.Logf("    [%dx] %s (signals: %s)", f.Count, f.Message, strings.Join(f.Signals, ", "))
			}
		}
	}
	t.Logf("  advisory details:")
	for _, level := range []string{"violation", "improvement", "information"} {
		for i := range report.Findings {
			if f := &report.Findings[i]; f.Level == level {
				t.Logf("    [%s] [%dx] %s (signals: %s)", f.Level, f.Count, f.Message, strings.Join(f.Signals, ", "))
			}
		}
	}

	assert.Zero(t, violations,
		"weaver found %d violation-level semantic convention advisory(ies)", violations)
}

// sortedKeys returns a count map's keys in lexical order, for stable log output.
func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
