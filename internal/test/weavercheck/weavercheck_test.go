// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package weavercheck

import (
	"testing"
)

// recorder is a minimal TestingT that records whether Validate reported a
// failure, without aborting the enclosing test.
type recorder struct{ failed bool }

func (r *recorder) Helper()               {}
func (r *recorder) Logf(string, ...any)   {}
func (r *recorder) Errorf(string, ...any) { r.failed = true }
func (r *recorder) FailNow()              { r.failed = true }

// findingReport mirrors the `compact` template output: a statistics block with
// a positive entity count plus one deduplicated finding. Validate keys off the
// statistics for pass/fail and the findings for the logged detail.
func findingReport(id, level string) Report {
	return Report{
		Findings: []Finding{{
			Message: "advice " + id,
			Level:   level,
			Type:    id,
			Count:   1,
			Signals: []string{"span:GET /test"},
		}},
		Statistics: Statistics{
			TotalEntities:     1,
			AdviceLevelCounts: map[string]int{level: 1},
		},
	}
}

// TestValidateFailsOnViolation pins that a violation-level advisory (e.g. an
// undefined_enum_variant that schemas/obi/.weaver.toml promotes to violation)
// fails validation.
func TestValidateFailsOnViolation(t *testing.T) {
	report := findingReport("undefined_enum_variant", "violation")
	rec := &recorder{}
	Validate(rec, &report)
	if !rec.failed {
		t.Fatal("expected Validate to fail on a violation-level advisory")
	}
}

// TestValidatePassesWithoutViolations pins the inverse: information- and
// improvement-level advice (which .weaver.toml did not promote) does not fail
// validation — the harness no longer promotes advice types itself.
func TestValidatePassesWithoutViolations(t *testing.T) {
	for _, level := range []string{"information", "improvement"} {
		report := findingReport("deprecated", level)
		rec := &recorder{}
		Validate(rec, &report)
		if rec.failed {
			t.Fatalf("expected Validate to pass on %s-level advice", level)
		}
	}
}

// TestValidateFailsOnNoTelemetry pins that an empty report — OTLP never reached
// weaver, so no entities were seen — is a failure rather than a silent pass.
func TestValidateFailsOnNoTelemetry(t *testing.T) {
	rec := &recorder{}
	Validate(rec, &Report{})
	if !rec.failed {
		t.Fatal("expected Validate to fail when weaver received no telemetry")
	}
}
