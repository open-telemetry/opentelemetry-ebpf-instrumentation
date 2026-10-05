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
// a positive entity count plus one deduplicated finding. Validate counts
// violations from the findings, which the template has already filtered.
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

// TestValidateIgnoresViolationsTheTemplateDropped pins that a violation weaver
// counted in its statistics but the compact template filtered out of the
// findings does not fail validation.
func TestValidateIgnoresViolationsTheTemplateDropped(t *testing.T) {
	report := Report{
		Statistics: Statistics{
			TotalEntities:     1,
			AdviceLevelCounts: map[string]int{"violation": 1},
		},
		ViolationsSeen: 1,
	}
	rec := &recorder{}
	Validate(rec, &report)
	if rec.failed {
		t.Fatal("expected Validate to pass when every violation was filtered out of the findings")
	}
}

// TestValidateFailsOnViolationsTheTemplateMissed pins that a violation weaver
// counted but the report template never saw fails, so a change in weaver's
// report format cannot empty the findings and pass every suite.
func TestValidateFailsOnViolationsTheTemplateMissed(t *testing.T) {
	report := Report{Statistics: Statistics{
		TotalEntities:     1,
		AdviceLevelCounts: map[string]int{"violation": 1},
	}}
	rec := &recorder{}
	Validate(rec, &report)
	if !rec.failed {
		t.Fatal("expected Validate to fail when the template saw fewer violations than weaver counted")
	}
}

// TestValidateFailsOnMatcherErrors pins that a matcher whose condition errors
// fails validation, even when another matcher picked up the samples.
func TestValidateFailsOnMatcherErrors(t *testing.T) {
	report := Report{Statistics: Statistics{
		TotalEntities: 1,
		Matchers:      []Matcher{{ID: "match.span.broken", Errors: 2, FirstError: "no such key"}},
	}}
	rec := &recorder{}
	Validate(rec, &report)
	if !rec.failed {
		t.Fatal("expected Validate to fail when a matcher reported errors")
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

// TestValidateFailsOnUnmatchedSpan pins that a span no matcher paired with a
// span definition fails validation even without a violation: its attributes
// were never compared with a definition, so a clean report would be vacuous.
func TestValidateFailsOnUnmatchedSpan(t *testing.T) {
	report := findingReport("recommended_attribute_not_present", "improvement")
	report.Unmatched = []UnmatchedGroup{{
		SampleType: "span",
		Kind:       "internal",
		Count:      2,
		Names:      []string{"in queue"},
	}}
	rec := &recorder{}
	Validate(rec, &report)
	if !rec.failed {
		t.Fatal("expected Validate to fail on a span that matched no span definition")
	}
}

// TestValidatePassesWhenMatchersMatchedNothing pins that a matcher that applied
// to no sample is not a failure: a suite exercises only some span definitions.
func TestValidatePassesWhenMatchersMatchedNothing(t *testing.T) {
	report := findingReport("recommended_attribute_not_present", "improvement")
	report.Statistics.Matchers = []Matcher{
		{ID: "match.span.http.server", Matched: 1},
		{ID: "match.span.dns"},
	}
	rec := &recorder{}
	Validate(rec, &report)
	if rec.failed {
		t.Fatal("expected Validate to pass when some matchers applied to no sample")
	}
}

// compactReport mirrors the `compact` template output of weaver's v2
// live-check, including the matching blocks.
const compactReport = `{
	"findings": [{"message": "advice", "level": "improvement", "type": "span_name_mismatch", "count": 1, "signals": ["span:GET wrong"]}],
	"matched_signals": {"obi.http.server": 2},
	"statistics": {
		"total_entities": 4,
		"total_entities_by_type": {"span": 4},
		"advice_level_counts": {"improvement": 1},
		"matchers": [{"id": "match.span.http.server", "matched": 2, "errors": 0, "first_error": null}]
	},
	"unmatched": [{"sample_type": "span", "kind": "internal", "attributes": [], "count": 1, "names": ["in queue"]}]
}`

// TestParseReadsMatching pins the report fields the matching rules rely on.
func TestParseReadsMatching(t *testing.T) {
	report, err := Parse([]byte(compactReport))
	if err != nil {
		t.Fatalf("parsing the compact report: %v", err)
	}
	if len(report.Unmatched) != 1 || report.Unmatched[0].Names[0] != "in queue" || report.Unmatched[0].Count != 1 {
		t.Fatalf("unexpected unmatched samples: %+v", report.Unmatched)
	}
	if len(report.Statistics.Matchers) != 1 || report.Statistics.Matchers[0].Matched != 2 {
		t.Fatalf("unexpected matcher statistics: %+v", report.Statistics.Matchers)
	}
	if report.MatchedSignals["obi.http.server"] != 2 {
		t.Fatalf("unexpected matched signals: %+v", report.MatchedSignals)
	}
}
