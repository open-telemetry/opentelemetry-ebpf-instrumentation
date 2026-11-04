// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Report is the part of a `compact` live-check report coverage reads.
type Report struct {
	MatchedSignals   map[string]int      `json:"matched_signals"`
	SignalAttributes map[string][]string `json:"signal_attributes"`
}

type Observed struct {
	Signals          map[string]struct{}
	SignalAttributes map[string]map[string]struct{}
}

// Observe unions the reports. A matched signal counts only with a positive
// count.
func Observe(reports []Report) Observed {
	o := Observed{Signals: map[string]struct{}{}, SignalAttributes: map[string]map[string]struct{}{}}
	for _, r := range reports {
		for name, count := range r.MatchedSignals {
			if count > 0 {
				o.Signals[name] = struct{}{}
			}
		}
		for signal, keys := range r.SignalAttributes {
			seen := o.SignalAttributes[signal]
			if seen == nil {
				seen = map[string]struct{}{}
				o.SignalAttributes[signal] = seen
			}
			for _, k := range keys {
				seen[k] = struct{}{}
			}
		}
	}
	return o
}

type SurfaceResult struct {
	Covered []string `json:"covered"`
	Gaps    []string `json:"gaps"`
}

type SignalAttributesResult struct {
	Signal  string              `json:"signal"`
	Kind    string              `json:"kind"`
	Covered []DeclaredAttribute `json:"covered"`
	Gaps    []DeclaredAttribute `json:"gaps"`
}

type Result struct {
	Reports          int                      `json:"reports"`
	Metrics          SurfaceResult            `json:"metrics"`
	Spans            SurfaceResult            `json:"spans"`
	SignalAttributes []SignalAttributesResult `json:"signal_attributes"`
}

// Aggregate measures the reports against the declared signals. Attribute
// coverage is measured only on signals some suite observed: an unobserved
// signal is already a signal gap, and counting its attributes again would only
// repeat it.
func Aggregate(signals []Signal, reports []Report) Result {
	o := Observe(reports)
	res := Result{
		Reports:          len(reports),
		Metrics:          SurfaceResult{Covered: []string{}, Gaps: []string{}},
		Spans:            SurfaceResult{Covered: []string{}, Gaps: []string{}},
		SignalAttributes: []SignalAttributesResult{},
	}

	for _, s := range signals {
		surface := &res.Metrics
		if s.Kind == kindSpan {
			surface = &res.Spans
		}
		if _, ok := o.Signals[s.Name]; !ok {
			surface.Gaps = append(surface.Gaps, s.Name)
			continue
		}
		surface.Covered = append(surface.Covered, s.Name)
		if len(s.Attributes) == 0 {
			continue
		}

		sr := SignalAttributesResult{Signal: s.Name, Kind: s.Kind, Covered: []DeclaredAttribute{}, Gaps: []DeclaredAttribute{}}
		for _, a := range s.Attributes {
			if a.observedIn(o.SignalAttributes[s.Name]) {
				sr.Covered = append(sr.Covered, a)
			} else {
				sr.Gaps = append(sr.Gaps, a)
			}
		}
		res.SignalAttributes = append(res.SignalAttributes, sr)
	}
	return res
}

// isMandatory reports whether attributes of a requirement level must be on
// every matching sample, which the report lists ahead of the optional ones.
func isMandatory(level string) bool {
	return level == levelRequired || level == levelConditionallyRequired
}

// FailingGaps counts the gaps --fail-on-gap fails on: signals no suite
// observed. Attribute gaps are reported but never fail: some conditions, such
// as error paths, are not reached by every suite.
func (r Result) FailingGaps() int {
	return len(r.Metrics.Gaps) + len(r.Spans.Gaps)
}

func pct(covered, total int) string {
	if total == 0 {
		return "100.0"
	}
	return fmt.Sprintf("%.1f", float64(covered)/float64(total)*100)
}

func (r Result) attributeCountsByLevel() (covered, total map[string]int) {
	covered, total = map[string]int{}, map[string]int{}
	for _, s := range r.SignalAttributes {
		for _, a := range s.Covered {
			covered[a.RequirementLevel]++
			total[a.RequirementLevel]++
		}
		for _, a := range s.Gaps {
			total[a.RequirementLevel]++
		}
	}
	return covered, total
}

func writeGapList(b *strings.Builder, label string, gaps []string) {
	if len(gaps) == 0 {
		fmt.Fprintf(b, "**%s:** all covered\n\n", label)
		return
	}
	fmt.Fprintf(b, "**%s: %d never observed**\n\n", label, len(gaps))
	for _, name := range gaps {
		fmt.Fprintf(b, "- `%s`\n", name)
	}
	b.WriteString("\n")
}

// writeAttributeGaps lists, per signal, the gaps the keep predicate selects.
func (r Result) writeAttributeGaps(b *strings.Builder, keep func(level string) bool) int {
	listed := 0
	for _, s := range r.SignalAttributes {
		var names []string
		for _, g := range s.Gaps {
			if keep(g.RequirementLevel) {
				names = append(names, fmt.Sprintf("`%s` (%s)", g.Key, g.RequirementLevel))
			}
		}
		if len(names) == 0 {
			continue
		}
		fmt.Fprintf(b, "- %s `%s`: %s\n", s.Kind, s.Signal, strings.Join(names, ", "))
		listed++
	}
	return listed
}

func (r Result) Markdown() string {
	var b strings.Builder
	b.WriteString("## Weaver telemetry coverage\n\n")
	fmt.Fprintf(&b, "_Union of %d per-suite weaver report(s). An item is covered when at least one suite emitted it. "+
		"Signal attributes are measured on the signals some suite emitted. Only an uncovered signal fails `--fail-on-gap`._\n\n", r.Reports)

	b.WriteString("| surface | covered | total | coverage |\n| --- | ---: | ---: | ---: |\n")
	row := func(label string, covered, total int) {
		fmt.Fprintf(&b, "| %s | %d | %d | %s%% |\n", label, covered, total, pct(covered, total))
	}
	row("metrics", len(r.Metrics.Covered), len(r.Metrics.Covered)+len(r.Metrics.Gaps))
	row("spans", len(r.Spans.Covered), len(r.Spans.Covered)+len(r.Spans.Gaps))
	covered, total := r.attributeCountsByLevel()
	for _, level := range requirementLevels {
		row("signal attributes, "+level, covered[level], total[level])
	}
	b.WriteString("\n")

	writeGapList(&b, "Uncovered metrics", r.Metrics.Gaps)
	writeGapList(&b, "Uncovered spans", r.Spans.Gaps)

	var attrs strings.Builder
	if n := r.writeAttributeGaps(&attrs, isMandatory); n == 0 {
		b.WriteString("**Required and conditionally required signal attributes:** all covered\n\n")
	} else {
		fmt.Fprintf(&b, "**Required and conditionally required signal attributes: %d signal(s) with gaps**\n\n%s\n", n, attrs.String())
	}

	var informational strings.Builder
	if n := r.writeAttributeGaps(&informational, func(level string) bool { return !isMandatory(level) }); n > 0 {
		fmt.Fprintf(&b, "<details><summary>Recommended and opt-in signal attributes never observed (%d signal(s))</summary>\n\n%s\n</details>\n\n",
			n, informational.String())
	}
	return b.String()
}

// LoadReports reads every weaver-report-*.json under dir. A report that does
// not parse is skipped with a warning, so one broken suite does not discard the
// others; a missing dir yields no reports.
func LoadReports(dir string) ([]Report, error) {
	var reports []Report
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), "weaver-report-") || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var r Report
		if err := json.Unmarshal(raw, &r); err != nil {
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n", path, err)
			return nil
		}
		reports = append(reports, r)
		return nil
	})
	return reports, err
}
