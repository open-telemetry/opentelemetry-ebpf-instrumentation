// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const resolvedFixture = `{"registry":{
	"attributes":[{"key":"http.route"}],
	"attribute_groups":[{"id":"attributes.obi.http.server","attributes":[{"key":"url.path"}]}],
	"metrics":[
		{"name":"http.server.request.duration","instrument":"histogram","unit":"s","attributes":[
			{"key":"http.request.method","requirement_level":"required"},
			{"key":"http.route","requirement_level":{"conditionally_required":"if the route is known"}},
			{"key":"client.address","requirement_level":"opt_in"}]},
		{"name":"go.goroutine.count","instrument":"updowncounter","unit":"{goroutine}","attributes":[]},
		{"name":"target.info","instrument":"updowncounter","unit":"","attributes":[
			{"key":"service.name","requirement_level":"required"},
			{"key":"host.id"}]}
	],
	"spans":[
		{"type":"obi.http.server","kind":"server","name":{"templates":["{http.request.method} {http.route}"]},"attributes":[
			{"key":"url.path","requirement_level":"required"},
			{"key":"http.request.header","type":"template[string[]]","requirement_level":"opt_in"},
			{"key":"server.port","requirement_level":{"recommended":"if known"}}]}
	],
	"entities":[],
	"events":[]
}}`

func fixtureSignals(t *testing.T) []Signal {
	t.Helper()
	signals, err := parseSignals([]byte(resolvedFixture))
	require.NoError(t, err)
	return signals
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestParseSignals(t *testing.T) {
	assert.Equal(t, []Signal{
		{Name: "go.goroutine.count", Kind: kindMetric, Attributes: []DeclaredAttribute{}},
		{Name: "http.server.request.duration", Kind: kindMetric, Attributes: []DeclaredAttribute{
			{Key: "client.address", RequirementLevel: levelOptIn},
			{Key: "http.request.method", RequirementLevel: levelRequired},
			{Key: "http.route", RequirementLevel: levelConditionallyRequired},
		}},
		{Name: "obi.http.server", Kind: kindSpan, Attributes: []DeclaredAttribute{
			{Key: "http.request.header", RequirementLevel: levelOptIn, Template: true},
			{Key: "server.port", RequirementLevel: levelRecommended},
			{Key: "url.path", RequirementLevel: levelRequired},
		}},
		{Name: "target.info", Kind: kindMetric, Attributes: []DeclaredAttribute{
			{Key: "host.id", RequirementLevel: levelRecommended},
			{Key: "service.name", RequirementLevel: levelRequired},
		}},
	}, fixtureSignals(t))
}

func TestParseSignalsRejectsAnEmptyRegistry(t *testing.T) {
	_, err := parseSignals([]byte(`{"registry":{"metrics":[],"spans":[]}}`))
	require.Error(t, err)

	_, err = parseSignals([]byte(`not json`))
	require.Error(t, err)
}

func TestObserveUnionsReports(t *testing.T) {
	o := Observe([]Report{
		{
			MatchedSignals:   map[string]int{"obi.http.server": 3, "go.goroutine.count": 0},
			SignalAttributes: map[string][]string{"obi.http.server": {"url.path"}},
		},
		{
			MatchedSignals:   map[string]int{"target.info": 1},
			SignalAttributes: map[string][]string{"obi.http.server": {"server.port"}, "target.info": {"service.name"}},
		},
	})

	assert.Equal(t, []string{"obi.http.server", "target.info"}, sortedKeys(o.Signals), "a zero count is not an observation")
	assert.Equal(t, []string{"server.port", "url.path"}, sortedKeys(o.SignalAttributes["obi.http.server"]))
	assert.Equal(t, []string{"service.name"}, sortedKeys(o.SignalAttributes["target.info"]))
}

func TestAggregateSplitsCoveredAndGaps(t *testing.T) {
	res := Aggregate(fixtureSignals(t), []Report{{
		MatchedSignals: map[string]int{"obi.http.server": 1, "http.server.request.duration": 1},
		SignalAttributes: map[string][]string{
			"obi.http.server":              {"url.path", "undeclared.key", "http.request.header.accept"},
			"http.server.request.duration": {"http.request.method"},
		},
	}})

	assert.Equal(t, 1, res.Reports)
	assert.Equal(t, SurfaceResult{Covered: []string{"http.server.request.duration"}, Gaps: []string{"go.goroutine.count", "target.info"}}, res.Metrics)
	assert.Equal(t, SurfaceResult{Covered: []string{"obi.http.server"}, Gaps: []string{}}, res.Spans)

	assert.Equal(t, []SignalAttributesResult{
		{
			Signal: "http.server.request.duration", Kind: kindMetric,
			Covered: []DeclaredAttribute{{Key: "http.request.method", RequirementLevel: levelRequired}},
			Gaps: []DeclaredAttribute{
				{Key: "client.address", RequirementLevel: levelOptIn},
				{Key: "http.route", RequirementLevel: levelConditionallyRequired},
			},
		},
		{
			Signal: "obi.http.server", Kind: kindSpan,
			Covered: []DeclaredAttribute{
				{Key: "http.request.header", RequirementLevel: levelOptIn, Template: true},
				{Key: "url.path", RequirementLevel: levelRequired},
			},
			Gaps: []DeclaredAttribute{{Key: "server.port", RequirementLevel: levelRecommended}},
		},
	}, res.SignalAttributes, "only observed signals are measured, a template is observed through its keys, and undeclared keys are ignored")

	assert.Equal(t, 2, res.FailingGaps(), "two signal gaps; attribute gaps never fail")
}

func TestAggregateFullCoverageHasNoFailingGaps(t *testing.T) {
	signals := []Signal{{Name: "m", Kind: kindMetric, Attributes: []DeclaredAttribute{
		{Key: "a", RequirementLevel: levelRequired},
		{Key: "o", RequirementLevel: levelOptIn},
	}}}
	res := Aggregate(signals, []Report{{
		MatchedSignals:   map[string]int{"m": 1},
		SignalAttributes: map[string][]string{"m": {"a"}},
	}})

	assert.Zero(t, res.FailingGaps())
	assert.Equal(t, []DeclaredAttribute{{Key: "o", RequirementLevel: levelOptIn}}, res.SignalAttributes[0].Gaps)
}

func TestMarkdownReportsTableAndGaps(t *testing.T) {
	res := Aggregate(fixtureSignals(t), []Report{{
		MatchedSignals: map[string]int{"obi.http.server": 1, "http.server.request.duration": 1},
		SignalAttributes: map[string][]string{
			"obi.http.server":              {"url.path"},
			"http.server.request.duration": {"http.request.method"},
		},
	}})

	md := res.Markdown()

	assert.Contains(t, md, "## Weaver telemetry coverage")
	assert.Contains(t, md, "| metrics | 1 | 3 | 33.3% |")
	assert.Contains(t, md, "| spans | 1 | 1 | 100.0% |")
	assert.Contains(t, md, "| signal attributes, required | 2 | 2 | 100.0% |")
	assert.Contains(t, md, "| signal attributes, conditionally_required | 0 | 1 | 0.0% |")
	assert.Contains(t, md, "| signal attributes, opt_in | 0 | 2 | 0.0% |")
	assert.Contains(t, md, "**Uncovered metrics: 2 never observed**")
	assert.Contains(t, md, "- `go.goroutine.count`")
	assert.Contains(t, md, "**Uncovered spans:** all covered")
	assert.Contains(t, md, "- metric `http.server.request.duration`: `http.route` (conditionally_required)\n")
	assert.Contains(t, md, "<details><summary>Recommended and opt-in signal attributes never observed (2 signal(s))</summary>")
	assert.Contains(t, md, "- metric `http.server.request.duration`: `client.address` (opt_in)\n")
	assert.Contains(t, md, "- span `obi.http.server`: `http.request.header` (opt_in), `server.port` (recommended)\n")
}

func TestMarkdownAllCovered(t *testing.T) {
	signals := []Signal{{Name: "m", Kind: kindMetric, Attributes: []DeclaredAttribute{{Key: "a", RequirementLevel: levelRequired}}}}
	res := Aggregate(signals, []Report{{
		MatchedSignals:   map[string]int{"m": 1},
		SignalAttributes: map[string][]string{"m": {"a"}},
	}})

	md := res.Markdown()

	assert.Contains(t, md, "**Uncovered metrics:** all covered")
	assert.Contains(t, md, "**Required and conditionally required signal attributes:** all covered")
	assert.NotContains(t, md, "<details>")
}

func TestLoadReportsWalksAndParses(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "shard-1"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "shard-2"), 0o755))
	write := func(p, body string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, p), []byte(body), 0o644))
	}
	write("shard-1/weaver-report-Foo.json", `{"matched_signals":{"obi.dns":1},"signal_attributes":{"obi.dns":["dns.question.name"]}}`)
	write("shard-2/weaver-report-Bar.json", `{"matched_signals":{"B":1}}`)
	write("shard-1/other.json", `not a report`)
	write("shard-1/integration.log", `ignored`)

	reports, err := LoadReports(dir)
	require.NoError(t, err)
	require.Len(t, reports, 2, "only weaver-report-*.json files are loaded")

	o := Observe(reports)
	assert.Equal(t, []string{"B", "obi.dns"}, sortedKeys(o.Signals))
	assert.Equal(t, []string{"dns.question.name"}, sortedKeys(o.SignalAttributes["obi.dns"]))
}

func TestLoadReportsSkipsMalformedReport(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "weaver-report-Bad.json"), []byte(`{not json}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "weaver-report-Good.json"), []byte(`{"matched_signals":{"m":1}}`), 0o644))

	reports, err := LoadReports(dir)
	require.NoError(t, err)
	require.Len(t, reports, 1, "a malformed report must not discard the others")
}

func TestLoadReportsMissingDir(t *testing.T) {
	reports, err := LoadReports(filepath.Join(t.TempDir(), "absent"))
	require.NoError(t, err)
	assert.Empty(t, reports)
}

func TestLoadReportsEmptyDir(t *testing.T) {
	reports, err := LoadReports(t.TempDir())
	require.NoError(t, err)
	assert.Empty(t, reports)
}
