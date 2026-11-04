// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package schemacheck holds tests that validate the OBI semantic-convention
// registry against the pinned upstream OpenTelemetry semantic conventions it
// depends on.
package schemacheck

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	obiGroupsDir = "../../schemas/obi/groups"
	upstreamDeps = "../../schemas/obi/.deps"
)

type metricFields struct {
	Unit        string `yaml:"unit"`
	Instrument  string `yaml:"instrument"`
	Stability   string `yaml:"stability"`
	Annotations struct {
		OBI struct {
			Upstream upstreamLink `yaml:"upstream"`
		} `yaml:"obi"`
	} `yaml:"annotations"`
}

// metricGroupsFile reads metrics from both definition formats: OBI's registry
// is definition/2 (`metrics:`), while the upstream semconv release it pins is
// still the groups format (`groups:` of `type: metric`).
type metricGroupsFile struct {
	Groups []struct {
		Type         string `yaml:"type"`
		MetricName   string `yaml:"metric_name"`
		metricFields `yaml:",inline"`
	} `yaml:"groups"`
	Metrics []struct {
		Name         string `yaml:"name"`
		metricFields `yaml:",inline"`
	} `yaml:"metrics"`
}

type metricDef struct {
	unit       string
	instrument string
	stability  string
	link       upstreamLink
	source     string
}

func metricsFromFile(t *testing.T, path string, out map[string]metricDef) {
	t.Helper()
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	var f metricGroupsFile
	require.NoErrorf(t, yaml.Unmarshal(body, &f), "parsing %s", path)
	add := func(name string, m metricFields) {
		out[name] = metricDef{
			unit:       m.Unit,
			instrument: m.Instrument,
			stability:  m.Stability,
			link:       m.Annotations.OBI.Upstream,
			source:     path,
		}
	}
	for _, g := range f.Groups {
		if g.Type == "metric" && g.MetricName != "" {
			add(g.MetricName, g.metricFields)
		}
	}
	for _, m := range f.Metrics {
		add(m.Name, m.metricFields)
	}
}

func obiMetrics(t *testing.T) map[string]metricDef {
	t.Helper()
	out := map[string]metricDef{}
	err := filepath.WalkDir(obiGroupsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		metricsFromFile(t, path, out)
		return nil
	})
	require.NoError(t, err)
	return out
}

// overrideMetrics returns the OBI metrics declared under an upstream metric's
// name — the narrowed re-declarations of upstream semconv metrics, as opposed
// to OBI-invented metrics.
func overrideMetrics(t *testing.T) map[string]metricDef {
	t.Helper()
	upstream := upstreamMetrics(t)
	out := map[string]metricDef{}
	for name, m := range obiMetrics(t) {
		if _, ok := upstream[name]; ok {
			out[name] = m
		}
	}
	return out
}

// implementedMetric returns the upstream metric a local metric implements: the
// first one its annotation names or, without an annotation, the upstream
// metric of the same name, if there is one.
func implementedMetric(name string, m metricDef, upstream map[string]metricDef) (string, bool) {
	switch {
	case m.link.none():
		return "", false
	case len(m.link) > 0:
		return m.link[0], true
	}
	_, ok := upstream[name]
	return name, ok
}

func upstreamMetrics(t *testing.T) map[string]metricDef {
	t.Helper()
	if _, err := os.Stat(upstreamDeps); os.IsNotExist(err) {
		t.Skipf("%s is not populated; run `make fetch-upstream-semconv`", upstreamDeps)
	}
	out := map[string]metricDef{}
	err := filepath.WalkDir(upstreamDeps, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		metricsFromFile(t, path, out)
		return nil
	})
	require.NoError(t, err)
	return out
}

// TestOBIMetricOverridesMatchUpstream asserts that every metric implementing an
// upstream metric declares the same unit, instrument and stability.
// Redeclaring a metric copies that wrapper and lets it drift, so this test
// pins it.
func TestOBIMetricOverridesMatchUpstream(t *testing.T) {
	local := obiMetrics(t)
	upstream := upstreamMetrics(t)
	require.NotEmpty(t, overrideMetrics(t))
	require.NotEmpty(t, upstream)

	for name, m := range local {
		target, ok := implementedMetric(name, m, upstream)
		if !ok {
			continue
		}
		up, ok := upstream[target]
		require.Truef(t, ok,
			"metric %q in %s implements %q, which has no upstream semconv definition; "+
				"fix the name or link, or set upstream: none if it is an OBI-only metric",
			name, m.source, target)
		assert.Equalf(t, up.unit, m.unit,
			"metric %q unit %q differs from upstream %q (%s vs %s)",
			name, m.unit, up.unit, m.source, up.source)
		assert.Equalf(t, up.instrument, m.instrument,
			"metric %q instrument %q differs from upstream %q (%s vs %s)",
			name, m.instrument, up.instrument, m.source, up.source)
		assert.Equalf(t, up.stability, m.stability,
			"metric %q stability %q differs from upstream %q (%s vs %s)",
			name, m.stability, up.stability, m.source, up.source)
	}
}

// TestLocalMetricsUnderUpstreamNamesAreNotMarkedNone asserts that a locally
// declared metric whose name also exists upstream is not marked `none`, so it
// cannot shadow the upstream definition and escape the drift check.
func TestLocalMetricsUnderUpstreamNamesAreNotMarkedNone(t *testing.T) {
	local := obiMetrics(t)
	upstream := upstreamMetrics(t)
	require.NotEmpty(t, local)
	require.NotEmpty(t, upstream)

	for name, m := range local {
		_, ok := upstream[name]
		assert.Falsef(t, ok && m.link.none(),
			"metric %q is declared in %s under an upstream metric's name but marked "+
				"upstream: none; drop the annotation so it is checked against upstream",
			name, m.source)
	}
}
