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

type metricGroupsFile struct {
	Groups []struct {
		Type       string `yaml:"type"`
		MetricName string `yaml:"metric_name"`
		Unit       string `yaml:"unit"`
		Instrument string `yaml:"instrument"`
		Stability  string `yaml:"stability"`
	} `yaml:"groups"`
}

type metricDef struct {
	unit       string
	instrument string
	stability  string
	source     string
}

func metricsFromFile(t *testing.T, path string, out map[string]metricDef) {
	t.Helper()
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	var f metricGroupsFile
	require.NoErrorf(t, yaml.Unmarshal(body, &f), "parsing %s", path)
	for _, g := range f.Groups {
		if g.Type != "metric" || g.MetricName == "" {
			continue
		}
		out[g.MetricName] = metricDef{unit: g.Unit, instrument: g.Instrument, stability: g.Stability, source: path}
	}
}

func obiMetrics(t *testing.T) map[string]metricDef {
	t.Helper()
	entries, err := os.ReadDir(obiGroupsDir)
	require.NoError(t, err)
	out := map[string]metricDef{}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		metricsFromFile(t, filepath.Join(obiGroupsDir, e.Name()), out)
	}
	return out
}

func upstreamMetrics(t *testing.T) map[string]metricDef {
	t.Helper()
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

// TestOBIMetricOverridesMatchUpstream asserts that every OBI metric reusing an
// upstream semconv metric name declares the same unit, instrument, and stability
// as the pinned upstream definition.
//
// OBI redeclares these metrics instead of importing them because weaver cannot
// narrow an imported metric's attributes down to the subset OBI emits
// (open-telemetry/weaver#1667). Redeclaring copies the metric wrapper — unit,
// instrument, stability — which can then drift from upstream, so this test pins
// it to the upstream definition. Attributes are not compared: OBI refs them, so
// they resolve against this same upstream registry and cannot drift.
func TestOBIMetricOverridesMatchUpstream(t *testing.T) {
	obi := obiMetrics(t)
	upstream := upstreamMetrics(t)
	require.NotEmpty(t, obi)
	require.NotEmpty(t, upstream)

	overrides := 0
	for name, m := range obi {
		up, ok := upstream[name]
		if !ok {
			continue // OBI-custom metric with no upstream definition to match
		}
		overrides++
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
	require.Positive(t, overrides, "expected OBI to override at least one upstream metric")
}
