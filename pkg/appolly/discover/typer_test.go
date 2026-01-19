// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"iter"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/transform"
)

type dummyCriterion struct {
	name      string
	namespace string
	export    services.ExportModes
	sampler   *services.SamplerConfig
	routes    *services.CustomRoutesConfig
	features  export.Features
}

func (d dummyCriterion) GetName() string                                                { return d.name }
func (d dummyCriterion) GetOpenPorts() *services.PortEnum                               { return nil }
func (d dummyCriterion) GetPath() services.StringMatcher                                { return nil }
func (d dummyCriterion) RangeMetadata() iter.Seq2[string, services.StringMatcher]       { return nil }
func (d dummyCriterion) RangePodAnnotations() iter.Seq2[string, services.StringMatcher] { return nil }
func (d dummyCriterion) RangePodLabels() iter.Seq2[string, services.StringMatcher]      { return nil }
func (d dummyCriterion) IsContainersOnly() bool                                         { return false }
func (d dummyCriterion) GetPathRegexp() services.StringMatcher                          { return nil }
func (d dummyCriterion) GetNamespace() string                                           { return d.namespace }
func (d dummyCriterion) GetExportModes() services.ExportModes                           { return d.export }
func (d dummyCriterion) GetSamplerConfig() *services.SamplerConfig                      { return d.sampler }
func (d dummyCriterion) GetRoutesConfig() *services.CustomRoutesConfig                  { return d.routes }

func (d dummyCriterion) MetricsConfig() perapp.SvcMetricsConfig {
	return perapp.SvcMetricsConfig{Features: d.features}
}

func TestMakeServiceAttrs(t *testing.T) {
	pi := services.ProcessInfo{Pid: 1234}
	proc := &ProcessMatch{
		Process: &pi,
		Criteria: []services.Selector{
			dummyCriterion{name: "svc1", namespace: "ns1", export: services.ExportModeUnset},
		},
	}
	ty := typer{cfg: &obi.Config{Routes: &transform.RoutesConfig{}}}
	attrs := ty.makeServiceAttrs(proc)
	assert.Equal(t, "svc1", attrs.UID.Name)
	assert.Equal(t, "ns1", attrs.UID.Namespace)
	assert.Equal(t, int32(1234), attrs.ProcPID)
	assert.Equal(t, services.ExportModeUnset, attrs.ExportModes)

	// Test with sampler and routes
	sampler := &services.SamplerConfig{}
	routes := &services.CustomRoutesConfig{
		Incoming: []string{"/test"},
		Outgoing: []string{"/test2"},
	}
	pi2 := services.ProcessInfo{Pid: 5678}
	proc2 := &ProcessMatch{
		Process: &pi2,
		Criteria: []services.Selector{
			dummyCriterion{sampler: sampler, routes: routes},
		},
	}
	attrs2 := ty.makeServiceAttrs(proc2)
	assert.NotNil(t, attrs2.Sampler)
	assert.NotNil(t, attrs2.CustomInRouteMatcher)
	assert.NotNil(t, attrs2.CustomOutRouteMatcher)
}

func TestMakeServiceAttrs_FeaturesMatchingMultipleCriteria(t *testing.T) {
	exTra := services.ExportModes{}
	exTra.AllowTraces()
	exMet := services.ExportModes{}
	exMet.AllowMetrics()

	type testCase struct {
		name     string
		criteria []services.Selector
		expected export.Features
	}

	for _, tc := range []testCase{{
		name: "last match wins",
		criteria: []services.Selector{
			dummyCriterion{export: exMet, features: export.FeatureGraph},
			dummyCriterion{
				export: exTra, name: "svc1", namespace: "ns1",
				features: export.FeatureApplicationRED | export.FeatureGraph,
			},
		},
		expected: export.FeatureApplicationRED | export.FeatureGraph,
	}, {
		name: "if no features are defined, global metrics features prevail",
		criteria: []services.Selector{
			dummyCriterion{export: exTra, name: "svc2", namespace: "ns2"},
			dummyCriterion{name: "svc1", namespace: "ns1"},
		},
		expected: export.FeatureSpanOTel,
	}, {
		name: "if last match does not define features, global metrics config override any prior match",
		criteria: []services.Selector{
			dummyCriterion{name: "svc2", namespace: "ns2", features: export.FeatureGraph},
			dummyCriterion{export: exTra, name: "svc1", namespace: "ns1"},
		},
		expected: export.FeatureSpanOTel,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			proc := &ProcessMatch{
				Process:  &services.ProcessInfo{Pid: 1234},
				Criteria: tc.criteria,
			}
			ty := typer{cfg: &obi.Config{
				Routes:  &transform.RoutesConfig{},
				Metrics: perapp.MetricsConfig{Features: export.FeatureSpanOTel},
			}}
			attrs := ty.makeServiceAttrs(proc)
			assert.Equal(t, "svc1", attrs.UID.Name)
			assert.Equal(t, "ns1", attrs.UID.Namespace)
			assert.Equal(t, int32(1234), attrs.ProcPID)

			// the later matching criteria prevails
			assert.Equal(t, exTra, attrs.ExportModes)
			assert.Equal(t, tc.expected, attrs.Features)
		})
	}
}
