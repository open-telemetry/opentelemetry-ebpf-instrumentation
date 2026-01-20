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
	exportModeTraces := services.ExportModes{}
	exportModeTraces.AllowTraces()
	exportModeMetrics := services.ExportModes{}
	exportModeMetrics.AllowMetrics()

	proc := &ProcessMatch{
		Process: &services.ProcessInfo{Pid: 1234},
		Criteria: []services.Selector{
			dummyCriterion{
				name: "svc1", namespace: "ns1", export: exportModeMetrics,
				features: export.FeatureApplicationRED | export.FeatureGraph,
			},
			dummyCriterion{export: exportModeTraces, features: export.FeatureGraph},
		},
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
	assert.Equal(t, exportModeTraces, attrs.ExportModes)
	assert.Equal(t, export.FeatureGraph, attrs.Features)
}

func TestMakeServiceAttrs_NoPerAppFeatures(t *testing.T) {
	proc := &ProcessMatch{
		Process: &services.ProcessInfo{Pid: 1234},
		Criteria: []services.Selector{
			dummyCriterion{name: "svc1", namespace: "ns1"},
			dummyCriterion{name: "svc2", namespace: "ns2"},
		},
	}

	ty := typer{cfg: &obi.Config{
		Routes:  &transform.RoutesConfig{},
		Metrics: perapp.MetricsConfig{Features: export.FeatureSpanOTel},
	}}

	attrs := ty.makeServiceAttrs(proc)
	assert.Equal(t, "svc2", attrs.UID.Name)
	assert.Equal(t, "ns2", attrs.UID.Namespace)
	assert.Equal(t, int32(1234), attrs.ProcPID)
	assert.Equal(t, services.ExportModeUnset, attrs.ExportModes)
	assert.Equal(t, export.FeatureSpanOTel, attrs.Features)
}
