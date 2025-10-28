// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"iter"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

type dummyCriterion struct {
	name      string
	namespace string
	export    services.ExportModes
	sampler   *services.SamplerConfig
	routes    *services.CustomRoutesConfig
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

func TestMakeServiceAttrs(t *testing.T) {
	pi := services.ProcessInfo{Pid: 1234}
	proc := &ProcessMatch{
		Process: &pi,
		Criteria: []services.Selector{
			dummyCriterion{name: "svc1", namespace: "ns1", export: services.ExportModeUnset},
		},
	}
	attrs := makeServiceAttrs(proc)
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
	attrs2 := makeServiceAttrs(proc2)
	assert.NotNil(t, attrs2.Sampler)
	assert.NotNil(t, attrs2.CustomInRouteMatcher)
	assert.NotNil(t, attrs2.CustomOutRouteMatcher)
}
