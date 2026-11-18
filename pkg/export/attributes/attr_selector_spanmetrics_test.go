// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func spanMetricSelector(t *testing.T, useV2 bool, selection Selection) *AttrSelector {
	t.Helper()
	selection.Normalize()
	p, err := NewAttrSelector(GroupKubernetes, &SelectorConfig{SelectionCfg: selection, UseV2Selection: useV2})
	require.NoError(t, err)
	return p
}

func TestForSpanMetricsV1ReturnsLegacyList(t *testing.T) {
	p := spanMetricSelector(t, false, Selection{"*": {Include: []string{"service.version"}}})
	legacy := []attr.Name{"deployment.environment"}
	assert.Equal(t, legacy, p.ForSpanMetrics(legacy, SpanMetricsDurationOTel, SpanMetricsCallsOTel))
}

func TestForSpanMetricsV2WithoutMatchingSelectionAddsNothing(t *testing.T) {
	p := spanMetricSelector(t, true, Selection{"http.*": {Include: []string{"service.version"}}})
	for _, metric := range SpanMetrics {
		assert.Empty(t, p.ForSpanMetrics([]attr.Name{"deployment.environment"}, metric), metric.Section)
	}
}

func TestForSpanMetricsV2PatternsAddNothing(t *testing.T) {
	p := spanMetricSelector(t, true, Selection{"*": {Include: []string{"*", "k8s.*"}}})
	assert.Empty(t, p.ForSpanMetrics(nil, SpanMetricsDurationOTel, SpanMetricsCallsOTel))
}

func TestForSpanMetricsV2ExactNamesSelectMetadataKeys(t *testing.T) {
	p := spanMetricSelector(t, true, Selection{
		"traces.span.metrics.*": {Include: []string{"service_version", "service.version", "deployment.environment", "k8s.pod.name"}, Exclude: []string{"k8s.*"}},
	})
	assert.Equal(t,
		[]attr.Name{"deployment.environment", "service.version"},
		p.ForSpanMetrics(nil, SpanMetricsDurationOTel, SpanMetricsCallsOTel))
	assert.Empty(t, p.ForSpanMetrics(nil, SpanMetricsLatencyLegacy, SpanMetricsCallsLegacy))
}

func TestForSpanMetricsV2PairSharesSelection(t *testing.T) {
	p := spanMetricSelector(t, true, Selection{
		"traces.span.metrics.calls": {Include: []string{"service.version"}},
	})
	assert.Equal(t, []attr.Name{"service.version"}, p.ForSpanMetrics(nil, SpanMetricsDurationOTel, SpanMetricsCallsOTel))
}

func TestForSpanMetricsV2SpecificSelectionExcludesWildcardIncludes(t *testing.T) {
	p := spanMetricSelector(t, true, Selection{
		"*":                     {Include: []string{"k8s.pod.name", "service.version"}},
		"traces.span.metrics.*": {Exclude: []string{"k8s_pod_name"}},
	})
	assert.Equal(t, []attr.Name{"service.version"}, p.ForSpanMetrics(nil, SpanMetricsDurationOTel, SpanMetricsCallsOTel))
}

func TestForSpanMetricsV2NeverDuplicatesFixedDimensions(t *testing.T) {
	p := spanMetricSelector(t, true, Selection{
		"*": {Include: []string{"service.name", "span_name", "job", "instance", "service.version"}},
	})
	assert.Equal(t, []attr.Name{"service.version"}, p.ForSpanMetrics(nil, SpanMetricsDurationOTel, SpanMetricsCallsOTel))
}
