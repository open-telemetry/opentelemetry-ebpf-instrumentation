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

func spanMetricPair(t *testing.T, p *AttrSelector, legacy ...attr.Name) []attr.Name {
	t.Helper()
	return p.ForSpanMetrics(legacy, SpanMetricsDurationOTel, SpanMetricsCallsOTel)
}

func TestForSpanMetricsV1ReturnsLegacyList(t *testing.T) {
	p := spanMetricSelector(t, false, Selection{"*": {Include: []string{"service.version"}}})
	assert.Equal(t, []attr.Name{"deployment.environment"}, spanMetricPair(t, p, "deployment.environment"))
}

func TestForSpanMetricsV2WithoutMatchingSelectionAddsNothing(t *testing.T) {
	p := spanMetricSelector(t, true, Selection{"http.*": {Include: []string{"service.version"}}})
	for _, metric := range SpanMetrics {
		assert.Empty(t, p.ForSpanMetrics(nil, metric), metric.Section)
	}
}

func TestForSpanMetricsV2PatternsAddNothing(t *testing.T) {
	p := spanMetricSelector(t, true, Selection{"*": {Include: []string{"*", "k8s.*"}}})
	assert.Empty(t, spanMetricPair(t, p))
}

func TestForSpanMetricsV2KeepsLiteralMetadataKeys(t *testing.T) {
	p := spanMetricSelector(t, true, Selection{
		"traces.span.metrics.*": {
			Include: []string{"deployment.environment_name", "service_version", "service.version", "k8s.pod.name"},
			Exclude: []string{"k8s.*"},
		},
	})
	assert.Equal(t, []attr.Name{"deployment.environment_name", "service_version"}, spanMetricPair(t, p))
	assert.Empty(t, p.ForSpanMetrics(nil, SpanMetricsLatencyLegacy, SpanMetricsCallsLegacy))
}

func TestForSpanMetricsV2PairSharesSelection(t *testing.T) {
	for _, member := range []Section{"traces.span.metrics.duration", "traces.span.metrics.calls"} {
		p := spanMetricSelector(t, true, Selection{member: {Include: []string{"service.version"}}})
		assert.Equal(t, []attr.Name{"service.version"}, spanMetricPair(t, p), member)
	}
}

func TestForSpanMetricsV2ExactExclusionOfEitherMemberOverridesPatternInclude(t *testing.T) {
	for _, member := range []Section{"traces.span.metrics.duration", "traces.span.metrics.calls"} {
		p := spanMetricSelector(t, true, Selection{
			"*":    {Include: []string{"service.version", "deployment.environment"}},
			member: {Exclude: []string{"service_version"}},
		})
		assert.Equal(t, []attr.Name{"deployment.environment"}, spanMetricPair(t, p), member)
	}
}

func TestForSpanMetricsV2ExclusionWinsBetweenPairMembers(t *testing.T) {
	p := spanMetricSelector(t, true, Selection{
		"traces.span.metrics.duration": {Include: []string{"service.version"}},
		"traces.span.metrics.calls":    {Exclude: []string{"service.version"}},
	})
	assert.Empty(t, spanMetricPair(t, p))
}

func TestForSpanMetricsV2AddsLegacyKeysAfterSelection(t *testing.T) {
	p := spanMetricSelector(t, true, Selection{
		"traces.span.metrics.*": {Include: []string{"service.version"}, Exclude: []string{"deployment.*"}},
	})
	assert.Equal(t,
		[]attr.Name{"deployment.environment", "service.version"},
		spanMetricPair(t, p, "deployment.environment", "service.version"))
}

func TestForSpanMetricsV2NeverDuplicatesFixedDimensions(t *testing.T) {
	p := spanMetricSelector(t, true, Selection{
		"*": {Include: []string{"service.name", "span_name", "job", "instance", "service.version"}},
	})
	assert.Equal(t, []attr.Name{"service.version"}, spanMetricPair(t, p))
}

func TestSpanMetadataValue(t *testing.T) {
	metadata := map[attr.Name]string{
		"service.version":             "1.2.3",
		"deployment.environment_name": "prod",
	}

	key, value, ok := SpanMetadataValue(metadata, "deployment.environment_name", true)
	assert.True(t, ok)
	assert.Equal(t, attr.Name("deployment.environment_name"), key)
	assert.Equal(t, "prod", value)

	key, value, ok = SpanMetadataValue(metadata, "service_version", true)
	assert.True(t, ok)
	assert.Equal(t, attr.Name("service.version"), key)
	assert.Equal(t, "1.2.3", value)

	_, _, ok = SpanMetadataValue(metadata, "service_version", false)
	assert.False(t, ok)
}
