// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestAttributeFilterYAML(t *testing.T) {
	t.Parallel()

	var filters SignalFilters
	err := yaml.Unmarshal([]byte(`
traces:
  http.route:
    match: /checkout/*
  service.name:
    not_match: internal-*
metrics:
  http.status_code:
    equals: 200
  retry_count:
    not_equals: 0
  latency_ms:
    greater_equals: 10
    greater_than: 11
    less_equals: 99
    less_than: 100
`), &filters)
	require.NoError(t, err)

	require.Equal(t, AttributeFilter{Match: "/checkout/*"}, filters.Traces["http.route"])
	require.Equal(t, AttributeFilter{NotMatch: "internal-*"}, filters.Traces["service.name"])

	statusCode := filters.Metrics["http.status_code"]
	require.NotNil(t, statusCode.Equals)
	require.Equal(t, 200, *statusCode.Equals)

	retryCount := filters.Metrics["retry_count"]
	require.NotNil(t, retryCount.NotEquals)
	require.Equal(t, 0, *retryCount.NotEquals)

	latency := filters.Metrics["latency_ms"]
	require.NotNil(t, latency.GreaterEquals)
	require.Equal(t, 10, *latency.GreaterEquals)
	require.NotNil(t, latency.GreaterThan)
	require.Equal(t, 11, *latency.GreaterThan)
	require.NotNil(t, latency.LessEquals)
	require.Equal(t, 99, *latency.LessEquals)
	require.NotNil(t, latency.LessThan)
	require.Equal(t, 100, *latency.LessThan)
}
