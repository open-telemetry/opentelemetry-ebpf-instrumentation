// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package avoidedsvc

import (
	"testing"

	"github.com/stretchr/testify/assert"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// PrometheusOverflowLabel is spelled out so it stays a compile-time constant; this keeps it
// honest against the OTLP attribute it renders.
func TestPrometheusOverflowLabelMatchesAttribute(t *testing.T) {
	assert.Equal(t, PrometheusOverflowLabel, attr.Name(OverflowAttribute).Prom())
}

func TestLimiterIgnoresServiceInstanceID(t *testing.T) {
	limiter := NewLimiter(3)

	assert.False(t, limiter.Labels("svc", "ns", "inst-0", "metrics").Overflow)
	assert.False(t, limiter.Labels("svc", "ns", "inst-1", "metrics").Overflow)
	assert.False(t, limiter.Labels("svc", "ns", "inst-0", "traces").Overflow)
	assert.True(t, limiter.Labels("other", "ns", "inst-0", "metrics").Overflow)
}
