// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/trace"
)

func TestMetricsConfigGetExemplarFilter(t *testing.T) {
	sampled := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1},
		SpanID:     trace.SpanID{1},
		TraceFlags: trace.FlagsSampled,
	}))
	unsampled := context.Background()

	tests := []struct {
		name           string
		wantSampled    bool
		wantUnsampled  bool
		wantUnfiltered bool
	}{
		{name: "always_on", wantSampled: true, wantUnsampled: true},
		{name: "always_off"},
		{name: "trace_based", wantSampled: true},
		{name: "", wantUnfiltered: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filter := (&MetricsConfig{ExemplarFilter: test.name}).GetExemplarFilter()
			if test.wantUnfiltered {
				require.Nil(t, filter)
				return
			}
			require.NotNil(t, filter)
			require.Equal(t, test.wantSampled, filter(sampled))
			require.Equal(t, test.wantUnsampled, filter(unsampled))
		})
	}
}
