// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/otel/sdk/trace"
)

func TestSamplerImplementation(t *testing.T) {
	type testCase struct {
		in  SamplerConfig
		out trace.Sampler
	}

	for _, tc := range []testCase{{
		// default sampler
		out: trace.ParentBased(trace.AlwaysSample()),
	}, {
		in:  SamplerConfig{Name: "invalid_sampler", Arg: "0.33"},
		out: trace.ParentBased(trace.AlwaysSample()),
	}, {
		in:  SamplerConfig{Name: "always_on"},
		out: trace.AlwaysSample(),
	}, {
		in:  SamplerConfig{Name: "always_off"},
		out: trace.NeverSample(),
	}, {
		in:  SamplerConfig{Name: "traceidratio", Arg: "0.33"},
		out: trace.TraceIDRatioBased(0.33),
	}, {
		// wrong argument: using default sampler
		in:  SamplerConfig{Name: "traceidratio", Arg: "fofofofoof"},
		out: trace.ParentBased(trace.AlwaysSample()),
	}, {
		in:  SamplerConfig{Name: "parentbased_always_off", Arg: "0.33"},
		out: trace.ParentBased(trace.NeverSample()),
	}, {
		in:  SamplerConfig{Name: "parentbased_always_on", Arg: "0.33"},
		out: trace.ParentBased(trace.AlwaysSample()),
	}, {
		in:  SamplerConfig{Name: "parentbased_traceidratio", Arg: "0.3"},
		out: trace.ParentBased(trace.TraceIDRatioBased(0.3)),
	}, {
		in:  SamplerConfig{Name: "parentbased_traceidratio", Arg: "wrong argument"},
		out: trace.ParentBased(trace.AlwaysSample()),
	}} {
		t.Run(string(tc.in.Name)+"/"+tc.in.Arg, func(t *testing.T) {
			assert.Equal(t, tc.out, tc.in.Implementation())
		})
	}
}

func TestSamplerTraceIDRatio(t *testing.T) {
	for _, tc := range []struct {
		in          SamplerConfig
		ratio       float64
		parentBased bool
	}{
		{in: SamplerConfig{}, ratio: 1, parentBased: true},
		{in: SamplerConfig{Name: "invalid_sampler", Arg: "0.33"}, ratio: 1, parentBased: true},
		{in: SamplerConfig{Name: "always_on"}, ratio: 1, parentBased: false},
		{in: SamplerConfig{Name: "always_off"}, ratio: 0, parentBased: false},
		{in: SamplerConfig{Name: "traceidratio", Arg: "0.25"}, ratio: 0.25, parentBased: false},
		{in: SamplerConfig{Name: "traceidratio", Arg: "invalid"}, ratio: 1, parentBased: true},
		{in: SamplerConfig{Name: "parentbased_always_on"}, ratio: 1, parentBased: true},
		{in: SamplerConfig{Name: "parentbased_always_off"}, ratio: 0, parentBased: true},
		{in: SamplerConfig{Name: "parentbased_traceidratio", Arg: "0.25"}, ratio: 0.25, parentBased: true},
		{in: SamplerConfig{Name: "parentbased_traceidratio", Arg: "invalid"}, ratio: 1, parentBased: true},
	} {
		t.Run(string(tc.in.Name)+"_"+tc.in.Arg, func(t *testing.T) {
			ratio, parentBased := tc.in.TraceIDRatio()

			assert.InDelta(t, tc.ratio, ratio, 0)
			assert.Equal(t, tc.parentBased, parentBased)
		})
	}
}
