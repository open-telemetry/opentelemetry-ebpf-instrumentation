// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
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

func TestOBIRuleBasedSamplerImplementation(t *testing.T) {
	cfg := SamplerConfig{
		OBIRuleBased: &OBIRuleBasedSamplerConfig{
			Fallback: SamplerLeafConfig{Name: SamplerAlwaysOff},
			Rules: []OBIRuleBasedSamplerRule{{
				Match: OBIRuleBasedSamplerMatch{
					ResourceAttributes: map[string]string{
						"service.name":      "frontend",
						"service.namespace": "default",
					},
				},
				Action: SamplerLeafConfig{Name: SamplerAlwaysOn},
			}},
		},
	}

	sampler := cfg.Implementation()
	match := sampler.ShouldSample(trace.SamplingParameters{
		ParentContext: context.Background(),
		TraceID:       oteltrace.TraceID{1},
		Name:          "GET /",
		Attributes: []attribute.KeyValue{
			attribute.String("service.name", "frontend"),
			attribute.String("service.namespace", "default"),
		},
	})
	assert.Equal(t, trace.RecordAndSample, match.Decision)

	miss := sampler.ShouldSample(trace.SamplingParameters{
		ParentContext: context.Background(),
		TraceID:       oteltrace.TraceID{2},
		Name:          "GET /",
		Attributes: []attribute.KeyValue{
			attribute.String("service.name", "backend"),
			attribute.String("service.namespace", "default"),
		},
	})
	assert.Equal(t, trace.Drop, miss.Decision)
}
