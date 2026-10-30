// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"context"
	"encoding/binary"
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/assert"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

// bpfDecision mirrors sample_new_trace and sample_remote_child (bpf/common/sampling.h)
func bpfDecision(sampler BpfSamplerT, hasEntry bool, traceID trace.TraceID, parent *bool) bool {
	if !hasEntry {
		return parent == nil || *parent
	}
	if parent != nil && sampler.ParentBased != 0 {
		return *parent
	}

	return binary.BigEndian.Uint64(traceID[8:])>>1 < sampler.Threshold
}

func sdkDecision(sampler sdktrace.Sampler, traceID trace.TraceID, parent *bool) bool {
	ctx := context.Background()
	if parent != nil {
		flags := trace.TraceFlags(0)
		if *parent {
			flags = trace.FlagsSampled
		}
		ctx = trace.ContextWithSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{
			TraceID:    traceID,
			SpanID:     trace.SpanID{1},
			TraceFlags: flags,
			Remote:     true,
		}))
	}

	result := sampler.ShouldSample(sdktrace.SamplingParameters{ParentContext: ctx, TraceID: traceID})

	return result.Decision == sdktrace.RecordAndSample
}

// valid trace ids only: an all-zero one never carries a parent
func testTraceIDs() []trace.TraceID {
	ids := []trace.TraceID{{15: 1}, {8: 0x80}, {8: 0xff, 9: 0xff, 10: 0xff, 11: 0xff, 12: 0xff, 13: 0xff, 14: 0xff, 15: 0xff}}
	random := rand.New(rand.NewPCG(1, 2))
	for range 1000 {
		var id trace.TraceID
		binary.BigEndian.PutUint64(id[:8], random.Uint64())
		binary.BigEndian.PutUint64(id[8:], random.Uint64())
		ids = append(ids, id)
	}

	return ids
}

func parentName(parent *bool) string {
	switch {
	case parent == nil:
		return "none"
	case *parent:
		return "sampled"
	default:
		return "unsampled"
	}
}

func TestPIDSamplerMatchesSDKSampler(t *testing.T) {
	sampled, unsampled := true, false
	parents := []*bool{nil, &sampled, &unsampled}

	for _, cfg := range []services.SamplerConfig{
		{},
		{Name: services.SamplerAlwaysOn},
		{Name: services.SamplerAlwaysOff},
		{Name: services.SamplerTraceIDRatio, Arg: "0"},
		{Name: services.SamplerTraceIDRatio, Arg: "0.1"},
		{Name: services.SamplerTraceIDRatio, Arg: "0.5"},
		{Name: services.SamplerTraceIDRatio, Arg: "1"},
		{Name: services.SamplerParentBasedAlwaysOn},
		{Name: services.SamplerParentBasedAlwaysOff},
		{Name: services.SamplerParentBasedTraceIDRatio, Arg: "0.1"},
		{Name: services.SamplerParentBasedTraceIDRatio, Arg: "0.9999"},
		{Name: services.SamplerParentBasedTraceIDRatio, Arg: "invalid"},
	} {
		t.Run(string(cfg.Name)+"_"+cfg.Arg, func(t *testing.T) {
			sdk := cfg.Implementation()
			bpf, hasEntry := pidSampler(&cfg, nil)

			for _, id := range testTraceIDs() {
				for _, parent := range parents {
					if !assert.Equal(t, sdkDecision(sdk, id, parent), bpfDecision(bpf, hasEntry, id, parent),
						"trace id %s, parent %s", id, parentName(parent)) {
						return
					}
				}
			}
		})
	}
}

func TestPIDSamplerFallsBackToGlobal(t *testing.T) {
	global := &services.SamplerConfig{Name: services.SamplerAlwaysOff}
	service := &services.SamplerConfig{Name: services.SamplerAlwaysOn}

	fromGlobal, ok := pidSampler(nil, global)
	assert.True(t, ok)
	assert.Equal(t, BpfSamplerT{Threshold: 0}, fromGlobal)

	fromService, ok := pidSampler(service, global)
	assert.True(t, ok)
	assert.Equal(t, BpfSamplerT{Threshold: ratioKeySpace}, fromService)
}

func TestPIDSamplerDefaultNeedsNoEntry(t *testing.T) {
	_, ok := pidSampler(nil, &services.SamplerConfig{})
	assert.False(t, ok)

	_, ok = pidSampler(nil, nil)
	assert.False(t, ok)
}
