// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bufio"
	"encoding/binary"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func TestSamplerCanonical(t *testing.T) {
	alwaysOn := SamplerDelegate{Type: SamplerTypeAlwaysOn}
	alwaysOff := SamplerDelegate{Type: SamplerTypeAlwaysOff}

	tests := []struct {
		name string
		in   SamplerConfig
		want CanonicalSampler
	}{
		{
			name: "default",
			want: CanonicalSampler{
				Type:                   SamplerTypeParentBased,
				Root:                   alwaysOn,
				RemoteParentSampled:    alwaysOn,
				RemoteParentNotSampled: alwaysOff,
				LocalParentSampled:     alwaysOn,
				LocalParentNotSampled:  alwaysOff,
			},
		},
		{
			name: "always on",
			in:   SamplerConfig{Name: SamplerAlwaysOn},
			want: CanonicalSampler{Type: SamplerTypeAlwaysOn},
		},
		{
			name: "always off",
			in:   SamplerConfig{Name: SamplerAlwaysOff},
			want: CanonicalSampler{Type: SamplerTypeAlwaysOff},
		},
		{
			name: "parent based always on",
			in:   SamplerConfig{Name: SamplerParentBasedAlwaysOn},
			want: CanonicalSampler{
				Type:                   SamplerTypeParentBased,
				Root:                   alwaysOn,
				RemoteParentSampled:    alwaysOn,
				RemoteParentNotSampled: alwaysOff,
				LocalParentSampled:     alwaysOn,
				LocalParentNotSampled:  alwaysOff,
			},
		},
		{
			name: "ratio",
			in:   SamplerConfig{Name: SamplerTraceIDRatio, Arg: "0.5"},
			want: CanonicalSampler{
				Type:              SamplerTypeTraceIDRatio,
				TraceIDUpperBound: 1 << 62,
			},
		},
		{
			name: "parent based ratio",
			in:   SamplerConfig{Name: SamplerParentBasedTraceIDRatio, Arg: "0.25"},
			want: CanonicalSampler{
				Type: SamplerTypeParentBased,
				Root: SamplerDelegate{
					Type:              SamplerTypeTraceIDRatio,
					TraceIDUpperBound: 1 << 61,
				},
				RemoteParentSampled:    alwaysOn,
				RemoteParentNotSampled: alwaysOff,
				LocalParentSampled:     alwaysOn,
				LocalParentNotSampled:  alwaysOff,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.in.Canonical()
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSamplerCanonicalRejectsInvalidConfiguration(t *testing.T) {
	for _, cfg := range []SamplerConfig{
		{Name: "unsupported"},
		{Name: SamplerTraceIDRatio},
		{Name: SamplerTraceIDRatio, Arg: "not-a-number"},
		{Name: SamplerTraceIDRatio, Arg: "NaN"},
		{Name: SamplerTraceIDRatio, Arg: "+Inf"},
		{Name: SamplerTraceIDRatio, Arg: "-0.1"},
		{Name: SamplerTraceIDRatio, Arg: "1.1"},
		{Name: SamplerParentBasedTraceIDRatio, Arg: "NaN"},
	} {
		t.Run(string(cfg.Name)+"/"+cfg.Arg, func(t *testing.T) {
			_, err := cfg.Canonical()
			require.Error(t, err)
		})
	}
}

func TestCanonicalSamplerMatchesSDKTraceIDRatio(t *testing.T) {
	vectors, err := os.Open("../../../bpf/tests/sampling_ratio_vectors.txt")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, vectors.Close())
	})

	scanner := bufio.NewScanner(vectors)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		require.Len(t, fields, 5)
		name, ratioArg := fields[0], fields[1]
		threshold, err := strconv.ParseUint(strings.TrimPrefix(fields[2], "0x"), 16, 64)
		require.NoError(t, err)
		value, err := strconv.ParseUint(strings.TrimPrefix(fields[3], "0x"), 16, 64)
		require.NoError(t, err)
		wantSampled := fields[4] == "1"

		t.Run(name, func(t *testing.T) {
			ratio, err := strconv.ParseFloat(ratioArg, 64)
			require.NoError(t, err)
			canonical, err := (&SamplerConfig{
				Name: SamplerTraceIDRatio,
				Arg:  ratioArg,
			}).Canonical()
			require.NoError(t, err)
			assert.Equal(t, threshold, canonical.TraceIDUpperBound)

			var traceID oteltrace.TraceID
			binary.BigEndian.PutUint64(traceID[8:], value<<1)
			got, err := canonical.ShouldSample(traceID, false, false, false)
			require.NoError(t, err)
			assert.Equal(t, wantSampled, got)

			sdkSampler := trace.TraceIDRatioBased(ratio)
			sdkResult := sdkSampler.ShouldSample(trace.SamplingParameters{TraceID: traceID})
			assert.Equal(t, wantSampled, sdkResult.Decision == trace.RecordAndSample)
		})
	}
	require.NoError(t, scanner.Err())
}

func TestCanonicalParentDelegates(t *testing.T) {
	canonical, err := (&SamplerConfig{Name: SamplerParentBasedAlwaysOff}).Canonical()
	require.NoError(t, err)
	var traceID oteltrace.TraceID

	tests := []struct {
		name          string
		hasParent     bool
		parentRemote  bool
		parentSampled bool
		want          bool
	}{
		{name: "root", want: false},
		{name: "remote sampled", hasParent: true, parentRemote: true, parentSampled: true, want: true},
		{name: "remote not sampled", hasParent: true, parentRemote: true, want: false},
		{name: "local sampled", hasParent: true, parentSampled: true, want: true},
		{name: "local not sampled", hasParent: true, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonical.ShouldSample(
				traceID, tc.hasParent, tc.parentRemote, tc.parentSampled)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
