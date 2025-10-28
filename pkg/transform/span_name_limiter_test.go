// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"fmt"
	"log/slog"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const maxCardinalityBeforeAggregation = 10

func TestSpanNameLimiter(t *testing.T) {
	// GIVEN a SpanNameLimiter instance
	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	outCh := output.Subscribe()
	runSpanNameLimiter, err := SpanNameLimiter(SpanNameLimiterConfig{
		Limit: maxCardinalityBeforeAggregation,
		OTEL:  &otelcfg.MetricsConfig{Features: []string{otelcfg.FeatureSpan}, TTL: time.Minute},
		Prom:  &prom.PrometheusConfig{Features: []string{otelcfg.FeatureSpan}, TTL: time.Minute},
	}, input, output)(t.Context())
	require.NoError(t, err)

	go runSpanNameLimiter(t.Context())

	// will check that different instances of the same service will be aggregated together
	svc1i1 := svc.Attrs{UID: svc.UID{Namespace: "ns", Name: "svc1", Instance: "i1"}}
	svc1i2 := svc.Attrs{UID: svc.UID{Namespace: "ns", Name: "svc1", Instance: "i2"}}
	svc2 := svc.Attrs{UID: svc.UID{Namespace: "ns", Name: "svc2", Instance: "i"}}

	t.Run("do not aggregate if cardinality is low", func(t *testing.T) {
		input.Send([]request.Span{
			{Service: svc1i1, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo-1"},
			{Service: svc1i1, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo-2"},
			{Service: svc1i2, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo-3"},
		})
		input.Send([]request.Span{
			{Service: svc1i1, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo-4"},
			{Service: svc1i2, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo-5"},
			{Service: svc1i2, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo-6"},
			{Service: svc2, Type: request.EventTypeHTTP, Method: "GET", Route: "/bar"},
		})

		spans := testutil.ReadChannel(t, outCh, testTimeout)
		require.Len(t, spans, 3)
		assert.Equal(t, "GET /foo-1", spans[0].TraceName())
		assert.Equal(t, "GET /foo-2", spans[1].TraceName())
		assert.Equal(t, "GET /foo-3", spans[2].TraceName())
		spans = testutil.ReadChannel(t, outCh, testTimeout)
		require.Len(t, spans, 4)
		assert.Equal(t, "GET /foo-4", spans[0].TraceName())
		assert.Equal(t, "GET /foo-5", spans[1].TraceName())
		assert.Equal(t, "GET /foo-6", spans[2].TraceName())
		assert.Equal(t, "GET /bar", spans[3].TraceName())
	})

	t.Run("start aggregating if max cardinality is reached", func(t *testing.T) {
		input.Send([]request.Span{
			{Service: svc1i1, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo-7"},
			{Service: svc1i2, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo-8"},
			{Service: svc2, Type: request.EventTypeHTTP, Method: "GET", Route: "/bar-2"},
			{Service: svc1i2, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo-9"},
		})
		input.Send([]request.Span{
			{Service: svc1i1, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo-10"},
			{Service: svc1i2, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo-11"},
			{Service: svc1i2, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo-12"},
			{Service: svc2, Type: request.EventTypeHTTP, Method: "GET", Route: "/bar-6"},
		})
		spans := testutil.ReadChannel(t, outCh, testTimeout)
		require.Len(t, spans, 4)
		assert.Equal(t, "GET /foo-7", spans[0].TraceName())
		assert.Equal(t, "GET /foo-8", spans[1].TraceName())
		assert.Equal(t, "GET /bar-2", spans[2].TraceName())
		spans = testutil.ReadChannel(t, outCh, testTimeout)
		require.Len(t, spans, 4)
		assert.Equal(t, "GET /foo-10", spans[0].TraceName())
		assert.Equal(t, "AGGREGATED", spans[1].TraceName())
		assert.Equal(t, "AGGREGATED", spans[2].TraceName())
		assert.Equal(t, "GET /bar-6", spans[3].TraceName())
	})

	t.Run("do not aggregate when same route is provided many times", func(t *testing.T) {
		for range 20 {
			input.Send([]request.Span{
				{Service: svc2, Type: request.EventTypeHTTP, Method: "GET", Route: "/bar"},
			})
			spans := testutil.ReadChannel(t, outCh, testTimeout)
			require.Len(t, spans, 1)
			assert.Equal(t, "GET /bar", spans[0].TraceName())
		}
	})
}

func TestSpanNameLimiter_ExpireOld(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	synctest.Test(t, func(t *testing.T) {
		// GIVEN a SpanNameLimiter instance
		input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
		output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
		outCh := output.Subscribe()
		runSpanNameLimiter, err := SpanNameLimiter(SpanNameLimiterConfig{
			Limit: maxCardinalityBeforeAggregation,
			OTEL:  &otelcfg.MetricsConfig{Features: []string{otelcfg.FeatureSpan}, TTL: time.Minute},
			Prom:  &prom.PrometheusConfig{Features: []string{otelcfg.FeatureSpan}, TTL: time.Minute},
		}, input, output)(t.Context())
		require.NoError(t, err)

		go runSpanNameLimiter(t.Context())

		svc1 := svc.Attrs{UID: svc.UID{Namespace: "ns", Name: "svc1", Instance: "i1"}}
		svc2 := svc.Attrs{UID: svc.UID{Namespace: "ns", Name: "svc2", Instance: "i2"}}

		for i := range maxCardinalityBeforeAggregation + 1 {
			input.Send([]request.Span{
				{Service: svc1, Type: request.EventTypeHTTP, Method: "GET", Route: fmt.Sprintf("/foo-%d", i)},
				{Service: svc2, Type: request.EventTypeHTTP, Method: "GET", Route: fmt.Sprintf("/bar-%d", i)},
			})
		}
		// before max cardinality, nothing is aggregated
		for i := range maxCardinalityBeforeAggregation {
			spans := testutil.ReadChannel(t, outCh, testTimeout)
			require.Len(t, spans, 2)
			assert.Equal(t, fmt.Sprintf("GET /foo-%d", i), spans[0].TraceName())
			assert.Equal(t, fmt.Sprintf("GET /bar-%d", i), spans[1].TraceName())
		}
		// after max cardinality, it starts aggregating
		spans := testutil.ReadChannel(t, outCh, testTimeout)
		require.Len(t, spans, 2)
		assert.Equal(t, "AGGREGATED", spans[0].TraceName())
		assert.Equal(t, "AGGREGATED", spans[1].TraceName())

		// During TTL time, a service stops sending data while the other keeps going
		for range 13 {
			// will expect that te internal expiration timer is eventually triggered during this loop
			time.Sleep(10 * time.Second)
			input.Send([]request.Span{
				{Service: svc1, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo"},
			})
			spans = testutil.ReadChannel(t, outCh, testTimeout)
			require.Len(t, spans, 1)
			assert.Equal(t, "AGGREGATED", spans[0].TraceName())
		}

		// Then if the service comes back after the TTL, it does not aggregate again
		// until the max cardinality is reached
		input.Send([]request.Span{
			{Service: svc1, Type: request.EventTypeHTTP, Method: "GET", Route: "/still-there"},
			{Service: svc2, Type: request.EventTypeHTTP, Method: "GET", Route: "/back-again"},
		})
		spans = testutil.ReadChannel(t, outCh, testTimeout)
		require.Len(t, spans, 2)
		assert.Equal(t, "AGGREGATED", spans[0].TraceName())
		assert.Equal(t, "GET /back-again", spans[1].TraceName())
	})
}

func TestSpanNameLimiter_CopiesOutput(t *testing.T) {
	// OBI has to mark as AGGREGATED only span metrics while the traces/spans need to
	// keep the original, high-cardinality span name.
	// To achieve that, the SpanNameLimiter must copy the modified spans instead of
	// modifying the original input array
	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	outCh := output.Subscribe()
	runSpanNameLimiter, err := SpanNameLimiter(SpanNameLimiterConfig{
		Limit: 3,
		OTEL:  &otelcfg.MetricsConfig{Features: []string{otelcfg.FeatureSpan}, TTL: time.Minute},
		Prom:  &prom.PrometheusConfig{Features: []string{otelcfg.FeatureSpan}, TTL: time.Minute},
	}, input, output)(t.Context())
	require.NoError(t, err)

	go runSpanNameLimiter(t.Context())

	svc := svc.Attrs{UID: svc.UID{Namespace: "ns", Name: "svc1", Instance: "i1"}}

	// generate diverse span names to reach the maximum aggregation
	input.Send([]request.Span{
		{Service: svc, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo-1"},
		{Service: svc, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo-2"},
		{Service: svc, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo-3"},
	})
	out := testutil.ReadChannel(t, outCh, testTimeout)
	require.Len(t, out, 3)
	assert.Equal(t, "GET /foo-1", out[0].TraceName())
	assert.Equal(t, "GET /foo-2", out[1].TraceName())
	assert.Equal(t, "GET /foo-3", out[2].TraceName())

	// From here, the output of the span name limiter shows aggregated spans,
	// but the original input spans remain untouched
	original := []request.Span{
		{Service: svc, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo-4"},
		{Service: svc, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo-5"},
		{Service: svc, Type: request.EventTypeHTTP, Method: "GET", Route: "/foo-6"},
	}
	input.Send(original)
	out = testutil.ReadChannel(t, outCh, testTimeout)
	require.Len(t, out, 3)
	assert.Equal(t, "AGGREGATED", out[0].TraceName())
	assert.Equal(t, "AGGREGATED", out[1].TraceName())
	assert.Equal(t, "AGGREGATED", out[2].TraceName())

	assert.Equal(t, "GET /foo-4", original[0].TraceName())
	assert.Equal(t, "GET /foo-5", original[1].TraceName())
	assert.Equal(t, "GET /foo-6", original[2].TraceName())
}
