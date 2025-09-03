package transform

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/components/svc"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestSpanNameLimiter(t *testing.T) {
	synctest.Test(t, testSpanNameLimiter)
}

func testSpanNameLimiter(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	const maxCardinalityBeforeAggregation = 10

	// GIVEN a SpanNameLimiter instance
	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
	outCh := output.Subscribe()
	runSpanNameLimiter, err := SpanNameLimiter(SpanNameLimiterConfig{
		Limit: maxCardinalityBeforeAggregation,
		OTEL:  &otelcfg.MetricsConfig{Features: []string{otelcfg.FeatureSpan}, TTL: time.Minute},
		Prom:  &prom.PrometheusConfig{Features: []string{otelcfg.FeatureSpan}, TTL: time.Minute},
	}, input, output)(ctx)
	require.NoError(t, err)

	go runSpanNameLimiter(ctx)

	// will check that different instances of the same service will be aggregated together
	svc1i1 := svc.Attrs{UID: svc.UID{Namespace: "ns", Name: "svc1", Instance: "i1"}}
	svc1i2 := svc.Attrs{UID: svc.UID{Namespace: "ns", Name: "svc1", Instance: "i2"}}
	svc2 := svc.Attrs{UID: svc.UID{Namespace: "ns", Name: "svc2", Instance: "i"}}

	input.Send([]request.Span{
		{Service: svc1i1, Type: request.EventTypeHTTP, Method: "GET", Path: "/foo-1"},
		{Service: svc1i1, Type: request.EventTypeHTTP, Method: "GET", Path: "/foo-2"},
		{Service: svc1i2, Type: request.EventTypeHTTP, Method: "GET", Path: "/foo-3"},
		{Service: svc1i1, Type: request.EventTypeHTTP, Method: "GET", Path: "/foo-4"},
		{Service: svc1i2, Type: request.EventTypeHTTP, Method: "GET", Path: "/foo-5"},
		{Service: svc1i2, Type: request.EventTypeHTTP, Method: "GET", Path: "/foo-6"},
		{Service: svc2, Type: request.EventTypeHTTP, Method: "GET", Path: "/bar"},
	})
	_ = outCh
	 //testutil.ReadChannel(t, outCh, testTimeout)
	//assert.Equal(t, "GET /foo-1", "ajr")

}
