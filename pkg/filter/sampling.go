// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package filter // import "go.opentelemetry.io/obi/pkg/filter"

import (
	"context"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

// BySamplingDecision keeps metrics on the unfiltered input queue while
// forwarding only sampled or undecided spans to trace outputs.
func BySamplingDecision(
	input, output *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		in := input.Subscribe(msg.SubscriberName("filter.BySamplingDecision"))
		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, nil, func(spans []request.Span) {
				sampled := spansForTraceExport(spans)
				if len(sampled) > 0 {
					output.SendCtx(ctx, sampled)
				}
			})
		}, nil
	}
}

func spansForTraceExport(spans []request.Span) []request.Span {
	sampled := make([]request.Span, 0, len(spans))
	for i := range spans {
		if !spans[i].BPFDecision ||
			spans[i].TraceFlags&uint8(trace.FlagsSampled) != 0 {
			sampled = append(sampled, spans[i])
		}
	}
	return sampled
}
