// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly // import "go.opentelemetry.io/obi/pkg/appolly"

import (
	"context"

	configruntime "go.opentelemetry.io/obi/internal/config/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

func protocolMetricsSpanGate(input, output *msg.Queue[[]request.Span]) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		selection, enabled := configruntime.ProtocolMetricSelection(ctx)
		if !enabled {
			return swarm.Bypass(input, output)
		}
		in := input.Subscribe(msg.SubscriberName("appolly.ProtocolMetricsSpanGate"))
		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, nil, func(spans []request.Span) {
				for i := range spans {
					if instrumentation, ok := spans[i].Type.Instrumentation(); ok && !selection.Enabled(instrumentation) {
						request.SetIgnoreMetrics(&spans[i])
					}
				}
				output.SendCtx(ctx, spans)
			})
		}, nil
	}
}
