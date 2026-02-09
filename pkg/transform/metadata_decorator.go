// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform // import "go.opentelemetry.io/obi/pkg/transform"

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/metadata"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

func mdlog() *slog.Logger {
	return slog.With("component", "transform.MetadataDecorator")
}

// spanMetadataDecorator decorates spans with metadata from the unified provider.
type spanMetadataDecorator struct {
	provider metadata.Provider
	input    <-chan []request.Span
	output   *msg.Queue[[]request.Span]
}

// MetadataDecoratorProvider creates a decorator for request spans.
func MetadataDecoratorProvider(
	provider metadata.Provider,
	input, output *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if provider == nil {
			return swarm.Bypass(input, output)
		}

		decorator := &spanMetadataDecorator{
			provider: provider,
			input:    input.Subscribe(msg.SubscriberName("transform.MetadataDecorator")),
			output:   output,
		}
		return decorator.nodeLoop, nil
	}
}

func (md *spanMetadataDecorator) nodeLoop(ctx context.Context) {
	defer md.output.Close()
	swarms.ForEachInput(ctx, md.input, mdlog().Debug, func(spans []request.Span) {
		for i := range spans {
			md.do(&spans[i])
		}
		md.output.SendCtx(ctx, spans)
	})
}

func (md *spanMetadataDecorator) do(span *request.Span) {
	// Decorate service with metadata from PID namespace
	md.provider.DecorateService(&span.Service, span.Pid.Namespace)

	// Ensure service metadata is not nil
	if span.Service.Metadata == nil {
		span.Service.Metadata = map[attr.Name]string{}
	}

	// Override peer and host names from metadata provider (IP-based lookups)
	if span.Host != "" {
		if name, _, _ := md.provider.ServiceNameForIP(span.Host); name != "" {
			span.HostName = name
		}
	}
	if span.Peer != "" {
		if name, _, _ := md.provider.ServiceNameForIP(span.Peer); name != "" {
			span.PeerName = name
		}
	}
}
