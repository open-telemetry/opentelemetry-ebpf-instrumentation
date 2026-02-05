// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform // import "go.opentelemetry.io/obi/pkg/transform"

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/docker"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

func delog() *slog.Logger {
	return slog.With("component", "transform.DockerEnricher")
}

func DockerDecoratorProvider(
	ctxInfo *global.ContextInfo,
	input, output *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		// only enable this node if Docker is available, but also
		// if we aren't running on Kubernetes
		if ctxInfo.K8sInformer.IsKubeEnabled() ||
			!ctxInfo.DockerMetadata.IsEnabled(ctx) {
			return swarm.Bypass(input, output)
		}

		dd := dockerEnricher{
			in:             input.Subscribe(msg.SubscriberName("DockerEnricher")),
			out:            output,
			containerByPID: map[docker.PID]docker.ContainerMeta{},
			log:            delog(),
			docker:         ctxInfo.DockerMetadata,
		}
		return dd.decorate, nil
	}
}

type dockerEnricher struct {
	in             <-chan []request.Span
	out            *msg.Queue[[]request.Span]
	containerByPID map[docker.PID]docker.ContainerMeta
	log            *slog.Logger
	docker         *docker.ContainerStore
}

func (dd *dockerEnricher) decorate(ctx context.Context) {
	defer dd.out.Close()
	swarms.ForEachInput(ctx, dd.in, dd.log.Debug, func(spans []request.Span) {
		for i := range spans {
			svc := &spans[i].Service
			if ci, ok := dd.containerInfo(ctx, docker.PID(svc.ProcPID)); ok {
				if svc.Metadata == nil {
					svc.Metadata = map[attr.Name]string{}
				}
				svc.Metadata[attr.ContainerName] = ci.Name
				svc.Metadata[attr.ContainerID] = ci.ID

				if svc.AutoName() {
					// populate service name from container metadata
					if ci.ComposeService != "" {
						svc.UID.Name = ci.ComposeService
					} else {
						svc.UID.Name = ci.Name
					}
				}
			}
		}
		dd.out.SendCtx(ctx, spans)
	})
}

func (dd *dockerEnricher) containerInfo(ctx context.Context, pid docker.PID) (docker.ContainerMeta, bool) {
	if ci, ok := dd.containerByPID[pid]; ok {
		return ci, true
	}
	ci, ok := dd.docker.ContainerInfo(ctx, pid)
	if ok {
		dd.containerByPID[pid] = ci
	} else {
		dd.log.Debug("can't find container metadata", "pid", pid)
	}
	return ci, ok
}
