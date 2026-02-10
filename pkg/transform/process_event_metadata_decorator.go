// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform // import "go.opentelemetry.io/obi/pkg/transform"

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/meta"
	"go.opentelemetry.io/obi/pkg/metadata"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func pelog() *slog.Logger {
	return slog.With("component", "transform.ProcessEventMetadataDecorator")
}

// processEventMetadataDecorator decorates process events with metadata.
type processEventMetadataDecorator struct {
	log        *slog.Logger
	provider   metadata.Provider
	input      <-chan exec.ProcessEvent
	output     *msg.Queue[exec.ProcessEvent]
	podsInfoCh chan Event[*informer.ObjectMeta]
	tracker    *pidContainerTracker
}

// ProcessEventMetadataDecoratorProvider creates a decorator for process events.
func ProcessEventMetadataDecoratorProvider(
	provider metadata.Provider,
	metaNotifier meta.Notifier,
	input, output *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if provider == nil {
			return swarm.Bypass(input, output)
		}

		decorator := &processEventMetadataDecorator{
			log:        pelog(),
			provider:   provider,
			input:      input.Subscribe(msg.SubscriberName("transform.ProcessEventMetadataDecorator")),
			output:     output,
			podsInfoCh: make(chan Event[*informer.ObjectMeta]),
			tracker:    newPidContainerTracker(),
		}

		// Subscribe to pod events if we have a Kubernetes provider
		if metaNotifier != nil {
			decorator.log.Debug("subscribing to Kubernetes pod events")
		}

		return decorator.k8sLoop, nil
	}
}

func (md *processEventMetadataDecorator) ID() string {
	return "unique-proc-event-metadata-decorator-id"
}

func (md *processEventMetadataDecorator) On(event *informer.Event) error {
	// ignoring updates on non-pod resources
	if event.Resource == nil || event.GetResource().GetPod() == nil {
		return nil
	}
	switch event.Type {
	case informer.EventType_CREATED, informer.EventType_UPDATED:
		md.podsInfoCh <- Event[*informer.ObjectMeta]{Type: EventCreated, Obj: event.Resource}
	case informer.EventType_DELETED:
		md.podsInfoCh <- Event[*informer.ObjectMeta]{Type: EventDeleted, Obj: event.Resource}
	}
	return nil
}

func (md *processEventMetadataDecorator) k8sLoop(ctx context.Context) {
	defer md.output.Close()

	md.log.Debug("starting process event metadata decoration loop")

mainLoop:
	for {
		select {
		case <-ctx.Done():
			break mainLoop
		case pe, ok := <-md.input:
			if !ok {
				break mainLoop
			}
			md.log.Debug("annotating process event", "event", pe)

			// Get metadata entries and apply them
			entries := md.provider.GetMetadataEntries(pe.File.Ns)
			metadata.ApplyMetadata(&pe.File.Service, entries)

			// Check if we got metadata
			if len(entries) == 0 {
				md.log.Debug("no metadata for event", "event", pe)

				// Track processes that don't have metadata yet (for Kubernetes late arrivals)
				if pe.Type == exec.ProcessEventCreated {
					if containerInfo, err := md.getContainerInfo(pe.File.Pid); err == nil {
						md.log.Debug("storing pid info", "pid", pe.File.Pid, "containerId", containerInfo.ContainerID)
						md.tracker.track(containerInfo.ContainerID, &pe)
					}
				} else {
					md.tracker.remove(pe.File.Pid)
				}
			}

			md.output.Send(pe)
		case podEvent, ok := <-md.podsInfoCh:
			if !ok {
				break mainLoop
			}
			switch podEvent.Type {
			case EventCreated:
				md.log.Debug("created pod event", "event", podEvent.Obj)
				md.handlePodUpdateEvent(podEvent.Obj)
			case EventDeleted:
				md.cleanupPodData(podEvent.Obj)
				md.log.Debug("deleted pod event", "event", podEvent.Obj)
			}
		}
	}

	md.log.Debug("stopping process event metadata decoration loop")
}

func (md *processEventMetadataDecorator) getContainerInfo(pid app.PID) (container.Info, error) {
	return containerInfoForPID(pid)
}

func (md *processEventMetadataDecorator) handlePodUpdateEvent(pod *informer.ObjectMeta) {
	md.log.Debug("pod update event", "pod", pod)
	for _, cnt := range pod.Pod.Containers {
		md.log.Debug("looking up running process for pod container", "container", cnt.Id)
		if peMap, ok := md.tracker.info(cnt.Id); ok {
			md.log.Debug("found missed pid info", "containerId", cnt.Id)
			for _, pe := range peMap {
				// Re-decorate with fresh metadata
				entries := md.provider.GetMetadataEntries(pe.File.Ns)
				if len(entries) > 0 {
					metadata.ApplyMetadata(&pe.File.Service, entries)
					md.log.Debug("resubmitting process event", "event", pe)
					md.output.Send(*pe)
				}
			}
			md.tracker.removeAll(cnt.Id)
		}
	}
}

func (md *processEventMetadataDecorator) cleanupPodData(pod *informer.ObjectMeta) {
	for _, cnt := range pod.Pod.Containers {
		md.log.Debug("deleting info for pod container", "container", cnt.Id)
		md.tracker.removeAll(cnt.Id)
	}
}
