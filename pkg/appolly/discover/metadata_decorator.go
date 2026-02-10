// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"log/slog"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/meta"
	"go.opentelemetry.io/obi/pkg/metadata"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// metadataDecorator decorates process attributes with metadata from the unified provider.
type metadataDecorator struct {
	provider metadata.Provider
	log      *slog.Logger

	// cached system objects
	mt                 sync.RWMutex
	containerByPID     map[app.PID]string // PID to container ID
	processByContainer map[string][]ProcessAttrs

	podsInfoCh chan Event[*informer.ObjectMeta]
	output     *msg.Queue[[]Event[ProcessAttrs]]
	input      <-chan []Event[ProcessAttrs]
}

func MetadataDiscoveryDecoratorProvider(
	provider metadata.Provider,
	metaNotifier meta.Notifier,
	input, output *msg.Queue[[]Event[ProcessAttrs]],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if provider == nil {
			return swarm.Bypass(input, output)
		}

		md := &metadataDecorator{
			provider:           provider,
			log:                slog.With("component", "discover.metadataDecorator"),
			containerByPID:     map[app.PID]string{},
			processByContainer: map[string][]ProcessAttrs{},
			podsInfoCh:         make(chan Event[*informer.ObjectMeta], 10),
			input:              input.Subscribe(msg.SubscriberName("MetadataDecorator")),
			output:             output,
		}

		// Subscribe to pod events if we have a Kubernetes provider
		if metaNotifier != nil {
			go metaNotifier.Subscribe(md)
		}

		return md.decorate, nil
	}
}

func (md *metadataDecorator) ID() string { return "unique-metadata-decorator-id" }

// On is invoked every time an object metadata instance is stored or deleted.
// This is only called when using Kubernetes provider.
func (md *metadataDecorator) On(event *informer.Event) error {
	// ignoring updates on non-pod resources
	if event.Resource == nil || event.GetResource().GetPod() == nil {
		return nil
	}
	switch event.Type {
	case informer.EventType_CREATED, informer.EventType_UPDATED:
		md.podsInfoCh <- Event[*informer.ObjectMeta]{Type: EventCreated, Obj: event.Resource}
	case informer.EventType_DELETED:
		md.podsInfoCh <- Event[*informer.ObjectMeta]{Type: EventDeleted, Obj: event.Resource}
	default:
		md.log.Debug("ignoring unknown event type", "event", event)
	}
	return nil
}

// decorate listens for process events and pod events, decorating processes with metadata.
func (md *metadataDecorator) decorate(_ context.Context) {
	defer md.output.Close()

	md.log.Debug("starting metadataDecorator")

	for {
		select {
		case podEvent, ok := <-md.podsInfoCh:
			if !ok {
				md.log.Debug("pod events channel closed")
				return
			}
			md.enrichPodEvent(podEvent)
		case processEvents, ok := <-md.input:
			if !ok {
				md.log.Debug("input channel closed. Stopping")
				return
			}
			md.enrichProcessEvent(processEvents)
		}
	}
}

func (md *metadataDecorator) enrichPodEvent(podEvent Event[*informer.ObjectMeta]) {
	switch podEvent.Type {
	case EventCreated:
		md.log.Debug("Pod added",
			"namespace", podEvent.Obj.Namespace, "name", podEvent.Obj.Name,
			"containers", podEvent.Obj.Pod.Containers)
		if events := md.onNewPod(podEvent.Obj); len(events) > 0 {
			md.output.Send(events)
		}
	case EventDeleted:
		md.log.Debug("Pod deleted", "namespace", podEvent.Obj.Namespace, "name", podEvent.Obj.Name)
		md.onDeletedPod(podEvent.Obj)
	}
}

func (md *metadataDecorator) enrichProcessEvent(processEvents []Event[ProcessAttrs]) {
	eventsWithMeta := make([]Event[ProcessAttrs], 0, len(processEvents))
	for _, procEvent := range processEvents {
		switch procEvent.Type {
		case EventCreated:
			md.log.Debug("new process", "pid", procEvent.Obj.pid)
			if procWithMeta, ok := md.onNewProcess(procEvent.Obj); ok {
				eventsWithMeta = append(eventsWithMeta, Event[ProcessAttrs]{
					Type: EventCreated,
					Obj:  procWithMeta,
				})
			}
		case EventDeleted:
			md.log.Debug("process stopped", "pid", procEvent.Obj.pid)
			md.onProcessTerminate(procEvent.Obj)
			eventsWithMeta = append(eventsWithMeta, procEvent)
		}
	}

	if len(eventsWithMeta) > 0 {
		md.output.Send(eventsWithMeta)
	}
}

func (md *metadataDecorator) onNewProcess(procInfo ProcessAttrs) (ProcessAttrs, bool) {
	md.mt.Lock()
	defer md.mt.Unlock()

	// Register process with the provider
	md.provider.AddProcess(procInfo.pid)

	// Get container info for tracking
	containerInfo, err := containerInfoForPID(procInfo.pid)
	if err != nil {
		md.log.Debug("can't get container info for PID", "pid", procInfo.pid, "error", err)
		return ProcessAttrs{}, false
	}

	md.log.Debug("found container info for process", "pid", procInfo.pid, "container", containerInfo.ContainerID)

	md.containerByPID[procInfo.pid] = containerInfo.ContainerID
	md.processByContainer[containerInfo.ContainerID] = append(md.processByContainer[containerInfo.ContainerID], procInfo)

	// Metadata will be added when pod events arrive
	// For now, return the process info as-is
	return procInfo, true
}

func (md *metadataDecorator) onProcessTerminate(procInfo ProcessAttrs) {
	md.mt.Lock()
	defer md.mt.Unlock()

	md.provider.DeleteProcess(procInfo.pid)

	if containerID, ok := md.containerByPID[procInfo.pid]; ok {
		if pidProcInfos, ok := md.processByContainer[containerID]; ok {
			filtered := []ProcessAttrs{}
			for _, pidProcInfo := range pidProcInfos {
				if pidProcInfo.pid != procInfo.pid {
					filtered = append(filtered, pidProcInfo)
					continue
				}
				md.log.Debug("removing process mapping", "container", containerID, "pid", pidProcInfo.pid)
			}
			if len(filtered) == 0 {
				delete(md.processByContainer, containerID)
			} else {
				md.processByContainer[containerID] = filtered
			}
		}
	}
	delete(md.containerByPID, procInfo.pid)
}

func (md *metadataDecorator) onNewPod(pod *informer.ObjectMeta) []Event[ProcessAttrs] {
	md.mt.RLock()
	defer md.mt.RUnlock()
	var events []Event[ProcessAttrs]
	for _, cnt := range pod.Pod.Containers {
		md.log.Debug("looking up running process for pod container", "container", cnt.Id)
		if procInfos, ok := md.processByContainer[cnt.Id]; ok {
			for _, procInfo := range procInfos {
				md.log.Debug("matched pod with running process", "container", cnt.Id, "pid", procInfo.pid)
				// Build metadata directly from pod info
				procInfo = md.withPodMetadata(procInfo, pod, cnt.Name)
				events = append(events, Event[ProcessAttrs]{
					Type: EventCreated,
					Obj:  procInfo,
				})
			}
		}
	}
	return events
}

func (md *metadataDecorator) onDeletedPod(pod *informer.ObjectMeta) {
	md.mt.Lock()
	defer md.mt.Unlock()
	for _, cnt := range pod.Pod.Containers {
		if pbcs, ok := md.processByContainer[cnt.Id]; ok {
			for _, pbc := range pbcs {
				delete(md.containerByPID, pbc.pid)
			}
		}
		delete(md.processByContainer, cnt.Id)
	}
}

// withPodMetadata returns a copy of ProcessAttrs with Kubernetes metadata populated from pod info.
// This builds metadata directly from the informer.ObjectMeta similar to the old watcher_kube.go approach.
func (md *metadataDecorator) withPodMetadata(pp ProcessAttrs, pod *informer.ObjectMeta, containerName string) ProcessAttrs {
	ret := pp
	ret.metadata = map[string]string{
		services.AttrNamespace: pod.Namespace,
		services.AttrPodName:   pod.Name,
	}

	// Set owner name (top-level owner)
	ownerName := pod.Name
	if pod.Pod != nil {
		for _, owner := range pod.Pod.Owners {
			// Use first owner as the main owner (usually the top-level one)
			if ownerName == pod.Name {
				ownerName = owner.Name
			}
			// Add specific owner type labels
			if kindLabel := ownerLabelForKind(owner.Kind); kindLabel != "" {
				ret.metadata[kindLabel] = owner.Name
			}
		}
	}
	ret.metadata[services.AttrOwnerName] = ownerName

	// Set container name
	if containerName != "" {
		ret.metadata[services.AttrContainerName] = containerName
	}

	// Copy labels and annotations
	ret.podLabels = pod.Labels
	ret.podAnnotations = pod.Annotations

	return ret
}

// ownerLabelForKind returns the Prometheus-style label name for a Kubernetes owner kind.
func ownerLabelForKind(kind string) string {
	switch kind {
	case "Deployment":
		return attr.K8sDeploymentName.Prom()
	case "StatefulSet":
		return attr.K8sStatefulSetName.Prom()
	case "DaemonSet":
		return attr.K8sDaemonSetName.Prom()
	case "ReplicaSet":
		return attr.K8sReplicaSetName.Prom()
	case "Job":
		return attr.K8sJobName.Prom()
	case "CronJob":
		return attr.K8sCronJobName.Prom()
	default:
		return ""
	}
}
