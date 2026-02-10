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

// kubernetesMetadataDecorator decorates process attributes with Kubernetes metadata.
// It subscribes to pod events from the Kubernetes informer and matches them with
// discovered processes, building metadata from pod information.
type kubernetesMetadataDecorator struct {
	provider metadata.Provider
	log      *slog.Logger

	// Process/container tracking for matching pods with processes
	mt                 sync.RWMutex
	containerByPID     map[app.PID]string // PID to container ID
	processByContainer map[string][]ProcessAttrs

	// Kubernetes-specific: pod event handling
	podsInfoCh chan Event[*informer.ObjectMeta]
	output     *msg.Queue[[]Event[ProcessAttrs]]
	input      <-chan []Event[ProcessAttrs]
}

// KubernetesMetadataDecoratorProvider creates a Kubernetes-specific metadata decorator.
// It requires a Kubernetes provider and meta.Notifier for pod event subscription.
func KubernetesMetadataDecoratorProvider(
	provider metadata.Provider,
	metaNotifier meta.Notifier,
	input, output *msg.Queue[[]Event[ProcessAttrs]],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if provider == nil || metaNotifier == nil {
			return swarm.Bypass(input, output)
		}

		kmd := &kubernetesMetadataDecorator{
			provider:           provider,
			log:                slog.With("component", "discover.kubernetesMetadataDecorator"),
			containerByPID:     map[app.PID]string{},
			processByContainer: map[string][]ProcessAttrs{},
			podsInfoCh:         make(chan Event[*informer.ObjectMeta], 10),
			input:              input.Subscribe(msg.SubscriberName("KubernetesMetadataDecorator")),
			output:             output,
		}

		// Subscribe to pod events from Kubernetes informer
		go metaNotifier.Subscribe(kmd)

		return kmd.decorate, nil
	}
}

func (kmd *kubernetesMetadataDecorator) ID() string {
	return "kubernetes-metadata-decorator-id"
}

// On implements meta.Observer interface.
// It is invoked every time a pod is created, updated, or deleted in Kubernetes.
func (kmd *kubernetesMetadataDecorator) On(event *informer.Event) error {
	// Only process pod events
	if event.Resource == nil || event.GetResource().GetPod() == nil {
		return nil
	}

	switch event.Type {
	case informer.EventType_CREATED, informer.EventType_UPDATED:
		kmd.podsInfoCh <- Event[*informer.ObjectMeta]{Type: EventCreated, Obj: event.Resource}
	case informer.EventType_DELETED:
		kmd.podsInfoCh <- Event[*informer.ObjectMeta]{Type: EventDeleted, Obj: event.Resource}
	default:
		kmd.log.Debug("ignoring unknown event type", "event", event)
	}
	return nil
}

// decorate listens for both process events and pod events, performing bidirectional matching.
// Processes can arrive before their pods, or pods can arrive before their processes.
func (kmd *kubernetesMetadataDecorator) decorate(_ context.Context) {
	defer kmd.output.Close()

	kmd.log.Debug("starting Kubernetes metadata decorator")

	for {
		select {
		case podEvent, ok := <-kmd.podsInfoCh:
			if !ok {
				kmd.log.Debug("pod events channel closed")
				return
			}
			kmd.enrichPodEvent(podEvent)
		case processEvents, ok := <-kmd.input:
			if !ok {
				kmd.log.Debug("input channel closed. Stopping")
				return
			}
			kmd.enrichProcessEvent(processEvents)
		}
	}
}

func (kmd *kubernetesMetadataDecorator) enrichPodEvent(podEvent Event[*informer.ObjectMeta]) {
	switch podEvent.Type {
	case EventCreated:
		kmd.log.Debug("Pod added",
			"namespace", podEvent.Obj.Namespace, "name", podEvent.Obj.Name,
			"containers", podEvent.Obj.Pod.Containers)
		if events := kmd.onNewPod(podEvent.Obj); len(events) > 0 {
			kmd.output.Send(events)
		}
	case EventDeleted:
		kmd.log.Debug("Pod deleted", "namespace", podEvent.Obj.Namespace, "name", podEvent.Obj.Name)
		kmd.onDeletedPod(podEvent.Obj)
	}
}

func (kmd *kubernetesMetadataDecorator) enrichProcessEvent(processEvents []Event[ProcessAttrs]) {
	eventsWithMeta := make([]Event[ProcessAttrs], 0, len(processEvents))
	for _, procEvent := range processEvents {
		switch procEvent.Type {
		case EventCreated:
			kmd.log.Debug("new process", "pid", procEvent.Obj.pid)
			if procWithMeta, ok := kmd.onNewProcess(procEvent.Obj); ok {
				eventsWithMeta = append(eventsWithMeta, Event[ProcessAttrs]{
					Type: EventCreated,
					Obj:  procWithMeta,
				})
			}
		case EventDeleted:
			kmd.log.Debug("process stopped", "pid", procEvent.Obj.pid)
			kmd.onProcessTerminate(procEvent.Obj)
			eventsWithMeta = append(eventsWithMeta, procEvent)
		}
	}

	if len(eventsWithMeta) > 0 {
		kmd.output.Send(eventsWithMeta)
	}
}

func (kmd *kubernetesMetadataDecorator) onNewProcess(procInfo ProcessAttrs) (ProcessAttrs, bool) {
	kmd.mt.Lock()
	defer kmd.mt.Unlock()

	// Register process with the provider
	kmd.provider.AddProcess(procInfo.pid)

	// Get container info for tracking
	containerInfo, err := containerInfoForPID(procInfo.pid)
	if err != nil {
		kmd.log.Debug("can't get container info for PID", "pid", procInfo.pid, "error", err)
		return ProcessAttrs{}, false
	}

	kmd.log.Debug("found container info for process", "pid", procInfo.pid, "container", containerInfo.ContainerID)

	kmd.containerByPID[procInfo.pid] = containerInfo.ContainerID
	kmd.processByContainer[containerInfo.ContainerID] = append(kmd.processByContainer[containerInfo.ContainerID], procInfo)

	// Metadata will be added when pod events arrive
	// For now, return the process info as-is for tracking
	return procInfo, true
}

func (kmd *kubernetesMetadataDecorator) onProcessTerminate(procInfo ProcessAttrs) {
	kmd.mt.Lock()
	defer kmd.mt.Unlock()

	kmd.provider.DeleteProcess(procInfo.pid)

	if containerID, ok := kmd.containerByPID[procInfo.pid]; ok {
		if pidProcInfos, ok := kmd.processByContainer[containerID]; ok {
			filtered := []ProcessAttrs{}
			for _, pidProcInfo := range pidProcInfos {
				if pidProcInfo.pid != procInfo.pid {
					filtered = append(filtered, pidProcInfo)
					continue
				}
				kmd.log.Debug("removing process mapping", "container", containerID, "pid", pidProcInfo.pid)
			}
			if len(filtered) == 0 {
				delete(kmd.processByContainer, containerID)
			} else {
				kmd.processByContainer[containerID] = filtered
			}
		}
	}
	delete(kmd.containerByPID, procInfo.pid)
}

// onNewPod matches a new pod with existing processes and emits decorated events.
func (kmd *kubernetesMetadataDecorator) onNewPod(pod *informer.ObjectMeta) []Event[ProcessAttrs] {
	kmd.mt.RLock()
	defer kmd.mt.RUnlock()

	var events []Event[ProcessAttrs]
	for _, cnt := range pod.Pod.Containers {
		kmd.log.Debug("looking up running process for pod container", "container", cnt.Id)
		if procInfos, ok := kmd.processByContainer[cnt.Id]; ok {
			for _, procInfo := range procInfos {
				kmd.log.Debug("matched pod with running process", "container", cnt.Id, "pid", procInfo.pid)
				// Build metadata directly from pod info
				procInfo = kmd.withPodMetadata(procInfo, pod, cnt.Name)
				events = append(events, Event[ProcessAttrs]{
					Type: EventCreated,
					Obj:  procInfo,
				})
			}
		}
	}
	return events
}

func (kmd *kubernetesMetadataDecorator) onDeletedPod(pod *informer.ObjectMeta) {
	kmd.mt.Lock()
	defer kmd.mt.Unlock()

	for _, cnt := range pod.Pod.Containers {
		if pbcs, ok := kmd.processByContainer[cnt.Id]; ok {
			for _, pbc := range pbcs {
				delete(kmd.containerByPID, pbc.pid)
			}
		}
		delete(kmd.processByContainer, cnt.Id)
	}
}

// withPodMetadata returns a copy of ProcessAttrs with Kubernetes metadata populated from pod info.
// This builds metadata directly from the informer.ObjectMeta, including namespace, pod name,
// owner hierarchy, labels, and annotations.
func (kmd *kubernetesMetadataDecorator) withPodMetadata(pp ProcessAttrs, pod *informer.ObjectMeta, containerName string) ProcessAttrs {
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
