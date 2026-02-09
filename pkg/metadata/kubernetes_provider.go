// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metadata // import "go.opentelemetry.io/obi/pkg/metadata"

import (
	"log/slog"
	"maps"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	ikube "go.opentelemetry.io/obi/pkg/internal/kube"
	"go.opentelemetry.io/obi/pkg/kube"
)

// KubernetesProvider wraps kube.Store to implement the Provider interface.
type KubernetesProvider struct {
	store       *kube.Store
	clusterName string
	log         *slog.Logger
}

var _ Provider = (*KubernetesProvider)(nil)

// NewKubernetesProvider creates a new Kubernetes metadata provider.
func NewKubernetesProvider(store *kube.Store, clusterName string) *KubernetesProvider {
	return &KubernetesProvider{
		store:       store,
		clusterName: clusterName,
		log:         slog.With("component", "metadata.KubernetesProvider"),
	}
}

func (k *KubernetesProvider) AddProcess(pid app.PID) {
	k.store.AddProcess(pid)
}

func (k *KubernetesProvider) DeleteProcess(pid app.PID) {
	k.store.DeleteProcess(pid)
}

func (k *KubernetesProvider) MetadataByPIDNs(pidns uint32) *Metadata {
	podMeta, containerName := k.store.PodContainerByPIDNs(pidns)
	if podMeta == nil {
		return nil
	}

	return k.convertToMetadata(podMeta, containerName)
}

func (k *KubernetesProvider) MetadataByIP(ip string) *Metadata {
	objMeta := k.store.ObjectMetaByIP(ip)
	if objMeta == nil {
		return nil
	}

	return k.convertToMetadata(objMeta, "")
}

func (k *KubernetesProvider) ServiceNameForIP(ip string) (string, string, string) {
	return k.store.ServiceNameNamespaceForIP(ip)
}

func (k *KubernetesProvider) DecorateService(svc *svc.Attrs, pidns uint32) {
	podMeta, containerName := k.store.PodContainerByPIDNs(pidns)
	if podMeta != nil {
		k.appendKubeMetadata(svc, podMeta, containerName)
	} else if svc.Metadata == nil {
		// Ensure metadata map is not nil
		svc.Metadata = map[attr.Name]string{}
	}
}

// appendKubeMetadata decorates a service with Kubernetes metadata.
// This is a copy of transform.AppendKubeMetadata to avoid import cycles.
func (k *KubernetesProvider) appendKubeMetadata(svc *svc.Attrs, meta *ikube.CachedObjMeta, containerName string) {
	if meta.Meta.Pod == nil {
		k.log.Debug("pod metadata for is nil. Ignoring decoration", "meta", meta)
		return
	}
	topOwner := ikube.TopOwner(meta.Meta.Pod)
	name, namespace := k.store.ServiceNameNamespaceForMetadata(meta.Meta, containerName)

	// If the user has not defined criteria values for the reported
	// service name and namespace, we will automatically set it from
	// the kubernetes metadata
	if svc.AutoName() {
		svc.UID.Name = name
	}
	if svc.UID.Namespace == "" {
		svc.UID.Namespace = namespace
	}

	// Service Instance ID is set according to OTEL collector conventions
	svc.UID.Instance = meta.Meta.Namespace + "." + meta.Meta.Name + "." + containerName

	k8sMeta := map[attr.Name]string{
		attr.K8sNamespaceName: meta.Meta.Namespace,
		attr.K8sPodName:       meta.Meta.Name,
		attr.K8sContainerName: containerName,
		attr.K8sNodeName:      meta.Meta.Pod.NodeName,
		attr.K8sPodUID:        meta.Meta.Pod.Uid,
		attr.K8sPodStartTime:  meta.Meta.Pod.StartTimeStr,
		attr.K8sClusterName:   k.clusterName,
	}

	// Create a new map to avoid concurrent map writes on svc.Metadata
	m := make(map[attr.Name]string)

	// Thread-safe copy for the existing metadata
	if svcMetadata := svc.Metadata; svcMetadata != nil {
		maps.Copy(m, svcMetadata)
	}

	// Thread-safe copy for the new k8s metadata
	maps.Copy(m, k8sMeta)

	// Add owner metadata
	if topOwner != nil {
		m[attr.K8sOwnerName] = topOwner.Name
		m[attr.K8sKind] = topOwner.Kind
	}

	for _, owner := range meta.Meta.Pod.Owners {
		if _, ok := m[attr.K8sKind]; !ok {
			m[attr.K8sKind] = owner.Kind
		}
		if kindLabel := ownerLabelName(owner.Kind); kindLabel != "" {
			m[kindLabel] = owner.Name
		}
	}

	// Append resource metadata from cached object
	maps.Copy(m, meta.OTELResourceMeta)

	// Thread-safe assignment of the new metadata map
	svc.Metadata = m

	// Override hostname by the Pod name
	svc.HostName = meta.Meta.Name
}

// ownerLabelName returns the attribute name for a given Kubernetes owner kind.
func ownerLabelName(kind string) attr.Name {
	switch kind {
	case "Deployment":
		return attr.K8sDeploymentName
	case "StatefulSet":
		return attr.K8sStatefulSetName
	case "DaemonSet":
		return attr.K8sDaemonSetName
	case "ReplicaSet":
		return attr.K8sReplicaSetName
	case "Job":
		return attr.K8sJobName
	case "CronJob":
		return attr.K8sCronJobName
	default:
		return ""
	}
}

// convertToMetadata converts kube.CachedObjMeta to unified Metadata structure.
func (k *KubernetesProvider) convertToMetadata(cachedMeta *ikube.CachedObjMeta, containerName string) *Metadata {
	meta := cachedMeta.Meta
	if meta.Pod == nil {
		k.log.Debug("pod metadata is nil, cannot convert", "meta", meta)
		return nil
	}

	topOwner := ikube.TopOwner(meta.Pod)
	ownerName := meta.Name
	ownerKind := ""
	if topOwner != nil {
		ownerName = topOwner.Name
		ownerKind = topOwner.Kind
	}

	// Build OTEL attributes
	otelAttrs := map[attr.Name]string{
		attr.K8sNamespaceName: meta.Namespace,
		attr.K8sPodName:       meta.Name,
		attr.K8sContainerName: containerName,
		attr.K8sNodeName:      meta.Pod.NodeName,
		attr.K8sPodUID:        meta.Pod.Uid,
		attr.K8sPodStartTime:  meta.Pod.StartTimeStr,
		attr.K8sClusterName:   k.clusterName,
	}

	if topOwner != nil {
		otelAttrs[attr.K8sOwnerName] = topOwner.Name
		otelAttrs[attr.K8sKind] = topOwner.Kind
	}

	for _, owner := range meta.Pod.Owners {
		if _, ok := otelAttrs[attr.K8sKind]; !ok {
			otelAttrs[attr.K8sKind] = owner.Kind
		}
		if kindLabel := ownerLabelName(owner.Kind); kindLabel != "" {
			otelAttrs[kindLabel] = owner.Name
		}
	}

	// Append resource metadata from cached object
	maps.Copy(otelAttrs, cachedMeta.OTELResourceMeta)

	return &Metadata{
		Name:          meta.Name,
		Namespace:     meta.Namespace,
		ContainerID:   "", // Not directly available in this context
		ContainerName: containerName,
		K8sMetadata: &K8sMetadata{
			PodName:      meta.Name,
			PodUID:       meta.Pod.Uid,
			PodStartTime: meta.Pod.StartTimeStr,
			NodeName:     meta.Pod.NodeName,
			OwnerName:    ownerName,
			OwnerKind:    ownerKind,
			ClusterName:  k.clusterName,
			Labels:       meta.Labels,
			Annotations:  meta.Annotations,
		},
		OTELAttributes: otelAttrs,
	}
}
