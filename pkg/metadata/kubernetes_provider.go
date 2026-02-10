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

func (k *KubernetesProvider) GetMetadataEntries(pidns uint32) []MetadataEntry {
	podMeta, containerName := k.store.PodContainerByPIDNs(pidns)
	if podMeta == nil {
		return nil
	}

	return k.buildMetadataEntries(podMeta, containerName)
}

func (k *KubernetesProvider) GetMetadataEntriesByIP(ip string) []MetadataEntry {
	objMeta := k.store.ObjectMetaByIP(ip)
	if objMeta == nil {
		return nil
	}

	return k.buildMetadataEntries(objMeta, "")
}

func (k *KubernetesProvider) GetServiceName(ip string) ServiceInfo {
	name, namespace, k8sNamespace := k.store.ServiceNameNamespaceForIP(ip)
	return ServiceInfo{
		Name:         name,
		Namespace:    namespace,
		K8sNamespace: k8sNamespace,
	}
}

// buildMetadataEntries constructs Kubernetes metadata entries from pod metadata.
func (k *KubernetesProvider) buildMetadataEntries(cachedMeta *ikube.CachedObjMeta, containerName string) []MetadataEntry {
	meta := cachedMeta.Meta
	if meta.Pod == nil {
		k.log.Debug("pod metadata is nil, cannot build entries", "meta", meta)
		return nil
	}

	topOwner := ikube.TopOwner(meta.Pod)

	// Start with base K8s metadata
	entries := []MetadataEntry{
		{Key: attr.K8sNamespaceName, Value: meta.Namespace},
		{Key: attr.K8sPodName, Value: meta.Name},
		{Key: attr.K8sContainerName, Value: containerName},
		{Key: attr.K8sNodeName, Value: meta.Pod.NodeName},
		{Key: attr.K8sPodUID, Value: meta.Pod.Uid},
		{Key: attr.K8sPodStartTime, Value: meta.Pod.StartTimeStr},
		{Key: attr.K8sClusterName, Value: k.clusterName},
	}

	// Add owner metadata
	if topOwner != nil {
		entries = append(entries,
			MetadataEntry{Key: attr.K8sOwnerName, Value: topOwner.Name},
			MetadataEntry{Key: attr.K8sKind, Value: topOwner.Kind},
		)
	}

	// Add all owner kinds
	for _, owner := range meta.Pod.Owners {
		// Set K8sKind only if not already set
		hasKind := false
		for _, e := range entries {
			if e.Key == attr.K8sKind {
				hasKind = true
				break
			}
		}
		if !hasKind {
			entries = append(entries, MetadataEntry{Key: attr.K8sKind, Value: owner.Kind})
		}

		// Add specific owner kind label
		if kindLabel := ownerLabelName(owner.Kind); kindLabel != "" {
			entries = append(entries, MetadataEntry{Key: kindLabel, Value: owner.Name})
		}
	}

	// Add OTEL resource metadata from cached object
	for k, v := range cachedMeta.OTELResourceMeta {
		entries = append(entries, MetadataEntry{Key: k, Value: v})
	}

	return entries
}

// DecorateService provides backward compatibility by applying metadata and service identity.
// This method combines metadata entries with service identity configuration.
func (k *KubernetesProvider) DecorateService(svc *svc.Attrs, pidns uint32) {
	podMeta, containerName := k.store.PodContainerByPIDNs(pidns)
	if podMeta == nil {
		return
	}

	k.appendKubeMetadata(svc, podMeta, containerName)
}

// appendKubeMetadata decorates a service with Kubernetes metadata and service identity.
// This is kept for backward compatibility and full service decoration.
func (k *KubernetesProvider) appendKubeMetadata(svc *svc.Attrs, meta *ikube.CachedObjMeta, containerName string) {
	if meta.Meta.Pod == nil {
		k.log.Debug("pod metadata for is nil. Ignoring decoration", "meta", meta)
		return
	}

	// Determine service name and namespace using Kubernetes business logic
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

	// Get metadata entries and convert to map
	entries := k.buildMetadataEntries(meta, containerName)

	// Create metadata map
	m := make(map[attr.Name]string, len(entries))
	if svcMetadata := svc.Metadata; svcMetadata != nil {
		maps.Copy(m, svcMetadata)
	}

	for _, entry := range entries {
		m[entry.Key] = entry.Value
	}

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
