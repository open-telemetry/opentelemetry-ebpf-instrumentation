// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metadata // import "go.opentelemetry.io/obi/pkg/metadata"

import (
	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// Provider abstracts metadata retrieval for containers and pods.
// It provides a unified interface for Kubernetes and Docker metadata sources.
type Provider interface {
	// AddProcess registers a process PID for metadata tracking.
	// This is called when a new process is discovered.
	AddProcess(pid app.PID)

	// DeleteProcess removes a process PID from metadata tracking.
	// This is called when a process terminates.
	DeleteProcess(pid app.PID)

	// MetadataByPIDNs retrieves metadata by PID namespace.
	// Used for decorating spans and process events.
	// Returns nil if no metadata is found.
	MetadataByPIDNs(pidns uint32) *Metadata

	// MetadataByIP retrieves metadata by IP address.
	// Only supported by Kubernetes provider (returns nil for Docker).
	// Used for network flow decoration and peer name resolution.
	MetadataByIP(ip string) *Metadata

	// ServiceNameForIP retrieves service name information by IP address.
	// Only supported by Kubernetes provider (returns empty strings for Docker).
	// Returns (serviceName, serviceNamespace, k8sNamespace).
	ServiceNameForIP(ip string) (string, string, string)

	// DecorateService decorates a service with metadata from the given PID namespace.
	// This is the primary method for adding metadata to services.
	DecorateService(svc *svc.Attrs, pidns uint32)
}

// Metadata represents unified container/pod metadata from any source.
type Metadata struct {
	// Name is the container or pod name
	Name string

	// Namespace is the Kubernetes namespace (empty for Docker)
	Namespace string

	// ContainerID is the container identifier
	ContainerID string

	// ContainerName is the container name (may differ from Name for Kubernetes)
	ContainerName string

	// K8sMetadata contains Kubernetes-specific metadata (nil for Docker)
	K8sMetadata *K8sMetadata

	// OTELAttributes contains OTEL resource attributes ready for decoration
	OTELAttributes map[attr.Name]string
}

// K8sMetadata contains Kubernetes-specific metadata fields.
type K8sMetadata struct {
	// PodName is the Kubernetes pod name
	PodName string

	// PodUID is the Kubernetes pod unique identifier
	PodUID string

	// PodStartTime is the pod start time as a string
	PodStartTime string

	// NodeName is the Kubernetes node name
	NodeName string

	// OwnerName is the name of the top-level owner (Deployment, StatefulSet, etc.)
	OwnerName string

	// OwnerKind is the kind of the top-level owner
	OwnerKind string

	// ClusterName is the Kubernetes cluster name
	ClusterName string

	// Labels are the pod labels
	Labels map[string]string

	// Annotations are the pod annotations
	Annotations map[string]string
}

// ServiceInfo contains service name and namespace information.
type ServiceInfo struct {
	// Name is the OTEL service name
	Name string

	// Namespace is the OTEL service namespace
	Namespace string

	// K8sNamespace is the Kubernetes namespace (may differ from service namespace)
	K8sNamespace string
}
