// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metadata // import "go.opentelemetry.io/obi/pkg/metadata"

import (
	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// MetadataEntry represents a single metadata key-value pair.
type MetadataEntry struct {
	Key   attr.Name
	Value string
}

// Provider abstracts metadata retrieval for containers and pods.
// It provides a unified interface for Kubernetes and Docker metadata sources.
type Provider interface {
	// AddProcess registers a process PID for metadata tracking.
	// This is called when a new process is discovered.
	AddProcess(pid app.PID)

	// DeleteProcess removes a process PID from metadata tracking.
	// This is called when a process terminates.
	DeleteProcess(pid app.PID)

	// GetMetadataEntries retrieves metadata entries by PID namespace.
	// Returns a list of key-value pairs to decorate the service.
	// Returns empty slice if no metadata is found.
	GetMetadataEntries(pidns uint32) []MetadataEntry

	// GetMetadataEntriesByIP retrieves metadata entries by IP address.
	// Only supported by Kubernetes provider (returns empty for Docker).
	// Used for network flow decoration and peer name resolution.
	GetMetadataEntriesByIP(ip string) []MetadataEntry

	// GetServiceName retrieves service name information by IP address.
	// Only supported by Kubernetes provider (returns empty ServiceInfo for Docker).
	GetServiceName(ip string) ServiceInfo
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

// ApplyMetadata applies metadata entries to a service's metadata map.
// It ensures the metadata map is initialized before adding entries.
func ApplyMetadata(svc *svc.Attrs, entries []MetadataEntry) {
	if svc.Metadata == nil {
		svc.Metadata = make(map[attr.Name]string, len(entries))
	}
	for _, entry := range entries {
		svc.Metadata[entry.Key] = entry.Value
	}
}
