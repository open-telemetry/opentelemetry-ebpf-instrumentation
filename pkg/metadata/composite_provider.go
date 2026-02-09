// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metadata // import "go.opentelemetry.io/obi/pkg/metadata"

import (
	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// CompositeProvider combines multiple metadata providers into a single provider.
// It allows decorating with metadata from multiple sources (e.g., Kubernetes + Cloud).
type CompositeProvider struct {
	providers []Provider
}

var _ Provider = (*CompositeProvider)(nil)

// NewCompositeProvider creates a new composite provider from a list of providers.
// If the list is empty, it behaves as a no-op provider.
func NewCompositeProvider(providers ...Provider) *CompositeProvider {
	return &CompositeProvider{
		providers: providers,
	}
}

func (c *CompositeProvider) AddProcess(pid app.PID) {
	for _, p := range c.providers {
		p.AddProcess(pid)
	}
}

func (c *CompositeProvider) DeleteProcess(pid app.PID) {
	for _, p := range c.providers {
		p.DeleteProcess(pid)
	}
}

// MetadataByPIDNs returns metadata from the first provider that has it.
// Returns nil if no provider has metadata for this PID namespace.
func (c *CompositeProvider) MetadataByPIDNs(pidns uint32) *Metadata {
	for _, p := range c.providers {
		if meta := p.MetadataByPIDNs(pidns); meta != nil {
			return meta
		}
	}
	return nil
}

// MetadataByIP returns metadata from the first provider that has it.
// Returns nil if no provider has metadata for this IP.
func (c *CompositeProvider) MetadataByIP(ip string) *Metadata {
	for _, p := range c.providers {
		if meta := p.MetadataByIP(ip); meta != nil {
			return meta
		}
	}
	return nil
}

// ServiceNameForIP returns service name from the first provider that has it.
// Returns empty strings if no provider has service name for this IP.
func (c *CompositeProvider) ServiceNameForIP(ip string) (string, string, string) {
	for _, p := range c.providers {
		if name, namespace, k8sNamespace := p.ServiceNameForIP(ip); name != "" {
			return name, namespace, k8sNamespace
		}
	}
	return "", "", ""
}

// DecorateService calls all providers in sequence to decorate the service.
// Each provider can add its own metadata attributes.
func (c *CompositeProvider) DecorateService(svc *svc.Attrs, pidns uint32) {
	// Ensure metadata map is initialized
	if svc.Metadata == nil {
		svc.Metadata = map[attr.Name]string{}
	}

	// Let each provider add its metadata
	for _, p := range c.providers {
		p.DecorateService(svc, pidns)
	}
}
