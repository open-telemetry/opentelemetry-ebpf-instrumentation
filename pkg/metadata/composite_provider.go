// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metadata // import "go.opentelemetry.io/obi/pkg/metadata"

import (
	"go.opentelemetry.io/obi/pkg/appolly/app"
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

// GetMetadataEntries collects metadata entries from all providers.
// Entries from all providers are combined (later providers can override earlier ones).
func (c *CompositeProvider) GetMetadataEntries(pidns uint32) []MetadataEntry {
	var allEntries []MetadataEntry
	for _, p := range c.providers {
		entries := p.GetMetadataEntries(pidns)
		allEntries = append(allEntries, entries...)
	}
	return allEntries
}

// GetMetadataEntriesByIP collects metadata entries from all providers by IP.
// Entries from all providers are combined (later providers can override earlier ones).
func (c *CompositeProvider) GetMetadataEntriesByIP(ip string) []MetadataEntry {
	var allEntries []MetadataEntry
	for _, p := range c.providers {
		entries := p.GetMetadataEntriesByIP(ip)
		allEntries = append(allEntries, entries...)
	}
	return allEntries
}

// GetServiceName returns service name from the first provider that has it.
// Returns empty ServiceInfo if no provider has service name for this IP.
func (c *CompositeProvider) GetServiceName(ip string) ServiceInfo {
	for _, p := range c.providers {
		if info := p.GetServiceName(ip); info.Name != "" {
			return info
		}
	}
	return ServiceInfo{}
}
