// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"net/netip"
	"time"
)

type cachedSnapshot struct {
	hostname        string
	listeners       map[Endpoint][]Service
	callers         map[Endpoint][]CallerService
	ambiguityMillis int64
}

// indexSnapshot indexes listeners and caller observations by endpoint for cached lookups.
func indexSnapshot(snapshot *Snapshot) *cachedSnapshot {
	indexed := &cachedSnapshot{
		hostname:        snapshot.Hostname,
		ambiguityMillis: snapshot.CallerAmbiguityMillis,
		listeners:       make(map[Endpoint][]Service),
		callers:         make(map[Endpoint][]CallerService),
	}

	for _, listener := range snapshot.Listeners {
		indexed.listeners[listener.Endpoint] = append(indexed.listeners[listener.Endpoint], listener.Service)
	}

	for _, caller := range snapshot.Callers {
		indexed.callers[caller.Destination] = append(indexed.callers[caller.Destination], caller.Services...)
	}

	return indexed
}

// listenerService finds a unique service across listeners, falling back to the hostname.
func listenerService(index map[Endpoint][]Service, endpoint Endpoint, hostname string) Service {
	fallback := Service{Name: hostname}
	var selected Service
	address, _ := netip.ParseAddr(endpoint.IP)

	for _, ip := range [...]string{endpoint.IP, "0.0.0.0", "::"} {
		if ip == "0.0.0.0" && address.Is6() {
			continue
		}
		if ip == "::" && address.Is4() {
			continue
		}

		for _, service := range index[Endpoint{IP: ip, Port: endpoint.Port}] {
			// We found multiple services with different metadata listening on the same port.
			if selected.Name != "" && selected != service {
				return fallback
			}

			selected = service
		}
	}

	if selected.Name == "" {
		return fallback
	}

	return selected
}

// destinationService resolves a destination from the cached listener inventory.
func (s *cachedSnapshot) destinationService(endpoint Endpoint) Service {
	return listenerService(s.listeners, endpoint, s.hostname)
}

// callerService selects a unique unexpired caller, falling back to the hostname when unresolved or ambiguous.
func (s *cachedSnapshot) callerService(endpoint Endpoint, age time.Duration) Service {
	fallback := Service{Name: s.hostname}

	if s.ambiguityMillis > age.Milliseconds() {
		return fallback
	}

	var selected Service
	for _, candidate := range s.callers[endpoint] {
		if candidate.RemainingMillis <= age.Milliseconds() {
			continue
		}

		if selected.Name != "" && selected != candidate.Service {
			return fallback
		}

		selected = candidate.Service
	}

	if selected.Name == "" {
		return fallback
	}

	return selected
}
