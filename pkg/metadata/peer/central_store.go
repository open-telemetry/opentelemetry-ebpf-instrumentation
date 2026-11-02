// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"
)

var errTooManyHosts = errors.New("central metadata host limit reached")

type centralHost struct {
	addresses []netip.Addr
	snapshot  Snapshot
	published time.Time
}

// centralStore keeps the latest snapshot published by each host, indexed by the addresses it is reachable at.
// Hosts are keyed by host ID, since distinct hosts may share a hostname.
type centralStore struct {
	mu        sync.RWMutex
	ttl       time.Duration
	maxHosts  int
	hosts     map[string]*centralHost
	addresses map[netip.Addr]string
}

func newCentralStore(ttl time.Duration, maxHosts int) *centralStore {
	return &centralStore{
		ttl:       ttl,
		maxHosts:  maxHosts,
		hosts:     map[string]*centralHost{},
		addresses: map[netip.Addr]string{},
	}
}

// publish replaces the host snapshot. An address claimed by another host moves to the latest publishing host.
func (s *centralStore) publish(hostID string, addresses []netip.Addr, snapshot Snapshot, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	previous, exists := s.hosts[hostID]
	if !exists && len(s.hosts) >= s.maxHosts {
		return errTooManyHosts
	}

	if exists {
		s.releaseAddresses(hostID, previous.addresses)
	}

	for _, address := range addresses {
		s.addresses[address] = hostID
	}

	s.hosts[hostID] = &centralHost{addresses: addresses, snapshot: snapshot, published: now}
	return nil
}

// lookup returns the snapshot published for an address, aged to now and with callers limited to the requester.
func (s *centralStore) lookup(address netip.Addr, requester []netip.Addr, now time.Time) (*Snapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	host, exists := s.hosts[s.addresses[address]]
	if !exists || now.Sub(host.published) >= s.ttl {
		return nil, false
	}

	age := now.Sub(host.published).Milliseconds()
	snapshot := Snapshot{
		Version:               ProtocolVersion,
		Hostname:              host.snapshot.Hostname,
		Services:              slices.Clone(host.snapshot.Services),
		Listeners:             slices.Clone(host.snapshot.Listeners),
		MetricProtocols:       host.snapshot.MetricProtocols,
		CallerAmbiguityMillis: max(0, host.snapshot.CallerAmbiguityMillis-age),
	}

	requesters := make(map[netip.Addr]struct{}, len(requester))
	for _, address := range requester {
		requesters[address] = struct{}{}
	}

	for _, caller := range host.snapshot.Callers {
		destination, err := netip.ParseAddr(caller.Destination.IP)
		_, requested := requesters[destination]
		if err != nil || !requested {
			continue
		}

		aged := Caller{Destination: caller.Destination}
		for _, service := range caller.Services {
			if remaining := service.RemainingMillis - age; remaining > 0 {
				aged.Services = append(aged.Services, CallerService{Service: service.Service, RemainingMillis: remaining})
			}
		}

		if len(aged.Services) > 0 {
			snapshot.Callers = append(snapshot.Callers, aged)
		}
	}

	return &snapshot, true
}

// expire removes hosts that have not published within the TTL.
func (s *centralStore) expire(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for hostID, host := range s.hosts {
		if now.Sub(host.published) >= s.ttl {
			s.releaseAddresses(hostID, host.addresses)
			delete(s.hosts, hostID)
		}
	}
}

// releaseAddresses removes the host's address mappings, keeping those already claimed by another host.
func (s *centralStore) releaseAddresses(hostID string, addresses []netip.Addr) {
	for _, address := range addresses {
		if s.addresses[address] == hostID {
			delete(s.addresses, address)
		}
	}
}
