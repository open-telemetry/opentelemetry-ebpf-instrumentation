// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

type activeConnectionInfo struct {
	attributes attribute.Set
	lastSeen   time.Time
}

type connectionInfoStore struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[attribute.Distinct]activeConnectionInfo
}

func newConnectionInfoStore(ttl time.Duration) *connectionInfoStore {
	return &connectionInfoStore{
		ttl:     ttl,
		entries: make(map[attribute.Distinct]activeConnectionInfo),
	}
}

func (s *connectionInfoStore) observe(attrs attribute.Set, now time.Time) {
	s.mu.Lock()
	s.entries[attrs.Equivalent()] = activeConnectionInfo{attributes: attrs, lastSeen: now}
	s.mu.Unlock()
}

func (s *connectionInfoStore) active(now time.Time) []attribute.Set {
	s.mu.Lock()
	defer s.mu.Unlock()

	active := make([]attribute.Set, 0, len(s.entries))
	for key, entry := range s.entries {
		if now.Sub(entry.lastSeen) >= s.ttl {
			delete(s.entries, key)
			continue
		}
		active = append(active, entry.attributes)
	}
	return active
}
