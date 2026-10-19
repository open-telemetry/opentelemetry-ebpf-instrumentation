// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"
)

type cachedPeer struct {
	address   netip.Addr
	lastUsed  time.Time
	lastGood  time.Time
	nextFetch time.Time
	fetchedAt time.Time
	fetching  bool
	failures  int
	size      int
	snapshot  *cachedSnapshot
}

type peerCache struct {
	mu    sync.Mutex
	cfg   Config
	peers *simplelru.LRU[netip.Addr, *cachedPeer]
	bytes int
	wake  chan struct{}
}

func newPeerCache(cfg Config) *peerCache {
	c := &peerCache{
		cfg:  cfg,
		wake: make(chan struct{}, 1),
	}

	c.peers, _ = simplelru.NewLRU(cfg.MaxPeers, func(_ netip.Addr, peer *cachedPeer) {
		c.bytes -= peer.size
	})

	return c
}

// lookup tracks peer activity, schedules newly seen peers, and returns metadata if it is within its TTL.
func (c *peerCache) lookup(address netip.Addr, now time.Time) (*cachedSnapshot, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	peer, exists := c.peers.Get(address)
	if !exists {
		peer = &cachedPeer{address: address}
		c.peers.Add(address, peer)
		c.notify()
	}

	// reject stale metadata
	peer.lastUsed = now
	if peer.snapshot == nil || now.Sub(peer.lastGood) >= c.cfg.CacheTTL {
		return nil, time.Time{}
	}

	return peer.snapshot, peer.fetchedAt
}

func (c *peerCache) notify() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// due removes inactive peers and reserves up to limit peers for fetching when their refresh is due.
func (c *peerCache) due(now time.Time, limit int) []*cachedPeer {
	c.mu.Lock()
	defer c.mu.Unlock()

	var due []*cachedPeer
	for _, address := range c.peers.Keys() {
		peer, _ := c.peers.Peek(address)
		if now.Sub(peer.lastUsed) >= c.cfg.CacheTTL {
			c.peers.Remove(address)
			continue
		}

		if len(due) >= limit || peer.fetching || now.Before(peer.nextFetch) {
			continue
		}

		peer.fetching = true
		due = append(due, peer)
	}

	return due
}

// complete records a fetch result, schedules the next attempt, and enforces the cache byte budget.
func (c *peerCache) complete(peer *cachedPeer, snapshot *cachedSnapshot, size int, started, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	current, exists := c.peers.Peek(peer.address)
	if !exists || current != peer {
		return
	}

	peer.fetching = false

	if snapshot == nil {
		peer.failures = min(peer.failures+1, 16)
		peer.nextFetch = now.Add(jitter(backoff(c.cfg.RefreshInterval, peer.failures)))
		c.notify()
		return
	}

	c.bytes -= peer.size
	peer.snapshot, peer.size = snapshot, size
	peer.lastGood, peer.fetchedAt = now, started
	peer.failures = 0
	peer.nextFetch = now.Add(jitter(c.cfg.RefreshInterval))
	c.bytes += size

	for c.bytes > c.cfg.MaxCacheBytes {
		c.peers.RemoveOldest()
	}

	c.notify()
}

func jitter(interval time.Duration) time.Duration {
	return time.Duration(float64(interval) * (0.9 + rand.Float64()*0.2))
}

// backoff doubles the retry interval per failure, capped at the greater of one minute and the base interval.
func backoff(interval time.Duration, failures int) time.Duration {
	limit := max(time.Minute, interval)

	for range failures {
		if interval >= limit/2 {
			return limit
		}
		interval *= 2
	}

	return min(interval, limit)
}
