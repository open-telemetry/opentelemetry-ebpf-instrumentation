// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCacheCoalescesRefreshAndExpiresFailures(t *testing.T) {
	cfg := DefaultConfig()
	cache := newPeerCache(cfg)
	ip := netip.MustParseAddr("10.1.0.2")
	now := time.Now()
	for range 100 {
		snapshot, _ := cache.lookup(ip, now)
		require.Nil(t, snapshot)
	}
	due := cache.due(now, 8)
	require.Len(t, due, 1)
	require.Empty(t, cache.due(now, 8))
	snapshot := &cachedSnapshot{hostname: "remote"}
	cache.complete(due[0], snapshot, 100, now, now.Add(time.Second))
	got, fetchedAt := cache.lookup(ip, now.Add(2*time.Second))
	require.Same(t, snapshot, got)
	require.Equal(t, now, fetchedAt)
	require.Empty(t, cache.due(now.Add(2*time.Second), 8))
	due = cache.due(now.Add(15*time.Second), 8)
	require.Len(t, due, 1)
	cache.complete(due[0], nil, 0, now, now.Add(15*time.Second))
	got, _ = cache.lookup(ip, now.Add(20*time.Second))
	require.Same(t, snapshot, got)
	got, _ = cache.lookup(ip, now.Add(61*time.Second))
	require.Nil(t, got)
	require.Equal(t, 1, due[0].failures)
	require.Greater(t, due[0].nextFetch.Sub(now.Add(15*time.Second)), cfg.RefreshInterval)
}

func TestCacheEvictionAndLateResponses(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxPeers = 1
	cache := newPeerCache(cfg)
	now := time.Now()
	a, b := netip.MustParseAddr("10.1.0.2"), netip.MustParseAddr("10.1.0.3")
	cache.lookup(a, now)
	old := cache.due(now, 1)[0]
	cache.lookup(b, now)
	cache.lookup(a, now)
	cache.complete(old, &cachedSnapshot{hostname: "stale"}, 100, now, now)
	got, _ := cache.lookup(a, now)
	require.Nil(t, got)
	require.Zero(t, cache.bytes)
	cache.due(now.Add(cfg.CacheTTL), 1)
	require.Zero(t, cache.peers.Len())
}

func TestCacheByteBudget(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxCacheBytes = 150
	cache := newPeerCache(cfg)
	now := time.Now()
	for _, value := range []string{"10.1.0.2", "10.1.0.3"} {
		ip := netip.MustParseAddr(value)
		cache.lookup(ip, now)
		peer := cache.due(now, 1)[0]
		cache.complete(peer, &cachedSnapshot{hostname: "remote"}, 100, now, now)
	}
	require.Equal(t, 100, cache.bytes)
	require.Equal(t, 1, cache.peers.Len())
}
