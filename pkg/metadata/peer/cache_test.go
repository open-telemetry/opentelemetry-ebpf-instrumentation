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

func TestCacheRefreshDoesNotStarvePeersUnderSustainedLoad(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RefreshInterval = time.Millisecond
	cfg.MaxConcurrent = 1
	cfg.MaxPeers = 8
	cache := newPeerCache(cfg)
	addresses := make([]netip.Addr, cfg.MaxPeers)
	for i := range addresses {
		addresses[i] = netip.AddrFrom4([4]byte{10, 1, 0, byte(i + 1)})
	}

	const requestDuration = 100 * time.Millisecond
	start := time.Unix(1, 0)
	jobs := make(chan *cachedPeer, cfg.MaxConcurrent)
	completed := make(map[netip.Addr]int)
	var active *cachedPeer
	var started time.Time

	for elapsed := time.Duration(0); elapsed <= 3*time.Duration(len(addresses))*requestDuration; elapsed += cfg.RefreshInterval {
		now := start.Add(elapsed)
		for _, address := range addresses {
			cache.lookup(address, now)
		}

		if active != nil && now.Sub(started) >= requestDuration {
			cache.complete(active, &cachedSnapshot{hostname: "remote"}, 1, started, now)
			completed[active.address]++
			active = nil
		}

		for _, peer := range cache.due(now, cap(jobs)-len(jobs)) {
			jobs <- peer
		}
		if active == nil {
			select {
			case active = <-jobs:
				started = now
			default:
			}
		}
	}

	for _, address := range addresses {
		require.GreaterOrEqual(t, completed[address], 2, "peer %s must keep receiving refreshes", address)
	}
}

func TestCacheRefreshPrioritizesDeadlineOverRecency(t *testing.T) {
	cache := newPeerCache(DefaultConfig())
	now := time.Unix(1, 0)
	a, b := netip.MustParseAddr("10.1.0.1"), netip.MustParseAddr("10.1.0.2")
	cache.lookup(a, now)
	cache.lookup(b, now.Add(time.Millisecond))
	cache.lookup(a, now.Add(2*time.Millisecond))

	due := cache.due(now.Add(2*time.Millisecond), 1)
	require.Len(t, due, 1)
	require.Equal(t, a, due[0].address)
	due = cache.due(now.Add(2*time.Millisecond), 1)
	require.Len(t, due, 1)
	require.Equal(t, b, due[0].address)
}

func TestCacheRefreshPreservesEvictionRecency(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxPeers = 2
	cache := newPeerCache(cfg)
	now := time.Unix(1, 0)
	a := netip.MustParseAddr("10.1.0.1")
	b := netip.MustParseAddr("10.1.0.2")
	c := netip.MustParseAddr("10.1.0.3")
	cache.lookup(a, now)
	cache.lookup(b, now)
	due := cache.due(now, 1)
	require.Len(t, due, 1)
	require.Equal(t, a, due[0].address)
	cache.complete(due[0], &cachedSnapshot{hostname: "remote"}, 1, now, now)
	cache.lookup(c, now)

	require.False(t, cache.peers.Contains(a))
	require.True(t, cache.peers.Contains(b))
	require.True(t, cache.peers.Contains(c))
}

func TestKnownCallersRespectCachedLifetimes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CacheTTL = 10 * time.Second
	cache := newPeerCache(cfg)
	requester := netip.MustParseAddr("10.1.0.1")
	now := time.Unix(100, 0)
	require.Empty(t, cache.knownCallers(requester, now))
	require.Zero(t, cache.peers.Len(), "serving metadata must not register peers")
	target := Endpoint{IP: "10.1.0.2", Port: 8080}
	frontend := Service{Name: "frontend"}
	for _, test := range []struct {
		name      string
		remaining time.Duration
		ambiguity time.Duration
		expect    time.Duration
	}{
		{name: "cache expiry bounds acknowledgement", remaining: time.Minute, expect: 7 * time.Second},
		{name: "caller expiry bounds acknowledgement", remaining: 8 * time.Second, expect: 3 * time.Second},
		{name: "expired caller", remaining: time.Second},
		{name: "global ambiguity", remaining: time.Minute, ambiguity: time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := indexSnapshot(&Snapshot{
				Hostname: "client-host", CallerAmbiguityMillis: test.ambiguity.Milliseconds(),
				Callers: []Caller{{Destination: target, Services: []CallerService{{Service: frontend, RemainingMillis: test.remaining.Milliseconds()}}}},
			})
			cache.lookup(requester, now)
			peer, _ := cache.peers.Peek(requester)
			cache.complete(peer, snapshot, 1, now.Add(-2*time.Second), now)
			known := cache.knownCallers(requester, now.Add(3*time.Second))
			if test.expect == 0 {
				require.Empty(t, known)
			} else {
				require.Equal(t, []Caller{{Destination: target, Services: []CallerService{{Service: frontend, RemainingMillis: test.expect.Milliseconds()}}}}, known)
			}
			require.Equal(t, now, peer.lastUsed, "serving metadata must not keep a peer active")
			require.Empty(t, cache.knownCallers(requester, now.Add(cfg.CacheTTL)))
		})
	}
}
