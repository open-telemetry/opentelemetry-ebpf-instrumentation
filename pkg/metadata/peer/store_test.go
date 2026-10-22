// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCallerIdentityAndExpiry(t *testing.T) {
	cfg := DefaultConfig()
	store := newStore("client-host", cfg)
	now := time.Now()
	target := Endpoint{IP: "10.1.0.2", Port: 8080}
	frontend := Service{Name: "frontend", Namespace: "shop"}
	fallback := Service{Name: "client-host"}
	require.Equal(t, fallback, store.callerService(target, now))
	store.observe(target, frontend, now)
	store.observe(target, frontend, now.Add(time.Second))
	require.Equal(t, frontend, store.callerService(target, now))
	store.observe(target, Service{Name: "frontend", Namespace: "other"}, now)
	require.Equal(t, fallback, store.callerService(target, now))
	require.Equal(t, frontend, store.callerService(target, now.Add(cfg.CallerTTL)))
	require.Equal(t, fallback, store.callerService(target, now.Add(cfg.CallerTTL+time.Second)))
	store.expire(now.Add(cfg.CallerTTL + time.Second))
	require.Zero(t, store.callerCount)
	require.Empty(t, store.callers)
}

func TestSnapshotTargetsAndRelativeLifetimes(t *testing.T) {
	store := newStore("client-host", DefaultConfig())
	now := time.Now()
	service := Service{Name: "frontend"}
	target := Endpoint{IP: "10.1.0.2", Port: 8080}
	store.observe(target, service, now)
	store.observe(Endpoint{IP: "10.1.0.3", Port: 8080}, service, now)
	snapshot := store.snapshot(map[string]struct{}{target.IP: {}}, now.Add(10*time.Second))
	require.Len(t, snapshot.Callers, 1)
	require.Equal(t, target, snapshot.Callers[0].Destination)
	require.EqualValues(t, 50000, snapshot.Callers[0].Services[0].RemainingMillis)
	indexed := indexSnapshot(&snapshot)
	require.Equal(t, service, indexed.callerService(target, 49*time.Second))
	require.Equal(t, Service{Name: "client-host"}, indexed.callerService(target, 50*time.Second))
	require.Empty(t, store.snapshot(nil, now).Callers)
}

func TestCallerOverflowIsConservative(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxCallerEntries = 1
	store := newStore("client-host", cfg)
	now := time.Now()
	target := Endpoint{IP: "10.1.0.2", Port: 8080}
	store.observe(target, Service{Name: "one"}, now)
	store.observe(target, Service{Name: "two"}, now)
	require.Equal(t, Service{Name: "client-host"}, store.callerService(target, now))
	snapshot := store.snapshot(map[string]struct{}{target.IP: {}}, now)
	require.Equal(t, Service{Name: "client-host"}, indexSnapshot(&snapshot).callerService(target, 0))
	require.Equal(t, 1, store.callerCount)
}

func TestListenerIdentity(t *testing.T) {
	store := newStore("server-host", DefaultConfig())
	service := Service{Name: "api", Namespace: "shop"}
	target := Endpoint{IP: "10.1.0.2", Port: 8080}
	store.setInventory([]Service{service}, []Listener{
		{Endpoint: target, Service: service},
		{Endpoint: Endpoint{IP: "0.0.0.0", Port: 8080}, Service: service},
	})
	resolved, matched := store.destinationService(target)
	require.True(t, matched)
	require.Equal(t, service, resolved)
	snapshot := store.snapshot(nil, time.Now())
	resolved, matched = indexSnapshot(&snapshot).destinationService(target)
	require.True(t, matched)
	require.Equal(t, service, resolved)
	store.setInventory(nil, []Listener{
		{Endpoint: target, Service: service},
		{Endpoint: target, Service: Service{Name: "api", Namespace: "other"}},
	})
	resolved, matched = store.destinationService(target)
	require.False(t, matched)
	require.Equal(t, Service{Name: "server-host"}, resolved)
	resolved, matched = store.destinationService(Endpoint{IP: target.IP, Port: 9090})
	require.False(t, matched)
	require.Equal(t, Service{Name: "server-host"}, resolved)
}

func TestIPv6DoesNotMatchIPv4Wildcard(t *testing.T) {
	store := newStore("host", DefaultConfig())
	service := Service{Name: "ipv4-api"}
	store.setInventory(nil, []Listener{
		{Endpoint: Endpoint{IP: "0.0.0.0", Port: 8080}, Service: service},
	})
	resolved, matched := store.destinationService(Endpoint{IP: "fd12::2", Port: 8080})
	require.False(t, matched)
	require.Equal(t, Service{Name: "host"}, resolved)
}
