// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCentralStoreAgesAndScopesCallers(t *testing.T) {
	store := newCentralStore(time.Minute, 10)
	now := time.Now()
	requester := netip.MustParseAddr("10.1.0.1")
	frontend := Service{Name: "frontend", Namespace: "shop"}
	api := Service{Name: "api", Namespace: "shop"}
	require.NoError(t, store.publish("client-host-id", []netip.Addr{netip.MustParseAddr("10.1.0.2")}, Snapshot{
		Hostname:  "client-host",
		Services:  []Service{frontend},
		Listeners: []Listener{{Endpoint: Endpoint{IP: "0.0.0.0", Port: 8080}, Service: frontend}},
		Callers: []Caller{
			{Destination: Endpoint{IP: requester.String(), Port: 9090}, Services: []CallerService{
				{Service: frontend, RemainingMillis: 30000}, {Service: api, RemainingMillis: 5000},
			}},
			{Destination: Endpoint{IP: "10.1.0.3", Port: 9090}, Services: []CallerService{{Service: frontend, RemainingMillis: 30000}}},
		},
		CallerAmbiguityMillis: 5000,
	}, now))

	snapshot, found := store.lookup(netip.MustParseAddr("10.1.0.2"), []netip.Addr{requester}, now.Add(10*time.Second))
	require.True(t, found)
	require.Equal(t, "client-host", snapshot.Hostname)
	require.Equal(t, []Service{frontend}, snapshot.Services)
	require.Len(t, snapshot.Listeners, 1)
	require.Zero(t, snapshot.CallerAmbiguityMillis)
	require.Equal(t, []Caller{{
		Destination: Endpoint{IP: requester.String(), Port: 9090},
		Services:    []CallerService{{Service: frontend, RemainingMillis: 20000}},
	}}, snapshot.Callers, "callers are aged and limited to the requester")

	snapshot, found = store.lookup(netip.MustParseAddr("10.1.0.2"), nil, now)
	require.True(t, found)
	require.Empty(t, snapshot.Callers)

	_, found = store.lookup(netip.MustParseAddr("10.1.0.9"), nil, now)
	require.False(t, found)
	_, found = store.lookup(netip.MustParseAddr("10.1.0.2"), nil, now.Add(time.Minute))
	require.False(t, found, "hosts that stop publishing are not served")
}

func TestCentralStoreAddressOwnershipAndExpiry(t *testing.T) {
	store := newCentralStore(time.Minute, 2)
	now := time.Now()
	shared, first, second := netip.MustParseAddr("10.1.0.1"), netip.MustParseAddr("10.1.0.2"), netip.MustParseAddr("10.1.0.3")
	require.NoError(t, store.publish("first", []netip.Addr{shared, first}, Snapshot{Hostname: "first"}, now))
	require.NoError(t, store.publish("second", []netip.Addr{shared, second}, Snapshot{Hostname: "second"}, now.Add(time.Second)))
	require.ErrorIs(t, store.publish("third", []netip.Addr{netip.MustParseAddr("10.1.0.4")}, Snapshot{Hostname: "third"}, now), errTooManyHosts)

	snapshot, _ := store.lookup(shared, nil, now.Add(time.Second))
	require.Equal(t, "second", snapshot.Hostname, "the latest publishing host owns a shared address")
	snapshot, _ = store.lookup(first, nil, now.Add(time.Second))
	require.Equal(t, "first", snapshot.Hostname)

	require.NoError(t, store.publish("first", []netip.Addr{first}, Snapshot{Hostname: "first"}, now.Add(2*time.Second)))
	snapshot, _ = store.lookup(shared, nil, now.Add(2*time.Second))
	require.Equal(t, "second", snapshot.Hostname, "republishing does not release addresses owned by other hosts")

	store.expire(now.Add(time.Minute + time.Second))
	require.Len(t, store.hosts, 1)
	_, found := store.lookup(shared, nil, now.Add(time.Minute+time.Second))
	require.False(t, found)
	_, found = store.lookup(first, nil, now.Add(time.Minute+time.Second))
	require.True(t, found)
	require.Equal(t, map[netip.Addr]string{first: "first"}, store.addresses)
}

func TestCentralStoreKeepsHostsSharingHostname(t *testing.T) {
	store := newCentralStore(time.Minute, 10)
	now := time.Now()
	first, second := netip.MustParseAddr("10.1.0.1"), netip.MustParseAddr("10.1.0.2")
	require.NoError(t, store.publish("first-host-id", []netip.Addr{first}, Snapshot{Hostname: "localhost"}, now))
	require.NoError(t, store.publish("second-host-id", []netip.Addr{second}, Snapshot{Hostname: "localhost"}, now))

	_, found := store.lookup(first, nil, now)
	require.True(t, found, "a host sharing its hostname with another host stays resolvable")
	_, found = store.lookup(second, nil, now)
	require.True(t, found)
	require.Len(t, store.hosts, 2)
}

func TestCentralStoreAcknowledgesKnownCallers(t *testing.T) {
	store := newCentralStore(time.Minute, 10)
	now := time.Now()
	client, server, other := netip.MustParseAddr("10.1.0.1"), netip.MustParseAddr("10.1.0.2"), netip.MustParseAddr("10.1.0.3")
	frontend := Service{Name: "frontend", Namespace: "shop"}
	destination := Endpoint{IP: server.String(), Port: 8080}
	clientSnapshot := Snapshot{Hostname: "client", Callers: []Caller{{
		Destination: destination, Services: []CallerService{{Service: frontend, RemainingMillis: 30000}},
	}}}
	require.NoError(t, store.publish("client-id", []netip.Addr{client}, clientSnapshot, now))
	require.NoError(t, store.publish("server-id", []netip.Addr{server}, Snapshot{Hostname: "server"}, now))
	require.NoError(t, store.publish("other-id", []netip.Addr{other}, Snapshot{Hostname: "other"}, now))

	snapshot, _ := store.lookup(server, []netip.Addr{client}, now)
	require.Empty(t, snapshot.KnownCallers, "the server has not looked up the client yet")

	snapshot, _ = store.lookup(client, []netip.Addr{server}, now)
	require.Len(t, snapshot.Callers, 1)

	require.NoError(t, store.publish("server-id", []netip.Addr{server}, Snapshot{Hostname: "server"}, now.Add(time.Second)))
	snapshot, _ = store.lookup(server, []netip.Addr{client}, now.Add(10*time.Second))
	require.Equal(t, []Caller{{
		Destination: destination, Services: []CallerService{{Service: frontend, RemainingMillis: 20000}},
	}}, snapshot.KnownCallers, "known callers are aged and survive republishing")

	snapshot, _ = store.lookup(server, []netip.Addr{other}, now)
	require.Empty(t, snapshot.KnownCallers, "known callers are limited to the requester")

	store.expire(now.Add(30 * time.Second))
	require.Empty(t, store.hosts["server-id"].known, "expired known callers are removed")

	clientSnapshot.CallerAmbiguityMillis = 5000
	require.NoError(t, store.publish("client-id", []netip.Addr{client}, clientSnapshot, now))
	store.lookup(client, []netip.Addr{server}, now)
	snapshot, _ = store.lookup(server, []netip.Addr{client}, now.Add(time.Second))
	require.Empty(t, snapshot.KnownCallers, "ambiguous callers are not acknowledged")
	snapshot, _ = store.lookup(server, []netip.Addr{client}, now.Add(6*time.Second))
	require.Len(t, snapshot.KnownCallers, 1)

	require.NoError(t, store.publish("client-id", []netip.Addr{client}, Snapshot{Hostname: "client"}, now))
	store.lookup(client, []netip.Addr{server}, now)
	snapshot, _ = store.lookup(server, []netip.Addr{client}, now)
	require.Empty(t, snapshot.KnownCallers, "a lookup without callers clears the acknowledgement")
}
