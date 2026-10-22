// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestListenerAddressFamilies(t *testing.T) {
	ipv4 := Listener{Endpoint: Endpoint{IP: "0.0.0.0", Port: 8080}, Service: Service{Name: "ipv4"}}
	ipv6 := Listener{Endpoint: Endpoint{IP: "::", Port: 8080}, Service: Service{Name: "ipv6"}}
	for _, test := range []struct {
		name      string
		listeners []Listener
		ipv4Name  string
		ipv6Name  string
	}{
		{
			name:      "separate IPv4 and IPv6-only services",
			listeners: []Listener{ipv4, ipv6},
			ipv4Name:  "ipv4", ipv6Name: "ipv6",
		},
		{
			name:      "dual-stack wildcard service",
			listeners: []Listener{ipv6},
			ipv4Name:  "ipv6", ipv6Name: "ipv6",
		},
		{
			name: "specific IPv4 listener takes precedence over IPv6 wildcard",
			listeners: []Listener{
				{Endpoint: Endpoint{IP: "10.1.0.2", Port: 8080}, Service: Service{Name: "ipv4"}},
				ipv6,
			},
			ipv4Name: "ipv4", ipv6Name: "ipv6",
		},
		{
			name: "ambiguous IPv6 wildcard services",
			listeners: []Listener{
				ipv6,
				{Endpoint: ipv6.Endpoint, Service: Service{Name: "other"}},
			},
			ipv4Name: "host", ipv6Name: "host",
		},
		{
			name:      "only IPv4 service instrumented",
			listeners: []Listener{ipv4},
			ipv4Name:  "ipv4", ipv6Name: "host",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newStore("host", DefaultConfig())
			store.setInventory(nil, test.listeners)
			snapshot := store.snapshot(nil, time.Now())
			cached := indexSnapshot(&snapshot)
			for _, target := range []struct{ ip, service string }{
				{ip: "10.1.0.2", service: test.ipv4Name},
				{ip: "fd12::2", service: test.ipv6Name},
			} {
				endpoint := Endpoint{IP: target.ip, Port: 8080}
				expected := Service{Name: target.service}
				local, localMatch := store.destinationService(endpoint)
				remote, remoteMatch := cached.destinationService(endpoint)
				require.Equal(t, expected, local, "local %s", target.ip)
				require.Equal(t, expected, remote, "remote %s", target.ip)
				require.Equal(t, target.service != "host", localMatch)
				require.Equal(t, localMatch, remoteMatch)
			}
		})
	}
}

func TestListenerGraphParticipationRequiresAllMatchingProcesses(t *testing.T) {
	endpoint := Endpoint{IP: "10.1.0.2", Port: 8080}
	participating := Service{Name: "api", Namespace: "shop", ServiceGraph: true}
	tracesOnly := Service{Name: "api", Namespace: "shop"}
	for _, services := range [][]Service{
		{participating, tracesOnly}, {tracesOnly, participating},
	} {
		listeners := []Listener{
			{Endpoint: Endpoint{IP: "0.0.0.0", Port: endpoint.Port}, Service: services[0]},
			{Endpoint: endpoint, Service: services[1]},
		}
		snapshot := indexSnapshot(&Snapshot{Hostname: "host", Listeners: listeners})
		service, matched := snapshot.destinationService(endpoint)
		require.True(t, matched)
		require.Equal(t, tracesOnly, service, "graph settings do not change the service identity")
	}
}

func TestKnownCallersRequireUniqueIdentity(t *testing.T) {
	target := Endpoint{IP: "10.1.0.2", Port: 8080}
	frontend := Service{Name: "frontend", Namespace: "shop"}
	snapshot := indexSnapshot(&Snapshot{KnownCallers: []Caller{{Destination: target, Services: []CallerService{
		{Service: frontend, RemainingMillis: 1000},
		{Service: Service{Name: frontend.Name, Namespace: "other"}, RemainingMillis: 500},
	}}}})
	require.False(t, snapshot.knowsCaller(target, frontend, 0), "ambiguous callers cannot take over the client count")
	require.True(t, snapshot.knowsCaller(target, frontend, 500*time.Millisecond))
	require.False(t, snapshot.knowsCaller(target, frontend, time.Second))
}
