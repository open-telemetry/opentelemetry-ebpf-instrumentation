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
			name:      "only IPv6 service instrumented",
			listeners: []Listener{ipv6},
			ipv4Name:  "host", ipv6Name: "ipv6",
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
				require.Equal(t, expected, store.destinationService(endpoint), "local %s", target.ip)
				require.Equal(t, expected, cached.destinationService(endpoint), "remote %s", target.ip)
			}
		})
	}
}
