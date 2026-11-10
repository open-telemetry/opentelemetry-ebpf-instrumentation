// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAutomaticPrivateBlocks(t *testing.T) {
	addresses := []netip.Addr{netip.MustParseAddr("10.1.0.1"), netip.MustParseAddr("fd12::1")}
	network, err := makeNetwork(addresses, nil)
	require.NoError(t, err)
	for _, value := range []string{"10.200.0.1", "fcff::1"} {
		require.True(t, network.permits(netip.MustParseAddr(value)))
	}
	for _, value := range []string{"172.16.0.1", "192.168.0.1", "8.8.8.8", "fe80::1", "224.0.0.1", "0.0.0.0"} {
		require.False(t, network.permits(netip.MustParseAddr(value)), value)
	}
	require.True(t, network.isLocal(addresses[0]))
	require.True(t, network.isLocal(netip.MustParseAddr("127.0.0.1")))
}

func TestExplicitCIDRsReplaceAutomaticBlocks(t *testing.T) {
	network, err := makeNetwork([]netip.Addr{netip.MustParseAddr("10.1.0.1")}, []string{"192.168.4.0/24"})
	require.NoError(t, err)
	require.False(t, network.permits(netip.MustParseAddr("10.1.0.2")))
	require.True(t, network.permits(netip.MustParseAddr("192.168.4.10")))
	require.False(t, network.permits(netip.MustParseAddr("192.168.5.10")))
	_, err = makeNetwork(nil, []string{"invalid"})
	require.Error(t, err)
}
