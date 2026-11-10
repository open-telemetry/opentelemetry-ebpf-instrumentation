// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"context"
	"crypto/x509"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func centralAgentConfig(address string) MetadataConfig {
	cfg := DefaultConfig()
	cfg.Mode = ModeCentral
	cfg.Central.Address = address
	cfg.RefreshInterval = 50 * time.Millisecond
	return cfg
}

func newTestCentralExchange(t *testing.T, cfg MetadataConfig, hostID string, store *localStore, local string) *centralExchange {
	t.Helper()
	network, err := makeNetwork([]netip.Addr{netip.MustParseAddr(local)}, []string{"10.1.0.0/16"})
	require.NoError(t, err)
	exchange, err := newCentralExchange(cfg, hostID, store, network)
	require.NoError(t, err)
	t.Cleanup(exchange.close)
	return exchange
}

func runExchange(t *testing.T, exchange exchange) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); exchange.run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
}

// eventualLookup registers interest in the address and waits until its metadata is fetched.
func eventualLookup(t *testing.T, exchange exchange, address string) *cachedSnapshot {
	t.Helper()
	var snapshot *cachedSnapshot
	require.Eventually(t, func() bool {
		snapshot, _ = exchange.lookup(netip.MustParseAddr(address), time.Now())
		return snapshot != nil
	}, 5*time.Second, 10*time.Millisecond)
	return snapshot
}

func TestCentralExchangeEnrichesBothDirections(t *testing.T) {
	serverCfg := DefaultCentralServerConfig()
	serverCfg.PeerCIDRs = []string{"10.1.0.0/16"}
	cfg := centralAgentConfig(serveCentralServer(t, &serverCfg))

	clientIP, serverIP := "10.1.0.1", "10.1.0.2"
	backend := Service{Name: "backend", Namespace: "shop", ServiceGraph: true}
	frontend := Service{Name: "frontend", Namespace: "shop"}
	destination := Endpoint{IP: serverIP, Port: 8080}

	serverStore := newStore("server-host", cfg)
	serverStore.setInventory([]Service{backend}, []Listener{{Endpoint: Endpoint{IP: "0.0.0.0", Port: 8080}, Service: backend}})
	clientStore := newStore("client-host", cfg)
	clientStore.observe(destination, frontend, time.Now())

	server := newTestCentralExchange(t, cfg, "server-id", serverStore, serverIP)
	client := newTestCentralExchange(t, cfg, "client-id", clientStore, clientIP)
	runExchange(t, server)
	runExchange(t, client)

	service, match := eventualLookup(t, client, serverIP).destinationService(destination)
	require.Equal(t, listenerUnique, match)
	require.Equal(t, backend, service)

	require.Equal(t, frontend, eventualLookup(t, server, clientIP).callerService(destination, 0))

	require.Eventually(t, func() bool {
		snapshot, fetchedAt := client.lookup(netip.MustParseAddr(serverIP), time.Now())
		return snapshot.knowsCaller(destination, frontend, time.Since(fetchedAt))
	}, 5*time.Second, 10*time.Millisecond, "the server acknowledges the callers it looked up")
}

func TestCentralExchangeBacksOffUnpublishedHosts(t *testing.T) {
	serverCfg := DefaultCentralServerConfig()
	serverCfg.PeerCIDRs = []string{"10.1.0.0/16"}
	cfg := centralAgentConfig(serveCentralServer(t, &serverCfg))
	exchange := newTestCentralExchange(t, cfg, "client-id", newStore("client-host", cfg), "10.1.0.1")
	runExchange(t, exchange)

	unknown := netip.MustParseAddr("10.1.0.9")
	snapshot, _ := exchange.lookup(unknown, time.Now())
	require.Nil(t, snapshot)
	require.Eventually(t, func() bool {
		exchange.cache.mu.Lock()
		defer exchange.cache.mu.Unlock()
		peer, ok := exchange.cache.peers.Peek(unknown)
		return ok && peer.failures > 0
	}, 5*time.Second, 10*time.Millisecond)

	_, _, err := exchange.fetch(t.Context(), unknown)
	require.ErrorIs(t, err, errHostNotPublished)
}

func TestCentralExchangeTLSWithoutClientCertificate(t *testing.T) {
	root := newTestCA(t, nil)
	leaf := newTestCertificate(t, &x509.Certificate{
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &root)
	serverCfg := DefaultCentralServerConfig()
	serverCfg.PeerCIDRs = []string{"10.1.0.0/16"}
	serverCfg.Token = "shared-secret"
	serverCfg.TLS = MetadataTLSConfig{Enabled: true, CertFile: leaf.certFile, KeyFile: leaf.keyFile}
	address := serveCentralServer(t, &serverCfg)

	for _, test := range []struct {
		name, token string
		code        codes.Code
	}{
		{name: "valid token", token: "shared-secret", code: codes.OK},
		{name: "wrong token", token: "wrong-secret", code: codes.Unauthenticated},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := centralAgentConfig(address)
			cfg.Enabled = true
			cfg.Token = test.token
			cfg.TLS = MetadataTLSConfig{Enabled: true, CAFile: root.certFile}
			require.NoError(t, cfg.Validate(), "central mode does not require a client certificate")
			exchange := newTestCentralExchange(t, cfg, "client-id", newStore("client-host", cfg), "10.1.0.1")
			require.Equal(t, test.code, status.Code(exchange.publish(t.Context())))
		})
	}
}

func TestCentralExchangeRequiresHostID(t *testing.T) {
	cfg := centralAgentConfig("127.0.0.1:8999")
	_, err := newCentralExchange(cfg, "", newStore("host", cfg), network{})
	require.ErrorContains(t, err, "requires a host ID")
}

func TestPublishedAddresses(t *testing.T) {
	network, err := makeNetwork([]netip.Addr{
		netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("10.1.0.1"), netip.MustParseAddr("192.168.1.1"),
	}, []string{"10.1.0.0/16"})
	require.NoError(t, err)
	require.Equal(t, []string{"10.1.0.1"}, publishedAddresses(network))
}
