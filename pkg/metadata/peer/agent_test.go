// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

func TestBackgroundDiscoveryEnrichesBothDirections(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RefreshInterval = time.Hour
	remote := newStore("remote-host", cfg)
	api := Service{Name: "api", Namespace: "shop", ServiceGraph: true}
	frontend := Service{Name: "frontend", Namespace: "shop"}
	remote.setInventory([]Service{api}, []Listener{
		{Endpoint: Endpoint{IP: "0.0.0.0", Port: 8080}, Service: api},
	})
	localTarget := Endpoint{IP: "127.0.0.1", Port: 9090}
	remote.observe(localTarget, frontend, time.Now())
	remote.observe(Endpoint{IP: "10.1.0.99", Port: 9090}, Service{Name: "unrelated"}, time.Now())
	var requests atomic.Int32
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		metadataHandler(remote, cfg, testLoopbackNetwork).ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	client := newHTTPClient(cfg, nil)
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	t.Cleanup(client.CloseIdleConnections)
	network, err := makeNetwork([]netip.Addr{netip.MustParseAddr(localTarget.IP)}, []string{"10.1.0.0/16"})
	require.NoError(t, err)
	agent := &Agent{cfg: cfg, store: newStore("local-host", cfg), cache: newPeerCache(cfg), client: client, network: network}
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	jobs := make(chan *cachedPeer, cfg.MaxConcurrent)
	workers.Go(func() { agent.fetchPeers(ctx, jobs) })
	workers.Go(func() { agent.schedulePeers(ctx, jobs) })
	t.Cleanup(func() { cancel(); workers.Wait() })
	span := request.Span{Type: request.EventTypeHTTPClient, Host: "10.1.0.2", HostPort: 8080, HostName: "dns-host"}
	agent.Decorate(&span, time.Now())
	require.Equal(t, "dns-host", span.HostName)
	require.False(t, request.IgnoreServiceGraphClientCount(&span))
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("metadata request was not scheduled")
	}
	for range 1000 {
		agent.Decorate(&span, time.Now())
	}
	require.EqualValues(t, 1, requests.Load())
	require.Equal(t, "dns-host", span.HostName)
	close(release)
	require.Eventually(t, func() bool {
		agent.Decorate(&span, time.Now())
		return span.HostName == "api"
	}, 2*time.Second, 10*time.Millisecond)
	require.Equal(t, "shop", span.OtherNamespace)
	require.True(t, request.IgnoreServiceGraphClientCount(&span))
	t.Run("failed connections retain client request counts", func(t *testing.T) {
		failed := request.Span{Type: request.EventTypeFailedConnect, Host: span.Host, HostPort: span.HostPort}
		agent.Decorate(&failed, time.Now())
		require.Equal(t, "api", failed.HostName)
		require.Equal(t, "shop", failed.OtherNamespace)
		require.False(t, request.IgnoreServiceGraphClientCount(&failed), "a failed connection has no server request span to count it")
	})
	serverSpan := request.Span{Type: request.EventTypeHTTP, Peer: "10.1.0.2", Host: localTarget.IP, HostPort: localTarget.Port}
	agent.Decorate(&serverSpan, time.Now())
	require.Equal(t, "frontend", serverSpan.PeerName)
	require.Equal(t, "shop", serverSpan.OtherNamespace)
	serverSpan.HostPort = 1234
	agent.Decorate(&serverSpan, time.Now())
	require.Equal(t, "remote-host", serverSpan.PeerName)
	require.Empty(t, serverSpan.OtherNamespace)
	require.EqualValues(t, 1, requests.Load())
	unresolved := request.Span{Type: request.EventTypeHTTPClient, Host: span.Host, HostPort: 1234}
	agent.Decorate(&unresolved, time.Now())
	require.Equal(t, "remote-host", unresolved.HostName)
	require.True(t, request.IgnoreServiceGraphClientCount(&unresolved), "a hostname fallback must not create a virtual-node request count")
	expired := request.Span{Type: request.EventTypeHTTPClient, Host: span.Host, HostPort: 8080}
	agent.Decorate(&expired, time.Now().Add(cfg.CacheTTL))
	require.False(t, request.IgnoreServiceGraphClientCount(&expired), "expired metadata cannot suppress request counts")
}

func TestAgentStartupFailureAndCancellation(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer occupied.Close()
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ListenAddress = "127.0.0.1"
	cfg.Port = occupied.Addr().(*net.TCPAddr).Port
	_, err = New(t.Context(), cfg, "host", false, nil)
	require.ErrorContains(t, err, "listening for peer metadata")
	require.NoError(t, occupied.Close())
	ctx, cancel := context.WithCancel(t.Context())
	agent, err := New(ctx, cfg, "host", false, nil)
	require.NoError(t, err)
	cancel()
	// Cancellation must release a listener even if the pipeline never runs.
	require.Eventually(t, func() bool {
		listener, err := net.Listen("tcp", net.JoinHostPort(cfg.ListenAddress, strconv.Itoa(cfg.Port)))
		if err != nil {
			return false
		}
		listener.Close()
		return true
	}, time.Second, 10*time.Millisecond)
	agent.Close()
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile, cfg.TLS.KeyFile = "missing-cert", "missing-key"
	_, err = New(t.Context(), cfg, "host", false, nil)
	require.ErrorContains(t, err, "certificate")
}

func TestLocalEnrichmentAndCIDRExclusion(t *testing.T) {
	cfg := DefaultConfig()
	network, err := makeNetwork([]netip.Addr{netip.MustParseAddr("10.1.0.1")}, nil)
	require.NoError(t, err)
	agent := &Agent{cfg: cfg, store: newStore("local-host", cfg), cache: newPeerCache(cfg), network: network}
	service := Service{Name: "local-api"}
	agent.store.setInventory([]Service{service}, []Listener{
		{Endpoint: Endpoint{IP: "127.0.0.1", Port: 8080}, Service: service},
	})
	span := request.Span{Type: request.EventTypeHTTPClient, Host: "127.0.0.1", HostPort: 8080}
	agent.Decorate(&span, time.Now())
	require.Equal(t, "local-api", span.HostName)
	span.Host, span.HostName = "8.8.8.8", "existing-name"
	agent.Decorate(&span, time.Now())
	require.Equal(t, "existing-name", span.HostName)
	require.Zero(t, agent.cache.peers.Len())
}

func TestIneligibleDestinationsDoNotCauseCallerOverflow(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxCallerEntries = 1
	peers, err := makeNetwork([]netip.Addr{
		netip.MustParseAddr("10.2.0.1"), netip.MustParseAddr("fd34::1"),
	}, []string{"10.1.0.0/16", "fd12::/64"})
	require.NoError(t, err)
	frontend := Service{Name: "frontend", Namespace: "shop"}
	now := time.Now()
	for _, host := range []string{
		"10.1.0.2", "fd12::2", "::ffff:10.1.0.2",
		"10.2.0.1", "fd34::1", "::ffff:10.2.0.1", "127.0.0.1", "::1",
	} {
		t.Run(host, func(t *testing.T) {
			agent := &Agent{cfg: cfg, store: newStore("local-host", cfg), cache: newPeerCache(cfg), network: peers}
			span := request.Span{
				Type: request.EventTypeHTTPClient, Host: host, HostPort: 8080,
				Service: svc.Attrs{UID: svc.UID{Name: frontend.Name, Namespace: frontend.Namespace}},
			}
			agent.Decorate(&span, now)
			for _, excluded := range []string{"8.8.8.8", "10.3.0.1", "fd56::1", "2001:4860:4860::8888", "::ffff:8.8.4.4"} {
				span.Host = excluded
				agent.Decorate(&span, now)
			}
			target := Endpoint{IP: netip.MustParseAddr(host).Unmap().String(), Port: span.HostPort}
			snapshot := agent.store.snapshot(map[string]struct{}{target.IP: {}}, now)
			require.Equal(t, 1, agent.store.callerCount)
			require.Zero(t, snapshot.CallerAmbiguityMillis)
			require.Equal(t, frontend, agent.store.callerService(target, now))
			require.Equal(t, frontend, indexSnapshot(&snapshot).callerService(target, 0))
		})
	}
}

func TestCachedPeerHostnameFallbackDoesNotCountClientRequests(t *testing.T) {
	cfg := DefaultConfig()
	network, err := makeNetwork([]netip.Addr{netip.MustParseAddr("10.1.0.1")}, nil)
	require.NoError(t, err)
	endpoint := Endpoint{IP: "0.0.0.0", Port: 8080}
	api := Service{Name: "api", Namespace: "shop", ServiceGraph: true}
	other := Service{Name: "other", Namespace: "shop", ServiceGraph: true}
	for _, test := range []struct {
		name      string
		listeners []Listener
		failed    bool
		service   Service
		suppress  bool
	}{
		{name: "inventory not populated", service: Service{Name: "remote-host"}, suppress: true},
		{
			name: "unmatched listener", listeners: []Listener{{Endpoint: Endpoint{IP: endpoint.IP, Port: 9090}, Service: api}},
			service: Service{Name: "remote-host"}, suppress: true,
		},
		{
			name: "ambiguous listeners", listeners: []Listener{{Endpoint: endpoint, Service: api}, {Endpoint: endpoint, Service: other}},
			service: Service{Name: "remote-host"}, suppress: true,
		},
		{
			name: "matched service with metrics disabled", listeners: []Listener{{Endpoint: endpoint, Service: Service{Name: "api", Namespace: "shop"}}},
			service: Service{Name: "api", Namespace: "shop"},
		},
		{
			name: "matched service named after host", listeners: []Listener{{Endpoint: endpoint, Service: Service{Name: "remote-host"}}},
			service: Service{Name: "remote-host"},
		},
		{name: "failed connection with unmatched listener", failed: true, service: Service{Name: "remote-host"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			agent := &Agent{cfg: cfg, store: newStore("local-host", cfg), cache: newPeerCache(cfg), network: network}
			now := time.Now()
			agent.cache.lookup(netip.MustParseAddr("10.1.0.2"), now)
			due := agent.cache.due(now, 1)
			require.Len(t, due, 1)
			snapshot := indexSnapshot(&Snapshot{Hostname: "remote-host", Listeners: test.listeners})
			agent.cache.complete(due[0], snapshot, 1, now, now)
			span := request.Span{Type: request.EventTypeHTTPClient, Host: "10.1.0.2", HostPort: endpoint.Port}
			if test.failed {
				span.Type = request.EventTypeFailedConnect
			}
			agent.Decorate(&span, now)
			require.Equal(t, test.service.Name, span.HostName)
			require.Equal(t, test.service.Namespace, span.OtherNamespace)
			require.Equal(t, test.suppress, request.IgnoreServiceGraphClientCount(&span))
		})
	}
}
