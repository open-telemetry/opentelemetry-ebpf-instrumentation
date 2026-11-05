// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	grpcpeer "google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"go.opentelemetry.io/obi/pkg/metadata/peer/metadatapb"
)

var testLoopbackNetwork = network{allowed: []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"),
}}

var loopback = netip.MustParseAddr("127.0.0.1")

func newTestExchange(cfg MetadataConfig, store *localStore, peers network) *peerExchange {
	return &peerExchange{cfg: cfg, store: store, network: peers, cache: newPeerCache(cfg)}
}

// requestFrom returns a context for a request received from the remote address.
func requestFrom(ctx context.Context, remote string) context.Context {
	var addr net.Addr = &net.UnixAddr{Name: remote, Net: "unix"}
	if address, err := netip.ParseAddrPort(remote); err == nil {
		addr = net.TCPAddrFromAddrPort(address)
	}
	return grpcpeer.NewContext(ctx, &grpcpeer.Peer{Addr: addr})
}

func getSnapshot(t *testing.T, exchange *peerExchange, remote string) (Snapshot, int, error) {
	t.Helper()
	message, err := exchange.GetSnapshot(requestFrom(t.Context(), remote), &metadatapb.GetSnapshotRequest{})
	if err != nil {
		return Snapshot{}, 0, err
	}
	return snapshotFromProto(message), proto.Size(message), nil
}

// startPeerServer serves the metadata service on a loopback port and returns the port.
func startPeerServer(t *testing.T, cfg *MetadataConfig, service metadatapb.PeerMetadataServiceServer,
	serverTLS *tls.Config, options ...grpc.ServerOption,
) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer(append(peerServerOptions(cfg, serverTLS), options...)...)
	metadatapb.RegisterPeerMetadataServiceServer(server, service)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return listener.Addr().(*net.TCPAddr).Port
}

func fetchFromLoopback(t *testing.T, cfg *MetadataConfig, clientTLS *tls.Config) (*Snapshot, int, error) {
	t.Helper()
	clients := newPeerClients(cfg, clientTLS)
	t.Cleanup(clients.close)
	client, err := clients.get(loopback)
	require.NoError(t, err)
	return fetchSnapshot(t.Context(), client, cfg)
}

type stubPeerServer struct {
	metadatapb.UnimplementedPeerMetadataServiceServer
	snapshot *metadatapb.Snapshot
	err      error
}

func (s *stubPeerServer) GetSnapshot(context.Context, *metadatapb.GetSnapshotRequest) (*metadatapb.Snapshot, error) {
	return s.snapshot, s.err
}

func TestGetSnapshot(t *testing.T) {
	cfg := DefaultConfig()
	peers, err := makeNetwork(nil, []string{"10.1.0.0/16"})
	require.NoError(t, err)
	store := newStore("host", cfg)
	api, idle := Service{Name: "api"}, Service{Name: "idle"}
	store.setInventory([]Service{api, idle}, []Listener{
		{Endpoint: Endpoint{IP: "0.0.0.0", Port: 8080}, Service: api},
	})
	store.observe(Endpoint{IP: "10.1.0.2", Port: 9090}, api, time.Now())
	snapshot, _, err := getSnapshot(t, newTestExchange(cfg, store, peers), "10.1.0.2:1234")
	require.NoError(t, err)
	require.Equal(t, "host", snapshot.Hostname)
	require.ElementsMatch(t, []Service{api, idle}, snapshot.Services)
	require.Len(t, snapshot.Listeners, 1)
	require.Len(t, snapshot.Callers, 1)
}

func TestSnapshotValidation(t *testing.T) {
	snapshot := Snapshot{Hostname: "host", Callers: []Caller{
		{Destination: Endpoint{IP: "::ffff:10.1.0.2", Port: 8080}, Services: []CallerService{
			{Service: Service{Name: "api"}, RemainingMillis: 120000},
		}},
	}}
	require.NoError(t, validateSnapshot(&snapshot, time.Minute))
	require.Equal(t, "10.1.0.2", snapshot.Callers[0].Destination.IP)
	require.EqualValues(t, 60000, snapshot.Callers[0].Services[0].RemainingMillis)
	snapshot.Callers[0].Services[0].RemainingMillis = -1
	require.Error(t, validateSnapshot(&snapshot, time.Minute))
	snapshot.Callers = nil
	snapshot.Hostname = ""
	require.Error(t, validateSnapshot(&snapshot, time.Minute))
}

func TestSnapshotValidatesKnownCallers(t *testing.T) {
	snapshot := Snapshot{Hostname: "host", KnownCallers: []Caller{
		{Destination: Endpoint{IP: "::ffff:10.1.0.2", Port: 8080}, Services: []CallerService{
			{Service: Service{Name: "frontend"}, RemainingMillis: 120000},
		}},
	}}
	require.NoError(t, validateSnapshot(&snapshot, time.Minute))
	require.Equal(t, "10.1.0.2", snapshot.KnownCallers[0].Destination.IP)
	require.EqualValues(t, 60000, snapshot.KnownCallers[0].Services[0].RemainingMillis)
	snapshot.KnownCallers[0].Services[0].RemainingMillis = -1
	require.Error(t, validateSnapshot(&snapshot, time.Minute))
}

func TestFetchFailuresAndResponseLimits(t *testing.T) {
	valid := &metadatapb.Snapshot{Hostname: "host", Services: []*metadatapb.Service{{Name: "api"}}}
	for _, test := range []struct {
		name               string
		server             *stubPeerServer
		serverMax, client  int
		code               codes.Code
		closedPort, failed bool
	}{
		{name: "invalid snapshot", server: &stubPeerServer{snapshot: &metadatapb.Snapshot{}}, failed: true},
		{name: "server error", server: &stubPeerServer{err: status.Error(codes.Unavailable, "unavailable")}, code: codes.Unavailable},
		{name: "response over the server limit", server: &stubPeerServer{snapshot: valid}, serverMax: 5, code: codes.ResourceExhausted},
		{name: "response over the client limit", server: &stubPeerServer{snapshot: valid}, client: 5, code: codes.ResourceExhausted},
		{name: "no agent listening", closedPort: true, code: codes.Unavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultConfig()
			if test.serverMax != 0 {
				cfg.MaxResponseBytes = test.serverMax
			}
			if test.closedPort {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				cfg.Port = listener.Addr().(*net.TCPAddr).Port
				require.NoError(t, listener.Close())
			} else {
				cfg.Port = startPeerServer(t, &cfg, test.server, nil)
			}
			if test.client != 0 {
				cfg.MaxResponseBytes = test.client
			}
			snapshot, _, err := fetchFromLoopback(t, &cfg, nil)
			require.Error(t, err)
			require.Nil(t, snapshot)
			if !test.failed {
				require.Equal(t, test.code, status.Code(err))
			}
		})
	}
}

func TestBearerTokenAuthorization(t *testing.T) {
	for _, test := range []struct {
		name, token, authorization string
		authorized                 bool
	}{
		{"valid token", "shared-secret", "Bearer shared-secret", true},
		{"missing header", "shared-secret", "", false},
		{"empty token", "shared-secret", "Bearer ", false},
		{"wrong token", "shared-secret", "Bearer different-secret", false},
		{"truncated token", "shared-secret", "Bearer shared", false},
		{"missing scheme", "shared-secret", "shared-secret", false},
		{"wrong scheme", "shared-secret", "Basic shared-secret", false},
		{"authentication disabled", "", "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			if test.authorization != "" {
				ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", test.authorization))
			}
			response, err := bearerTokenInterceptor(test.token)(ctx, nil, nil, func(context.Context, any) (any, error) {
				return "host", nil
			})
			if test.authorized {
				require.NoError(t, err)
				require.Equal(t, "host", response)
				return
			}
			require.Equal(t, codes.Unauthenticated, status.Code(err))
			require.Nil(t, response)
			require.NotContains(t, err.Error(), test.token)
		})
	}
}

func TestGetSnapshotRestrictsRequesterCIDRs(t *testing.T) {
	for _, test := range []struct {
		name      string
		remote    string
		automatic bool
		permitted bool
	}{
		{name: "allowed IPv4", remote: "10.1.0.2:1234", permitted: true},
		{name: "outside IPv4 CIDR", remote: "10.2.0.2:1234"},
		{name: "IPv4-mapped IPv6", remote: "[::ffff:10.1.0.2]:1234", permitted: true},
		{name: "allowed IPv6", remote: "[fd12::2]:1234", permitted: true},
		{name: "outside IPv6 CIDR", remote: "[fd13::2]:1234"},
		{name: "loopback excluded by explicit CIDRs", remote: "127.0.0.1:1234"},
		{name: "malformed source", remote: "invalid"},
		{name: "automatic private block", remote: "10.200.0.2:1234", automatic: true, permitted: true},
		{name: "outside automatic private blocks", remote: "172.16.0.2:1234", automatic: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.PeerCIDRs = []string{"10.1.0.0/16", "fd12::/64"}
			if test.automatic {
				cfg.PeerCIDRs = nil
			}
			peers, err := makeNetwork([]netip.Addr{netip.MustParseAddr("10.1.0.1"), netip.MustParseAddr("fd12::1")}, cfg.PeerCIDRs)
			require.NoError(t, err)
			store := newStore("private-host", cfg)
			store.setInventory([]Service{{Name: "private-api"}}, nil)
			snapshot, _, err := getSnapshot(t, newTestExchange(cfg, store, peers), test.remote)
			if test.permitted {
				require.NoError(t, err)
				require.Equal(t, "private-host", snapshot.Hostname)
				return
			}
			require.Equal(t, codes.PermissionDenied, status.Code(err))
			require.NotContains(t, err.Error(), "private-host")
			require.NotContains(t, err.Error(), "private-api")
		})
	}
}

func TestGetSnapshotScopesCallersToRequester(t *testing.T) {
	cfg := DefaultConfig()
	peers, err := makeNetwork(nil, []string{"10.1.0.0/16", "fd12::/64"})
	require.NoError(t, err)
	store := newStore("host", cfg)
	for _, ip := range []string{"10.1.0.2", "10.1.0.3", "fd12::2", "fd12::3"} {
		store.observe(Endpoint{IP: ip, Port: 8080}, Service{Name: "caller"}, time.Now())
	}
	exchange := newTestExchange(cfg, store, peers)
	for _, remote := range []string{"10.1.0.2:1234", "[::ffff:10.1.0.2]:1234", "[fd12::2]:1234"} {
		t.Run(remote, func(t *testing.T) {
			snapshot, _, err := getSnapshot(t, exchange, remote)
			require.NoError(t, err)
			require.Len(t, snapshot.Callers, 1)
			expected := netip.MustParseAddrPort(remote).Addr().Unmap().String()
			require.Equal(t, expected, snapshot.Callers[0].Destination.IP)
		})
	}
}

func TestFetchSnapshotScopesCallersToSourceAddress(t *testing.T) {
	cfg := DefaultConfig()
	store := newStore("host", cfg)
	self := Endpoint{IP: loopback.String(), Port: 8080}
	store.observe(self, Service{Name: "caller"}, time.Now())
	store.observe(Endpoint{IP: "10.1.0.2", Port: 8080}, Service{Name: "unrelated"}, time.Now())
	cfg.Port = startPeerServer(t, &cfg, newTestExchange(cfg, store, testLoopbackNetwork), nil)
	snapshot, size, err := fetchFromLoopback(t, &cfg, nil)
	require.NoError(t, err)
	require.Positive(t, size)
	require.Len(t, snapshot.Callers, 1)
	require.Equal(t, self, snapshot.Callers[0].Destination)
}

func TestKnownCallersAreScopedToRequester(t *testing.T) {
	cfg := DefaultConfig()
	peers, err := makeNetwork(nil, []string{"10.1.0.0/16"})
	require.NoError(t, err)
	exchange := newTestExchange(cfg, newStore("server-host", cfg), peers)
	target := Endpoint{IP: "10.1.0.2", Port: 8080}
	now := time.Now()
	for _, caller := range []struct{ ip, name string }{
		{ip: "10.1.0.1", name: "frontend"}, {ip: "10.1.0.3", name: "other"},
	} {
		address := netip.MustParseAddr(caller.ip)
		snapshot := indexSnapshot(&Snapshot{Hostname: "host", Callers: []Caller{{
			Destination: target,
			Services:    []CallerService{{Service: Service{Name: caller.name}, RemainingMillis: cfg.CallerTTL.Milliseconds()}},
		}}})
		exchange.cache.lookup(address, now)
		exchange.cache.complete(exchange.cache.due(now, 1)[0], snapshot, 1, now, now)
	}
	before := exchange.cache.peers.Keys()
	for _, test := range []struct{ source, caller string }{
		{source: "10.1.0.1", caller: "frontend"}, {source: "10.1.0.3", caller: "other"}, {source: "10.1.0.4"},
	} {
		snapshot, _, err := getSnapshot(t, exchange, net.JoinHostPort(test.source, "1234"))
		require.NoError(t, err)
		if test.caller == "" {
			require.Empty(t, snapshot.KnownCallers)
			continue
		}
		require.Len(t, snapshot.KnownCallers, 1)
		require.Equal(t, target, snapshot.KnownCallers[0].Destination)
		require.Len(t, snapshot.KnownCallers[0].Services, 1)
		require.Equal(t, test.caller, snapshot.KnownCallers[0].Services[0].Service.Name)
	}
	require.Equal(t, before, exchange.cache.peers.Keys(), "metadata requests must not register peers or alter eviction order")
}

func TestPeerClientsCloseEvictedConnections(t *testing.T) {
	cfg := DefaultConfig()
	clients := newPeerClients(&cfg, nil)
	t.Cleanup(clients.close)
	kept, evicted := netip.MustParseAddr("10.1.0.1"), netip.MustParseAddr("10.1.0.2")
	for _, address := range []netip.Addr{kept, evicted, kept} {
		_, err := clients.get(address)
		require.NoError(t, err)
	}
	require.Len(t, clients.conns, 2, "connections are reused per address")
	clients.retain(func(address netip.Addr) bool { return address == kept })
	require.Len(t, clients.conns, 1)
	require.Contains(t, clients.conns, kept)
}

func TestPeerClientsRejectRequestsAfterClose(t *testing.T) {
	cfg := DefaultConfig()
	clients := newPeerClients(&cfg, nil)
	_, err := clients.get(netip.MustParseAddr("10.1.0.1"))
	require.NoError(t, err)

	clients.close()
	_, err = clients.get(netip.MustParseAddr("10.1.0.2"))
	require.ErrorIs(t, err, errPeerClientsClosed)
	require.Empty(t, clients.conns)
}

func TestIncompleteRequestTimesOut(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequestTimeout = 50 * time.Millisecond
	cfg.Port = startPeerServer(t, &cfg, &stubPeerServer{snapshot: &metadatapb.Snapshot{Hostname: "peer"}}, nil)

	conn, err := grpc.NewClient(net.JoinHostPort(loopback.String(), strconv.Itoa(cfg.Port)),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// Open the call without a client deadline and never send the request message.
	stream, err := conn.NewStream(t.Context(), &grpc.StreamDesc{}, metadatapb.PeerMetadataService_GetSnapshot_FullMethodName)
	require.NoError(t, err)

	err = stream.RecvMsg(&metadatapb.Snapshot{})
	require.Equal(t, codes.DeadlineExceeded, status.Code(err), "unexpected error: %v", err)
}
