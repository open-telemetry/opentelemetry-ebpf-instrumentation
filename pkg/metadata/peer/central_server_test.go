// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"context"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/metadata/peer/metadatapb"
)

func startCentralServer(t *testing.T, cfg *CentralServerConfig, options ...grpc.DialOption) metadatapb.MetadataServiceClient {
	t.Helper()
	server, err := NewCentralServer(cfg)
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() { cancel(); require.NoError(t, <-done) })

	if len(options) == 0 {
		options = []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	}
	conn, err := grpc.NewClient(listener.Addr().String(), options...)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return metadatapb.NewMetadataServiceClient(conn)
}

func TestCentralServerPublishAndLookup(t *testing.T) {
	cfg := DefaultCentralServerConfig()
	cfg.PeerCIDRs = []string{"10.1.0.0/16"}
	client := startCentralServer(t, &cfg)

	agentCfg := DefaultConfig()
	server := newStore("server-host", agentCfg)
	server.graphEnabled = true
	backend := Service{Name: "backend", Namespace: "shop", ServiceGraph: true}
	server.setInventory([]Service{backend}, []Listener{{Endpoint: Endpoint{IP: "0.0.0.0", Port: 8080}, Service: backend}})
	clientIP, serverIP := "10.1.0.1", "10.1.0.2"
	server.observe(Endpoint{IP: clientIP, Port: 9090}, backend, time.Now())
	published := server.snapshot(map[string]struct{}{clientIP: {}}, time.Now())

	_, err := client.Publish(t.Context(), &metadatapb.PublishRequest{HostId: "server-host-id", Addresses: []string{serverIP}, Snapshot: snapshotToProto(&published)})
	require.NoError(t, err)

	response, err := client.Lookup(t.Context(), &metadatapb.LookupRequest{Address: serverIP, RequesterAddresses: []string{clientIP}})
	require.NoError(t, err)
	snapshot := snapshotFromProto(response.GetSnapshot())
	require.NoError(t, validateSnapshot(&snapshot, agentCfg.CallerTTL))
	indexed := indexSnapshot(&snapshot)
	service, match := indexed.destinationService(Endpoint{IP: serverIP, Port: 8080})
	require.Equal(t, listenerUnique, match)
	require.Equal(t, backend, service)
	require.Equal(t, backend, indexed.callerService(Endpoint{IP: clientIP, Port: 9090}, 0))
	require.Equal(t, published.MetricProtocols, snapshot.MetricProtocols)

	response, err = client.Lookup(t.Context(), &metadatapb.LookupRequest{Address: "10.1.0.9"})
	require.NoError(t, err)
	require.Nil(t, response.GetSnapshot(), "unknown hosts return no snapshot")
}

func TestCentralServerRejectsInvalidRequests(t *testing.T) {
	cfg := DefaultCentralServerConfig()
	cfg.PeerCIDRs = []string{"10.1.0.0/16"}
	client := startCentralServer(t, &cfg)
	valid := &metadatapb.Snapshot{Hostname: "host"}

	for _, test := range []struct {
		name    string
		request *metadatapb.PublishRequest
	}{
		{name: "missing host ID", request: &metadatapb.PublishRequest{Addresses: []string{"10.1.0.1"}, Snapshot: valid}},
		{name: "no addresses", request: &metadatapb.PublishRequest{HostId: "host-id", Snapshot: valid}},
		{name: "invalid address", request: &metadatapb.PublishRequest{HostId: "host-id", Addresses: []string{"invalid"}, Snapshot: valid}},
		{name: "address outside peer CIDRs", request: &metadatapb.PublishRequest{HostId: "host-id", Addresses: []string{"10.2.0.1"}, Snapshot: valid}},
		{name: "missing hostname", request: &metadatapb.PublishRequest{HostId: "host-id", Addresses: []string{"10.1.0.1"}}},
		{name: "invalid listener", request: &metadatapb.PublishRequest{HostId: "host-id", Addresses: []string{"10.1.0.1"}, Snapshot: &metadatapb.Snapshot{
			Hostname:  "host",
			Listeners: []*metadatapb.Listener{{Endpoint: &metadatapb.Endpoint{Ip: "10.1.0.1"}, Service: &metadatapb.Service{Name: "api"}}},
		}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := client.Publish(t.Context(), test.request)
			require.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}

	_, err := client.Lookup(t.Context(), &metadatapb.LookupRequest{Address: "invalid"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestCentralServerBearerToken(t *testing.T) {
	root := newTestCA(t, nil)
	leaf := newTestCertificate(t, &x509.Certificate{
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &root)
	cfg := DefaultCentralServerConfig()
	cfg.Token = "shared-secret"
	cfg.TLS = MetadataTLSConfig{Enabled: true, CertFile: leaf.certFile, KeyFile: leaf.keyFile, CAFile: root.certFile}
	_, clientTLS, err := tlsConfigs(cfg.TLS)
	require.NoError(t, err)
	client := startCentralServer(t, &cfg, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))

	for _, test := range []struct {
		name, token string
		code        codes.Code
	}{
		{name: "valid token", token: "shared-secret", code: codes.OK},
		{name: "missing token", code: codes.Unauthenticated},
		{name: "wrong token", token: "wrong-secret", code: codes.Unauthenticated},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()
			if test.token != "" {
				ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+test.token)
			}
			_, err := client.Lookup(ctx, &metadatapb.LookupRequest{Address: "10.1.0.1"})
			require.Equal(t, test.code, status.Code(err))
		})
	}
}

func TestCentralServerConfigValidation(t *testing.T) {
	cfg := DefaultCentralServerConfig()
	require.NoError(t, cfg.Validate())
	cfg.Token = "secret"
	require.ErrorContains(t, cfg.Validate(), "token requires TLS")
	cfg = DefaultCentralServerConfig()
	cfg.PeerCIDRs = []string{"invalid"}
	require.ErrorContains(t, cfg.Validate(), "peer_cidrs")
	cfg = DefaultCentralServerConfig()
	cfg.MaxHosts = 0
	require.Error(t, cfg.Validate())
}

func TestSnapshotProtoRoundTrip(t *testing.T) {
	protocols := instrumentations.NewInstrumentationSelection([]instrumentations.Instrumentation{instrumentations.InstrumentationGRPC})
	snapshot := Snapshot{
		Version:   ProtocolVersion,
		Hostname:  "host",
		Services:  []Service{{Name: "api", Namespace: "shop", ServiceGraph: true}},
		Listeners: []Listener{{Endpoint: Endpoint{IP: "0.0.0.0", Port: 8080}, Service: Service{Name: "api"}}},
		Callers: []Caller{{
			Destination: Endpoint{IP: "10.1.0.2", Port: 9090},
			Services:    []CallerService{{Service: Service{Name: "api"}, RemainingMillis: 1000}},
		}},
		KnownCallers: []Caller{{
			Destination: Endpoint{IP: "10.1.0.3", Port: 9090},
			Services:    []CallerService{{Service: Service{Name: "web"}, RemainingMillis: 2000}},
		}},
		MetricProtocols:       &protocols,
		CallerAmbiguityMillis: 3000,
	}
	require.Equal(t, snapshot, snapshotFromProto(snapshotToProto(&snapshot)))
}
