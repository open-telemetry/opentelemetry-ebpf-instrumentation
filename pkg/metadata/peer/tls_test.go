// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.opentelemetry.io/obi/pkg/internal/testutil"
)

func TestTLSCertificateVerification(t *testing.T) {
	root := testutil.NewTestCA(t, nil)
	otherRoot := testutil.NewTestCA(t, nil)
	intermediate := testutil.NewTestCA(t, &root)
	for _, test := range []struct {
		name         string
		caFile       string
		serverName   string
		dnsOnly      bool
		expired      bool
		intermediate bool
		wantError    string
	}{
		{name: "trusted CA and IP SAN", caFile: root.CertFile},
		{name: "trusted intermediate chain", caFile: root.CertFile, intermediate: true},
		// System verifiers report untrusted certificates differently, e.g. macOS rejects ed25519 keys first.
		{name: "no custom CA", wantError: "tls: failed to verify certificate"},
		{name: "unrelated CA", caFile: otherRoot.CertFile, wantError: "certificate signed by unknown authority"},
		{name: "wrong server name", caFile: root.CertFile, serverName: "wrong.example", wantError: "certificate is valid for peer.example, not wrong.example"},
		{name: "DNS certificate queried by IP", caFile: root.CertFile, dnsOnly: true, wantError: "doesn't contain any IP SANs"},
		{name: "explicit server name", caFile: root.CertFile, dnsOnly: true, serverName: "peer.example"},
		{name: "expired certificate", caFile: root.CertFile, expired: true, wantError: "certificate has expired"},
	} {
		t.Run(test.name, func(t *testing.T) {
			template := &x509.Certificate{
				DNSNames:    []string{"peer.example"},
				NotBefore:   time.Now().Add(-2 * time.Hour),
				NotAfter:    time.Now().Add(time.Hour),
				KeyUsage:    x509.KeyUsageDigitalSignature,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			if !test.dnsOnly {
				template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			}
			if test.expired {
				template.NotAfter = time.Now().Add(-time.Hour)
			}
			issuer := &root
			if test.intermediate {
				issuer = &intermediate
			}
			leaf := testutil.NewTestCertificate(t, template, issuer)
			if test.intermediate {
				chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate.Raw})
				chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediate.Certificate.Raw})...)
				require.NoError(t, os.WriteFile(leaf.CertFile, chain, 0o600))
			}
			cfg := DefaultConfig()
			cfg.Token = "shared-secret"
			cfg.TLS = MetadataTLSConfig{Enabled: true, CertFile: leaf.CertFile, KeyFile: leaf.KeyFile, CAFile: test.caFile, ServerName: test.serverName}
			serverTLS, clientTLS := testTLSConfigs(t, cfg.TLS)
			store := newStore("remote-host", cfg)
			service := Service{Name: "api", Namespace: "shop"}
			store.setInventory([]Service{service}, nil)
			var requests atomic.Int32
			countRequests := func(ctx context.Context, request any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
				requests.Add(1)
				return handler(ctx, request)
			}
			cfg.Port = startPeerServer(t, &cfg, newTestExchange(cfg, store, testLoopbackNetwork), serverTLS,
				grpc.ChainUnaryInterceptor(countRequests))
			snapshot, _, err := fetchFromLoopback(t, &cfg, clientTLS)
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
				require.Zero(t, requests.Load(), "certificate verification must fail before sending the request and bearer token")
				return
			}
			require.NoError(t, err)
			require.Equal(t, "remote-host", snapshot.Hostname)
			require.Equal(t, []Service{service}, snapshot.Services)
			require.EqualValues(t, 1, requests.Load())
		})
	}
}

func TestTLSInvalidFiles(t *testing.T) {
	certificate := testutil.NewTestCA(t, nil)
	other := testutil.NewTestCA(t, nil)
	invalidFile := filepath.Join(t.TempDir(), "invalid.pem")
	require.NoError(t, os.WriteFile(invalidFile, []byte("not a PEM certificate"), 0o600))
	missingFile := filepath.Join(t.TempDir(), "missing.pem")
	for _, test := range []struct {
		name, certFile, keyFile, caFile, wantError string
	}{
		{"missing certificate", missingFile, certificate.KeyFile, "", "loading peer metadata certificate"},
		{"invalid certificate", invalidFile, certificate.KeyFile, "", "loading peer metadata certificate"},
		{"missing key", certificate.CertFile, missingFile, "", "loading peer metadata certificate"},
		{"invalid key", certificate.CertFile, invalidFile, "", "loading peer metadata certificate"},
		{"mismatched key", certificate.CertFile, other.KeyFile, "", "loading peer metadata certificate"},
		{"missing CA", certificate.CertFile, certificate.KeyFile, missingFile, "loading peer metadata CA"},
		{"invalid CA", certificate.CertFile, certificate.KeyFile, invalidFile, "ca_file contains no certificates"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Enabled = true
			cfg.TLS = MetadataTLSConfig{Enabled: true, CertFile: test.certFile, KeyFile: test.keyFile, CAFile: test.caFile}
			_, err := New(t.Context(), cfg, "host", false, nil, nil)
			require.ErrorContains(t, err, test.wantError)
		})
	}
}

func testTLSConfigs(t *testing.T, cfg MetadataTLSConfig) (server, client *tls.Config) {
	t.Helper()
	server, err := serverTLSConfig(cfg)
	require.NoError(t, err)
	client, err = clientTLSConfig(cfg)
	require.NoError(t, err)
	return server, client
}

func TestTLSDisabledIgnoresCertificateFiles(t *testing.T) {
	server, client := testTLSConfigs(t, MetadataTLSConfig{CertFile: "missing", KeyFile: "missing", CAFile: "missing"})
	require.Nil(t, server)
	require.Nil(t, client)
}

func TestClientTLSDoesNotRequireCertificate(t *testing.T) {
	root := testutil.NewTestCA(t, nil)
	client, err := clientTLSConfig(MetadataTLSConfig{Enabled: true, CAFile: root.CertFile, ServerName: "metadata"})
	require.NoError(t, err)
	require.Empty(t, client.Certificates)
	require.NotNil(t, client.RootCAs)
	require.Equal(t, "metadata", client.ServerName)
}

func TestTLSBearerToken(t *testing.T) {
	root := testutil.NewTestCA(t, nil)
	leaf := testutil.NewTestCertificate(t, &x509.Certificate{
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &root)
	for _, test := range []struct {
		name, serverToken, clientToken string
		unauthorized                   bool
	}{
		{name: "valid token", serverToken: "shared-secret", clientToken: "shared-secret"},
		{name: "missing token", serverToken: "shared-secret", unauthorized: true},
		{name: "wrong token", serverToken: "shared-secret", clientToken: "wrong-secret", unauthorized: true},
		{name: "authentication disabled"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Token = test.serverToken
			cfg.TLS = MetadataTLSConfig{Enabled: true, CertFile: leaf.CertFile, KeyFile: leaf.KeyFile, CAFile: root.CertFile}
			serverTLS, clientTLS := testTLSConfigs(t, cfg.TLS)
			cfg.Port = startPeerServer(t, &cfg, newTestExchange(cfg, newStore("remote-host", cfg), testLoopbackNetwork), serverTLS)
			cfg.Token = test.clientToken
			snapshot, _, err := fetchFromLoopback(t, &cfg, clientTLS)
			if test.unauthorized {
				require.Equal(t, codes.Unauthenticated, status.Code(err))
				require.Nil(t, snapshot)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "remote-host", snapshot.Hostname)
		})
	}
}
