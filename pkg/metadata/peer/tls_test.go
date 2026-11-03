// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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
)

type testCertificate struct {
	certificate *x509.Certificate
	key         ed25519.PrivateKey
	certFile    string
	keyFile     string
}

func newTestCertificate(t *testing.T, template *x509.Certificate, issuer *testCertificate) testCertificate {
	t.Helper()
	publicKey, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	template.SerialNumber = serial
	parent, signingKey := template, key
	if issuer != nil {
		parent, signingKey = issuer.certificate, issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signingKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	return testCertificate{certificate: certificate, key: key, certFile: certFile, keyFile: keyFile}
}

func newTestCA(t *testing.T, issuer *testCertificate) testCertificate {
	t.Helper()
	return newTestCertificate(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: t.Name()},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, issuer)
}

func TestTLSCertificateVerification(t *testing.T) {
	root := newTestCA(t, nil)
	otherRoot := newTestCA(t, nil)
	intermediate := newTestCA(t, &root)
	for _, test := range []struct {
		name         string
		caFile       string
		serverName   string
		dnsOnly      bool
		expired      bool
		intermediate bool
		wantError    string
	}{
		{name: "trusted CA and IP SAN", caFile: root.certFile},
		{name: "trusted intermediate chain", caFile: root.certFile, intermediate: true},
		// System verifiers report untrusted certificates differently, e.g. macOS rejects ed25519 keys first.
		{name: "no custom CA", wantError: "tls: failed to verify certificate"},
		{name: "unrelated CA", caFile: otherRoot.certFile, wantError: "certificate signed by unknown authority"},
		{name: "wrong server name", caFile: root.certFile, serverName: "wrong.example", wantError: "certificate is valid for peer.example, not wrong.example"},
		{name: "DNS certificate queried by IP", caFile: root.certFile, dnsOnly: true, wantError: "doesn't contain any IP SANs"},
		{name: "explicit server name", caFile: root.certFile, dnsOnly: true, serverName: "peer.example"},
		{name: "expired certificate", caFile: root.certFile, expired: true, wantError: "certificate has expired"},
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
			leaf := newTestCertificate(t, template, issuer)
			if test.intermediate {
				chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.certificate.Raw})
				chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediate.certificate.Raw})...)
				require.NoError(t, os.WriteFile(leaf.certFile, chain, 0o600))
			}
			cfg := DefaultConfig()
			cfg.Token = "shared-secret"
			cfg.TLS = MetadataTLSConfig{Enabled: true, CertFile: leaf.certFile, KeyFile: leaf.keyFile, CAFile: test.caFile, ServerName: test.serverName}
			serverTLS, clientTLS, err := tlsConfigs(cfg.TLS)
			require.NoError(t, err)
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
	certificate := newTestCA(t, nil)
	other := newTestCA(t, nil)
	invalidFile := filepath.Join(t.TempDir(), "invalid.pem")
	require.NoError(t, os.WriteFile(invalidFile, []byte("not a PEM certificate"), 0o600))
	missingFile := filepath.Join(t.TempDir(), "missing.pem")
	for _, test := range []struct {
		name, certFile, keyFile, caFile, wantError string
	}{
		{"missing certificate", missingFile, certificate.keyFile, "", "loading peer metadata certificate"},
		{"invalid certificate", invalidFile, certificate.keyFile, "", "loading peer metadata certificate"},
		{"missing key", certificate.certFile, missingFile, "", "loading peer metadata certificate"},
		{"invalid key", certificate.certFile, invalidFile, "", "loading peer metadata certificate"},
		{"mismatched key", certificate.certFile, other.keyFile, "", "loading peer metadata certificate"},
		{"missing CA", certificate.certFile, certificate.keyFile, missingFile, "loading peer metadata CA"},
		{"invalid CA", certificate.certFile, certificate.keyFile, invalidFile, "ca_file contains no certificates"},
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

func TestTLSDisabledIgnoresCertificateFiles(t *testing.T) {
	server, client, err := tlsConfigs(MetadataTLSConfig{CertFile: "missing", KeyFile: "missing", CAFile: "missing"})
	require.NoError(t, err)
	require.Nil(t, server)
	require.Nil(t, client)
}

func TestTLSBearerToken(t *testing.T) {
	root := newTestCA(t, nil)
	leaf := newTestCertificate(t, &x509.Certificate{
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
			cfg.TLS = MetadataTLSConfig{Enabled: true, CertFile: leaf.certFile, KeyFile: leaf.keyFile, CAFile: root.certFile}
			serverTLS, clientTLS, err := tlsConfigs(cfg.TLS)
			require.NoError(t, err)
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
