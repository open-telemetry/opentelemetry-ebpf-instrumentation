// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/testutil"
)

func TestHTTPSCertificateVerification(t *testing.T) {
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
		{name: "no custom CA", wantError: "authority"},
		{name: "unrelated CA", caFile: otherRoot.CertFile, wantError: "authority"},
		{name: "wrong server name", caFile: root.CertFile, serverName: "wrong.example", wantError: "hostname"},
		{name: "DNS certificate queried by IP", caFile: root.CertFile, dnsOnly: true, wantError: "hostname"},
		{name: "explicit server name", caFile: root.CertFile, dnsOnly: true, serverName: "peer.example"},
		{name: "expired certificate", caFile: root.CertFile, expired: true, wantError: "expired"},
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
			serverTLS, clientTLS, err := tlsConfigs(cfg.TLS)
			require.NoError(t, err)
			store := newStore("remote-host", cfg)
			service := Service{Name: "api", Namespace: "shop"}
			store.setInventory([]Service{service}, nil)
			var requests atomic.Int32
			handler := metadataHandler(store, cfg, testLoopbackNetwork, nil)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				handler.ServeHTTP(w, r)
			}))
			server.TLS = serverTLS
			server.StartTLS()
			t.Cleanup(server.Close)
			cfg.Port = server.Listener.Addr().(*net.TCPAddr).Port
			client := newHTTPClient(cfg, clientTLS)
			t.Cleanup(client.CloseIdleConnections)
			snapshot, _, err := fetchSnapshot(t.Context(), client, cfg, netip.MustParseAddr("127.0.0.1"))
			switch test.wantError {
			case "authority":
				var unknownAuthority x509.UnknownAuthorityError
				require.ErrorAs(t, err, &unknownAuthority)
			case "hostname":
				var hostnameError x509.HostnameError
				require.ErrorAs(t, err, &hostnameError)
			case "expired":
				var invalidCertificate x509.CertificateInvalidError
				require.ErrorAs(t, err, &invalidCertificate)
				require.Equal(t, x509.Expired, invalidCertificate.Reason)
			default:
				require.NoError(t, err)
				require.Equal(t, "remote-host", snapshot.Hostname)
				require.Equal(t, []Service{service}, snapshot.Services)
			}
			if test.wantError != "" {
				require.Zero(t, requests.Load(), "certificate verification must fail before sending the HTTP request and bearer token")
			} else {
				require.EqualValues(t, 1, requests.Load())
			}
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

func TestTLSDisabledIgnoresCertificateFiles(t *testing.T) {
	server, client, err := tlsConfigs(MetadataTLSConfig{CertFile: "missing", KeyFile: "missing", CAFile: "missing"})
	require.NoError(t, err)
	require.Nil(t, server)
	require.Nil(t, client)
}

func TestHTTPSBearerToken(t *testing.T) {
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
			serverTLS, clientTLS, err := tlsConfigs(cfg.TLS)
			require.NoError(t, err)
			server := httptest.NewUnstartedServer(metadataHandler(newStore("remote-host", cfg), cfg, testLoopbackNetwork, nil))
			server.TLS = serverTLS
			server.StartTLS()
			t.Cleanup(server.Close)
			cfg.Port = server.Listener.Addr().(*net.TCPAddr).Port
			cfg.Token = test.clientToken
			client := newHTTPClient(cfg, clientTLS)
			t.Cleanup(client.CloseIdleConnections)
			snapshot, _, err := fetchSnapshot(t.Context(), client, cfg, netip.MustParseAddr("127.0.0.1"))
			if test.unauthorized {
				require.ErrorContains(t, err, "HTTP 401")
				require.Nil(t, snapshot)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "remote-host", snapshot.Hostname)
		})
	}
}
