// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kubecache

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"go.opentelemetry.io/obi/pkg/internal/testutil"
)

func TestTLSHandshake(t *testing.T) {
	ca := testutil.NewTestCA(t, nil)
	serverCert := testutil.NewLocalhostCertificate(t, &ca)
	clientCert := testutil.NewLocalhostCertificate(t, &ca)
	other := testutil.NewTestCA(t, nil)
	untrustedCert := testutil.NewLocalhostCertificate(t, &other)

	serverTLS := TLSConfig{CertFile: serverCert.CertFile, KeyFile: serverCert.KeyFile}
	serverMTLS := TLSConfig{CertFile: serverCert.CertFile, KeyFile: serverCert.KeyFile, ClientCAFile: ca.CertFile}

	tests := []struct {
		name    string
		server  TLSConfig
		client  ClientTLSConfig
		wantErr bool
	}{
		{name: "plaintext", server: TLSConfig{}, client: ClientTLSConfig{}},
		{name: "tls", server: serverTLS, client: ClientTLSConfig{CAFile: ca.CertFile}},
		{name: "tls with untrusted server", server: serverTLS, client: ClientTLSConfig{CAFile: other.CertFile}, wantErr: true},
		{name: "plaintext client to tls server", server: serverTLS, client: ClientTLSConfig{}, wantErr: true},
		{
			name:   "mtls",
			server: serverMTLS,
			client: ClientTLSConfig{CAFile: ca.CertFile, CertFile: clientCert.CertFile, KeyFile: clientCert.KeyFile},
		},
		{name: "mtls without client certificate", server: serverMTLS, client: ClientTLSConfig{CAFile: ca.CertFile}, wantErr: true},
		{
			name:    "mtls with untrusted client certificate",
			server:  serverMTLS,
			client:  ClientTLSConfig{CAFile: ca.CertFile, CertFile: untrustedCert.CertFile, KeyFile: untrustedCert.KeyFile},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			serverCreds, err := tc.server.Credentials()
			require.NoError(t, err)
			server := grpc.NewServer(grpc.Creds(serverCreds))
			healthpb.RegisterHealthServer(server, health.NewServer())
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(server.Stop)

			clientCreds, err := tc.client.Credentials()
			require.NoError(t, err)
			conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(clientCreds))
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })

			_, err = healthpb.NewHealthClient(conn).Check(t.Context(), &healthpb.HealthCheckRequest{})
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTLSConfigValidate(t *testing.T) {
	require.NoError(t, TLSConfig{}.Validate())
	require.NoError(t, TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"}.Validate())
	require.NoError(t, TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem", ClientCAFile: "ca.pem"}.Validate())
	require.Error(t, TLSConfig{CertFile: "cert.pem"}.Validate())
	require.Error(t, TLSConfig{KeyFile: "key.pem"}.Validate())
	require.Error(t, TLSConfig{ClientCAFile: "ca.pem"}.Validate())

	require.NoError(t, ClientTLSConfig{}.Validate())
	require.NoError(t, ClientTLSConfig{CAFile: "ca.pem"}.Validate())
	require.NoError(t, ClientTLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"}.Validate())
	require.Error(t, ClientTLSConfig{CertFile: "cert.pem"}.Validate())
	require.Error(t, ClientTLSConfig{KeyFile: "key.pem"}.Validate())
}

func TestTLSCredentialsInvalidFiles(t *testing.T) {
	ca := testutil.NewTestCA(t, nil)
	certFile, keyFile := ca.CertFile, ca.KeyFile

	_, err := TLSConfig{CertFile: "missing.pem", KeyFile: keyFile}.Credentials()
	require.Error(t, err)
	_, err = TLSConfig{CertFile: certFile, KeyFile: keyFile, ClientCAFile: keyFile}.Credentials()
	require.ErrorContains(t, err, "contains no certificates")
	_, err = ClientTLSConfig{CAFile: "missing.pem"}.Credentials()
	require.Error(t, err)
	_, err = ClientTLSConfig{CertFile: certFile, KeyFile: "missing.pem"}.Credentials()
	require.Error(t, err)

	_, err = TLSConfig{}.Credentials()
	require.NoError(t, err, "no files means plaintext")
}
