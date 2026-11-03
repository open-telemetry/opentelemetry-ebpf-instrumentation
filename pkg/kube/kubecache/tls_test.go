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
	ca := testutil.NewTestCA(t)
	serverCert, serverKey := ca.Issue(t)
	clientCert, clientKey := ca.Issue(t)
	other := testutil.NewTestCA(t)
	otherCert, otherKey := other.Issue(t)

	serverTLS := TLSConfig{Enabled: true, CertFile: serverCert, KeyFile: serverKey}
	serverMTLS := TLSConfig{Enabled: true, CertFile: serverCert, KeyFile: serverKey, ClientCAFile: ca.File}

	tests := []struct {
		name    string
		server  TLSConfig
		client  ClientTLSConfig
		wantErr bool
	}{
		{name: "plaintext", server: TLSConfig{}, client: ClientTLSConfig{}},
		{name: "tls", server: serverTLS, client: ClientTLSConfig{Enabled: true, CAFile: ca.File}},
		{name: "tls with untrusted server", server: serverTLS, client: ClientTLSConfig{Enabled: true, CAFile: other.File}, wantErr: true},
		{name: "plaintext client to tls server", server: serverTLS, client: ClientTLSConfig{}, wantErr: true},
		{
			name:   "mtls",
			server: serverMTLS,
			client: ClientTLSConfig{Enabled: true, CAFile: ca.File, CertFile: clientCert, KeyFile: clientKey},
		},
		{name: "mtls without client certificate", server: serverMTLS, client: ClientTLSConfig{Enabled: true, CAFile: ca.File}, wantErr: true},
		{
			name:    "mtls with untrusted client certificate",
			server:  serverMTLS,
			client:  ClientTLSConfig{Enabled: true, CAFile: ca.File, CertFile: otherCert, KeyFile: otherKey},
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
	require.NoError(t, TLSConfig{CertFile: "ignored"}.Validate())
	require.NoError(t, TLSConfig{Enabled: true, CertFile: "cert.pem", KeyFile: "key.pem"}.Validate())
	require.Error(t, TLSConfig{Enabled: true}.Validate())
	require.Error(t, TLSConfig{Enabled: true, CertFile: "cert.pem"}.Validate())

	require.NoError(t, ClientTLSConfig{Enabled: true}.Validate())
	require.NoError(t, ClientTLSConfig{Enabled: true, CertFile: "cert.pem", KeyFile: "key.pem"}.Validate())
	require.Error(t, ClientTLSConfig{Enabled: true, CertFile: "cert.pem"}.Validate())
	require.Error(t, ClientTLSConfig{Enabled: true, KeyFile: "key.pem"}.Validate())
}

func TestTLSCredentialsInvalidFiles(t *testing.T) {
	ca := testutil.NewTestCA(t)
	certFile, keyFile := ca.Issue(t)

	_, err := TLSConfig{Enabled: true, CertFile: "missing.pem", KeyFile: keyFile}.Credentials()
	require.Error(t, err)
	_, err = TLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile, ClientCAFile: keyFile}.Credentials()
	require.ErrorContains(t, err, "contains no certificates")
	_, err = ClientTLSConfig{Enabled: true, CAFile: "missing.pem"}.Credentials()
	require.Error(t, err)
	_, err = ClientTLSConfig{Enabled: true, CertFile: certFile, KeyFile: "missing.pem"}.Credentials()
	require.Error(t, err)

	_, err = TLSConfig{CertFile: "missing.pem"}.Credentials()
	require.NoError(t, err, "files are ignored while TLS is disabled")
}
