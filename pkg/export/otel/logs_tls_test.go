// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/plog/plogotlp"

	"go.opentelemetry.io/obi/pkg/exceptions"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

func TestExceptionLogsHTTPTLS(t *testing.T) {
	for _, tc := range []struct {
		name       string
		prefix     string
		mutualTLS  bool
		precedence bool
		omitCA     bool
		omitClient bool
	}{
		{name: "custom CA", prefix: "OTEL_EXPORTER_OTLP_LOGS"},
		{name: "untrusted server rejected", prefix: "OTEL_EXPORTER_OTLP_LOGS", omitCA: true},
		{name: "missing client certificate rejected", prefix: "OTEL_EXPORTER_OTLP_LOGS", mutualTLS: true, omitClient: true},
		{name: "common CA fallback", prefix: "OTEL_EXPORTER_OTLP"},
		{name: "mTLS", prefix: "OTEL_EXPORTER_OTLP_LOGS", mutualTLS: true},
		{name: "common mTLS fallback", prefix: "OTEL_EXPORTER_OTLP", mutualTLS: true},
		{name: "logs settings take precedence", prefix: "OTEL_EXPORTER_OTLP_LOGS", mutualTLS: true, precedence: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, prefix := range []string{"OTEL_EXPORTER_OTLP", "OTEL_EXPORTER_OTLP_LOGS"} {
				for _, suffix := range []string{"_CERTIFICATE", "_CLIENT_CERTIFICATE", "_CLIENT_KEY"} {
					t.Setenv(prefix+suffix, "")
				}
			}
			var requests atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.mutualTLS {
					if !assert.NotEmpty(t, r.TLS.VerifiedChains) {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					assert.Equal(t, "obi-test-client", r.TLS.PeerCertificates[0].Subject.CommonName)
				}
				data, err := io.ReadAll(r.Body)
				if !assert.NoError(t, err) {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				request := plogotlp.NewExportRequest()
				if !assert.NoError(t, request.UnmarshalProto(data)) {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				assert.Equal(t, 1, request.Logs().LogRecordCount())
				requests.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			if tc.mutualTLS {
				certPath, keyPath, clientCAs := logsClientCertificate(t)
				server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs, MinVersion: tls.VersionTLS12}
				if !tc.omitClient {
					t.Setenv(tc.prefix+"_CLIENT_CERTIFICATE", certPath)
					t.Setenv(tc.prefix+"_CLIENT_KEY", keyPath)
				}
			}
			server.StartTLS()
			certPath := filepath.Join(t.TempDir(), "collector.pem")
			cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			require.NoError(t, os.WriteFile(certPath, cert, 0o600))
			if !tc.omitCA {
				t.Setenv(tc.prefix+"_CERTIFICATE", certPath)
			}
			if tc.precedence {
				for _, suffix := range []string{"_CERTIFICATE", "_CLIENT_CERTIFICATE", "_CLIENT_KEY"} {
					t.Setenv("OTEL_EXPORTER_OTLP"+suffix, filepath.Join(t.TempDir(), "missing.pem"))
				}
			}

			cfg := logsTestConfig()
			cfg.Endpoint, cfg.Protocol = server.URL+"/v1/logs", otelcfg.ProtocolHTTPProtobuf
			send, closeSender, err := newTestLogsSender(t, cfg)
			require.NoError(t, err)
			defer func() { require.NoError(t, closeSender()) }()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			err = send(ctx, exceptionRecords(&global.ContextInfo{}, []exceptions.Event{exceptionFixture()}))
			if tc.omitCA || tc.omitClient {
				require.Error(t, err)
				require.Zero(t, requests.Load())
			} else {
				require.NoError(t, err)
				require.EqualValues(t, 1, requests.Load())
			}
		})
	}
}

func logsClientCertificate(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "obi-test-client"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	require.NoError(t, err)
	key, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem")
	require.NoError(t, os.WriteFile(certPath, cert, 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600))
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(cert))
	return certPath, keyPath, pool
}
