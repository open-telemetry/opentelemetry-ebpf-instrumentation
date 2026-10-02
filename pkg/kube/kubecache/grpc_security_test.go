// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kubecache

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"
)

func testCertificates(t *testing.T) (ca, serverCert, serverKey, clientCert, clientKey string) {
	t.Helper()
	dir := t.TempDir()
	writePEM := func(name, kind string, der []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0600))
		return path
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca = writePEM("ca.pem", "CERTIFICATE", caDER)
	caParsed, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	issue := func(name string, serial int64, usage x509.ExtKeyUsage) (string, string) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		certTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		}
		if usage == x509.ExtKeyUsageServerAuth {
			certTemplate.DNSNames = []string{"cache.test"}
		}
		certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caParsed, &key.PublicKey, caKey)
		require.NoError(t, err)
		keyDER, err := x509.MarshalECPrivateKey(key)
		require.NoError(t, err)
		return writePEM(name+".pem", "CERTIFICATE", certDER), writePEM(name+".key", "EC PRIVATE KEY", keyDER)
	}
	serverCert, serverKey = issue("server", 2, x509.ExtKeyUsageServerAuth)
	clientCert, clientKey = issue("client", 3, x509.ExtKeyUsageClientAuth)
	return
}

func TestGRPCSecurityHandshake(t *testing.T) {
	ca, serverCert, serverKey, clientCert, clientKey := testCertificates(t)
	for _, mode := range []string{"tls", "mtls"} {
		t.Run(mode, func(t *testing.T) {
			serverSecurity := GRPCSecurity{Mode: mode, CertFile: serverCert, KeyFile: serverKey}
			if mode == "mtls" {
				serverSecurity.CAFile = ca
			}
			option, err := serverSecurity.ServerOption()
			require.NoError(t, err)
			server := grpc.NewServer(option)
			grpc_health_v1.RegisterHealthServer(server, health.NewServer())
			listener := bufconn.Listen(1024 * 1024)
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(server.Stop)

			check := func(security GRPCSecurity) error {
				t.Helper()
				credentials, err := security.ClientCredentials()
				if err != nil {
					return err
				}
				conn, err := grpc.NewClient("passthrough:///cache.test:50055",
					grpc.WithTransportCredentials(credentials),
					grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
				if err != nil {
					return err
				}
				defer conn.Close()
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				_, err = grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
				return err
			}
			clientSecurity := GRPCSecurity{Mode: mode, CAFile: ca, ServerName: "cache.test"}
			if mode == "mtls" {
				clientSecurity.CertFile, clientSecurity.KeyFile = clientCert, clientKey
			}
			require.NoError(t, check(clientSecurity))
			clientSecurity.ServerName = "wrong.test"
			require.Error(t, check(clientSecurity), "wrong server name must fail")
			clientSecurity.ServerName = "cache.test"
			clientSecurity.CAFile = ""
			require.Error(t, check(clientSecurity), "untrusted server must fail")
			if mode == "mtls" {
				clientSecurity.CAFile = ca
				clientSecurity.CertFile, clientSecurity.KeyFile = "", ""
				clientSecurity.Mode = "tls"
				require.Error(t, check(clientSecurity), "server must reject missing client certificate")
				_, _, _, otherCert, otherKey := testCertificates(t)
				clientSecurity.Mode = "mtls"
				clientSecurity.CertFile, clientSecurity.KeyFile = otherCert, otherKey
				require.Error(t, check(clientSecurity), "server must reject a client signed by another CA")
			}
		})
	}
}

func TestGRPCSecurityRejectsInvalidConfiguration(t *testing.T) {
	_, err := (GRPCSecurity{Mode: "unknown"}).ClientCredentials()
	require.Error(t, err)
	_, err = (GRPCSecurity{Mode: "insecure", CAFile: "ca.pem"}).ClientCredentials()
	require.Error(t, err)
	_, err = (GRPCSecurity{Mode: "tls"}).ServerOption()
	require.Error(t, err)
	_, err = (GRPCSecurity{Mode: "mtls", CertFile: "missing", KeyFile: "missing"}).ServerOption()
	require.Error(t, err)
}

func TestLoadConfigGRPCSecurity(t *testing.T) {
	t.Run("YAML", func(t *testing.T) {
		_, cert, key, _, _ := testCertificates(t)
		cfg, err := LoadConfig(strings.NewReader("grpc:\n  security_mode: tls\n  cert_file: " + cert + "\n  key_file: " + key + "\n"))
		require.NoError(t, err)
		require.Equal(t, "tls", cfg.GRPC.Mode)
	})
	t.Run("environment", func(t *testing.T) {
		_, cert, key, _, _ := testCertificates(t)
		t.Setenv("OTEL_EBPF_K8S_CACHE_GRPC_SECURITY_MODE", "tls")
		t.Setenv("OTEL_EBPF_K8S_CACHE_GRPC_CERT_FILE", cert)
		t.Setenv("OTEL_EBPF_K8S_CACHE_GRPC_KEY_FILE", key)
		cfg, err := LoadConfig(nil)
		require.NoError(t, err)
		require.Equal(t, cert, cfg.GRPC.CertFile)
	})
	t.Run("invalid", func(t *testing.T) {
		_, err := LoadConfig(strings.NewReader("grpc:\n  security_mode: mtls\n"))
		require.Error(t, err)
	})
}
