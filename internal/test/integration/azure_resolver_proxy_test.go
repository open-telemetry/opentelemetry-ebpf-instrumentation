// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/ory/dockertest/v4"
	"github.com/stretchr/testify/require"
)

// azureARMProxy tunnels the SDK's original HTTPS requests to a local ARM mock.
// A temporary trusted certificate keeps TLS verification enabled in the OBI container.
func azureARMProxy(t *testing.T, network dockertest.Network, handler http.Handler) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Azure integration mock"}, DNSNames: []string{"management.azure.com"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(pathOutput, 0o755))
	certFile, err := os.CreateTemp(pathOutput, "azure-ca-*.pem")
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
	require.NoError(t, certFile.Close())
	t.Cleanup(func() { require.NoError(t, os.Remove(certFile.Name())) })
	mock := httptest.NewUnstartedServer(handler)
	mock.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	mock.StartTLS()
	t.Cleanup(mock.Close)
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != "management.azure.com:443" {
			http.Error(w, "unexpected proxy destination", http.StatusForbidden)
			return
		}
		upstream, err := net.DialTimeout("tcp", mock.Listener.Addr().String(), time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		conn, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err = buffer.Flush(); err != nil {
			return
		}
		done := make(chan struct{})
		go func() { defer close(done); _, _ = io.Copy(upstream, buffer); _ = upstream.Close() }()
		_, _ = io.Copy(conn, upstream)
		_ = conn.Close()
		<-done
	}))
	require.NoError(t, proxy.Listener.Close())
	proxy.Listener, err = net.Listen("tcp", "0.0.0.0:0")
	require.NoError(t, err)
	proxy.Start()
	t.Cleanup(proxy.Close)
	require.NotEmpty(t, network.Inspect().IPAM.Config)
	gatewayIP := network.Inspect().IPAM.Config[0].Gateway
	require.True(t, gatewayIP.IsValid(), "Docker IMDS network must have a gateway for the ARM proxy")
	gateway := gatewayIP.String()
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		gateway = "host.docker.internal"
	}
	return "http://" + net.JoinHostPort(gateway, strconv.Itoa(proxy.Listener.Addr().(*net.TCPAddr).Port)), "/coverage/" + filepath.Base(certFile.Name())
}
