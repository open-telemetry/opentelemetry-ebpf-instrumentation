// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package testutil // import "go.opentelemetry.io/obi/pkg/internal/testutil"

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestCertificate is a certificate and its private key, also written as PEM files.
type TestCertificate struct {
	Certificate *x509.Certificate
	Key         ed25519.PrivateKey
	CertFile    string
	KeyFile     string
}

// NewTestCertificate signs template with issuer, or self-signs it when issuer is nil.
func NewTestCertificate(t *testing.T, template *x509.Certificate, issuer *TestCertificate) TestCertificate {
	t.Helper()
	publicKey, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	template.SerialNumber = serial
	parent, signingKey := template, key
	if issuer != nil {
		parent, signingKey = issuer.Certificate, issuer.Key
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
	return TestCertificate{Certificate: certificate, Key: key, CertFile: certFile, KeyFile: keyFile}
}

// NewTestCA creates a CA certificate, signed by issuer or self-signed when issuer is nil.
func NewTestCA(t *testing.T, issuer *TestCertificate) TestCertificate {
	t.Helper()
	return NewTestCertificate(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: t.Name()},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, issuer)
}

// NewLocalhostCertificate creates a server and client certificate for localhost and 127.0.0.1.
func NewLocalhostCertificate(t *testing.T, issuer *TestCertificate) TestCertificate {
	t.Helper()
	return NewTestCertificate(t, &x509.Certificate{
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}, issuer)
}
