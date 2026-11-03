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
)

// TestCA is a throwaway certificate authority whose PEM certificate is stored in File.
type TestCA struct {
	File string
	cert *x509.Certificate
	key  ed25519.PrivateKey
}

// NewTestCA creates a CA for the duration of the test.
func NewTestCA(t *testing.T) *TestCA {
	t.Helper()
	ca := &TestCA{}
	ca.cert, ca.key, ca.File, _ = writeCertificate(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: t.Name() + " CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, nil)
	return ca
}

// Issue writes a certificate for localhost and 127.0.0.1, signed by the CA, and returns its PEM files.
func (ca *TestCA) Issue(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	_, _, certFile, keyFile = writeCertificate(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "localhost"},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}, ca)
	return certFile, keyFile
}

func writeCertificate(t *testing.T, template *x509.Certificate, issuer *TestCA) (*x509.Certificate, ed25519.PrivateKey, string, string) {
	t.Helper()
	publicKey, key, err := ed25519.GenerateKey(rand.Reader)
	check(t, err)
	template.SerialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	check(t, err)
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(time.Hour)
	parent, signingKey := template, key
	if issuer != nil {
		parent, signingKey = issuer.cert, issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signingKey)
	check(t, err)
	cert, err := x509.ParseCertificate(der)
	check(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	check(t, err)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	check(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	check(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	return cert, key, certFile, keyFile
}

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
