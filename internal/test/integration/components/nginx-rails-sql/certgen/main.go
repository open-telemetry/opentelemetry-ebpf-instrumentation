// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	keyBits              = 2048
	certificateBackdate  = time.Hour
	certificateLifetime  = 10 * 365 * 24 * time.Hour
	mysqlServerOutputDir = "/out/mysql-server"
	mysqlClientOutputDir = "/out/mysql-client"
	nginxOutputDir       = "/out/nginx"
	mysqlUserID          = 999
	mysqlGroupID         = 999
	privateKeyFileMode   = 0o600
	certificateFileMode  = 0o644
)

type certificateAuthority struct {
	certificate *x509.Certificate
	privateKey  *rsa.PrivateKey
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "generate test certificates: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if err := os.MkdirAll(mysqlServerOutputDir, 0o755); err != nil {
		return fmt.Errorf("create mysql server output directory: %w", err)
	}

	if err := os.MkdirAll(mysqlClientOutputDir, 0o755); err != nil {
		return fmt.Errorf("create mysql client output directory: %w", err)
	}

	if err := os.MkdirAll(nginxOutputDir, 0o755); err != nil {
		return fmt.Errorf("create nginx output directory: %w", err)
	}

	mysqlCA, err := newCertificateAuthority("obi mysql test ca")
	if err != nil {
		return err
	}

	if err := writeCertificateAuthority(mysqlServerOutputDir, "ca", mysqlCA); err != nil {
		return err
	}

	if err := writeCertificateAuthority(mysqlClientOutputDir, "ca", mysqlCA); err != nil {
		return err
	}

	if err := writeSignedLeaf(mysqlServerOutputDir, "server", mysqlCA, []string{"db", "mysql_db", "localhost"}, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, mysqlUserID, mysqlGroupID); err != nil {
		return err
	}

	if err := writeSignedLeaf(mysqlClientOutputDir, "client", mysqlCA, []string{"rails_app", "testserver", "localhost"}, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, 0, 0); err != nil {
		return err
	}

	if err := writeSelfSignedLeaf(nginxOutputDir, "cert", []string{"localhost", "nginx", "nginx_server"}, []net.IP{net.ParseIP("127.0.0.1")}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}); err != nil {
		return err
	}

	return nil
}

func newCertificateAuthority(commonName string) (*certificateAuthority, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serialNumber, err := newSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generate CA serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-certificateBackdate),
		NotAfter:              now.Add(certificateLifetime),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}

	return &certificateAuthority{
		certificate: template,
		privateKey:  privateKey,
	}, nil
}

func writeCertificateAuthority(dir, name string, ca *certificateAuthority) error {
	certificateDER, err := x509.CreateCertificate(rand.Reader, ca.certificate, ca.certificate, &ca.privateKey.PublicKey, ca.privateKey)
	if err != nil {
		return fmt.Errorf("create CA certificate: %w", err)
	}

	return writeCertificate(filepath.Join(dir, name+".pem"), certificateDER)
}

func writeSignedLeaf(dir, name string, ca *certificateAuthority, dnsNames []string, ipAddresses []net.IP, usages []x509.ExtKeyUsage, ownerUID, ownerGID int) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return fmt.Errorf("generate %s key: %w", name, err)
	}

	template, err := newLeafTemplate(name, dnsNames, ipAddresses, usages)
	if err != nil {
		return fmt.Errorf("create %s template: %w", name, err)
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &privateKey.PublicKey, ca.privateKey)
	if err != nil {
		return fmt.Errorf("create %s certificate: %w", name, err)
	}

	if err := writeCertificate(filepath.Join(dir, name+"-cert.pem"), certificateDER); err != nil {
		return err
	}

	return writePrivateKey(filepath.Join(dir, name+"-key.pem"), privateKey, ownerUID, ownerGID)
}

func writeSelfSignedLeaf(dir, name string, dnsNames []string, ipAddresses []net.IP, usages []x509.ExtKeyUsage) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return fmt.Errorf("generate %s key: %w", name, err)
	}

	template, err := newLeafTemplate(name, dnsNames, ipAddresses, usages)
	if err != nil {
		return fmt.Errorf("create %s template: %w", name, err)
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("create %s certificate: %w", name, err)
	}

	if err := writeCertificate(filepath.Join(dir, name+".pem"), certificateDER); err != nil {
		return err
	}

	return writePrivateKey(filepath.Join(dir, "key.pem"), privateKey, 0, 0)
}

func newLeafTemplate(commonName string, dnsNames []string, ipAddresses []net.IP, usages []x509.ExtKeyUsage) (*x509.Certificate, error) {
	serialNumber, err := newSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generate %s serial number: %w", commonName, err)
	}

	now := time.Now()

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-certificateBackdate),
		NotAfter:     now.Add(certificateLifetime),
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  usages,
	}, nil
}

func writeCertificate(path string, der []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	return file.Chmod(certificateFileMode)
}

func writePrivateKey(path string, privateKey *rsa.PrivateKey, ownerUID, ownerGID int) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, privateKeyFileMode)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	if err := pem.Encode(file, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	if err := file.Chmod(privateKeyFileMode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}

	if err := file.Chown(ownerUID, ownerGID); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}

	return nil
}

func newSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	return serialNumber, nil
}
