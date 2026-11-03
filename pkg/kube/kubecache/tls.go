// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kubecache // import "go.opentelemetry.io/obi/pkg/kube/kubecache"

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// TLSConfig enables TLS, and optionally mutual TLS, on the cache service.
type TLSConfig struct {
	Enabled bool `yaml:"enabled" env:"ENABLED"`
	// CertFile and KeyFile are the PEM-encoded certificate and private key of the service
	CertFile string `yaml:"cert_file" env:"CERT_FILE"`
	KeyFile  string `yaml:"key_file" env:"KEY_FILE"`
	// ClientCAFile, when set, makes the service require client certificates signed by this CA
	ClientCAFile string `yaml:"client_ca_file" env:"CLIENT_CA_FILE"`
}

func (c TLSConfig) Validate() error {
	if c.Enabled && (c.CertFile == "" || c.KeyFile == "") {
		return errors.New("tls.cert_file and tls.key_file are required when tls is enabled")
	}
	return nil
}

// Credentials returns the gRPC transport credentials for the cache service.
func (c TLSConfig) Credentials() (credentials.TransportCredentials, error) {
	if !c.Enabled {
		return insecure.NewCredentials(), nil
	}
	certificate, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading cache service certificate: %w", err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	if c.ClientCAFile != "" {
		if cfg.ClientCAs, err = loadCertPool(c.ClientCAFile); err != nil {
			return nil, err
		}
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return credentials.NewTLS(cfg), nil
}

// ClientTLSConfig configures how OBI connects to a cache service with TLS enabled.
type ClientTLSConfig struct {
	Enabled bool
	// CAFile verifies the cache service certificate. The system CAs are used when empty.
	CAFile string
	// CertFile and KeyFile are the client certificate for a cache service that requires one
	CertFile string
	KeyFile  string
}

func (c ClientTLSConfig) Validate() error {
	if c.Enabled && (c.CertFile == "") != (c.KeyFile == "") {
		return errors.New("kubernetes metadata_cache tls cert_file and key_file must be set together")
	}
	return nil
}

// Credentials returns the gRPC transport credentials for connecting to the cache service.
func (c ClientTLSConfig) Credentials() (credentials.TransportCredentials, error) {
	if !c.Enabled {
		return insecure.NewCredentials(), nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		pool, err := loadCertPool(c.CAFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	if c.CertFile != "" {
		certificate, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading cache client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{certificate}
	}
	return credentials.NewTLS(cfg), nil
}

func loadCertPool(file string) (*x509.CertPool, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("loading CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("CA file %s contains no certificates", file)
	}
	return pool, nil
}
