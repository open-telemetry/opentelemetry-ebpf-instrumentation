// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kubecache // import "go.opentelemetry.io/obi/pkg/kube/kubecache"

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// GRPCSecurity configures transport security for the Kubernetes metadata cache.
// An empty Mode uses plaintext, preserving the default connection behavior.
type GRPCSecurity struct {
	// Mode is insecure (default), tls (server authentication), or mtls (mutual authentication).
	Mode string `yaml:"mode" env:"MODE" jsonschema:"enum=insecure,enum=tls,enum=mtls"`
	// CertFile is the server certificate, or the client certificate in mtls mode.
	CertFile string `yaml:"cert_file" env:"CERT_FILE"`
	// KeyFile is the private key corresponding to CertFile.
	KeyFile string `yaml:"key_file" env:"KEY_FILE"`
	// CAFile is the trusted client CA for an mtls server or a trusted server CA for a client.
	CAFile string `yaml:"ca_file" env:"CA_FILE"`
}

func (s GRPCSecurity) validateMode() error {
	switch s.Mode {
	case "", "insecure", "tls", "mtls":
		return nil
	default:
		return fmt.Errorf("unsupported Kubernetes metadata cache gRPC security mode %q", s.Mode)
	}
}

func (s GRPCSecurity) validateInsecure() error {
	if s.CertFile != "" || s.KeyFile != "" || s.CAFile != "" {
		return errors.New("kubernetes metadata cache gRPC certificate settings require tls or mtls security mode")
	}
	return nil
}

func (s GRPCSecurity) certificate() (tls.Certificate, error) {
	if s.CertFile == "" || s.KeyFile == "" {
		return tls.Certificate{}, fmt.Errorf("kubernetes metadata cache gRPC %s requires cert_file and key_file", s.Mode)
	}
	cert, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("loading Kubernetes metadata cache gRPC certificate: %w", err)
	}
	return cert, nil
}

func (s GRPCSecurity) certPool() (*x509.CertPool, error) {
	if s.CAFile == "" {
		return nil, nil // Go uses the system trust store for client connections.
	}
	caPEM, err := os.ReadFile(s.CAFile)
	if err != nil {
		return nil, fmt.Errorf("reading Kubernetes metadata cache gRPC CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("kubernetes metadata cache gRPC CA file contains no certificates")
	}
	return pool, nil
}

func (s GRPCSecurity) serverTLSConfig() (*tls.Config, error) {
	if err := s.validateMode(); err != nil {
		return nil, err
	}
	if s.Mode == "" || s.Mode == "insecure" {
		return nil, s.validateInsecure()
	}
	cert, err := s.certificate()
	if err != nil {
		return nil, err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if s.Mode == "mtls" {
		if s.CAFile == "" {
			return nil, errors.New("kubernetes metadata cache gRPC mtls server requires ca_file")
		}
		config.ClientCAs, err = s.certPool()
		if err != nil {
			return nil, err
		}
		config.ClientAuth = tls.RequireAndVerifyClientCert
	} else if s.CAFile != "" {
		return nil, errors.New("kubernetes metadata cache gRPC tls server does not use ca_file")
	}
	return config, nil
}

func (s GRPCSecurity) clientTLSConfig() (*tls.Config, error) {
	if err := s.validateMode(); err != nil {
		return nil, err
	}
	if s.Mode == "" || s.Mode == "insecure" {
		if err := s.validateInsecure(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if s.Mode == "tls" && (s.CertFile != "" || s.KeyFile != "") {
		return nil, errors.New("kubernetes metadata cache gRPC client certificates require mtls security mode")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	var err error
	config.RootCAs, err = s.certPool()
	if err != nil {
		return nil, err
	}
	if s.Mode == "mtls" {
		var cert tls.Certificate
		cert, err = s.certificate()
		if err != nil {
			return nil, err
		}
		config.Certificates = []tls.Certificate{cert}
	}
	return config, nil
}

// ValidateServer checks server security settings before the service starts.
func (s GRPCSecurity) ValidateServer() error {
	_, err := s.serverTLSConfig()
	return err
}

// ValidateClient checks client security settings before a connection is created.
func (s GRPCSecurity) ValidateClient() error {
	_, err := s.clientTLSConfig()
	return err
}

// ServerOption returns the gRPC server credential option, or nil for plaintext mode.
func (s GRPCSecurity) ServerOption() (grpc.ServerOption, error) {
	config, err := s.serverTLSConfig()
	if err != nil || config == nil {
		return nil, err
	}
	return grpc.Creds(credentials.NewTLS(config)), nil
}

// ClientCredentials returns gRPC transport credentials for the selected mode.
func (s GRPCSecurity) ClientCredentials() (credentials.TransportCredentials, error) {
	config, err := s.clientTLSConfig()
	if err != nil {
		return nil, err
	}
	if config == nil {
		return insecure.NewCredentials(), nil
	}
	return credentials.NewTLS(config), nil
}
