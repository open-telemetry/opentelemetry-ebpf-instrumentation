// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

const (
	staticTraceparent          = "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-86"
	oversizedMetadataValueSize = 64 << 10
)

func main() {
	serverTLS, clientTLS := tlsConfigs()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	defer listener.Close()

	traceparents := make(chan []string, 1)
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(serverTLS)),
		grpc.UnaryInterceptor(func(
			ctx context.Context,
			request any,
			info *grpc.UnaryServerInfo,
			handler grpc.UnaryHandler,
		) (any, error) {
			values := append([]string(nil), metadata.ValueFromIncomingContext(ctx, "traceparent")...)
			response, handlerErr := handler(ctx, request)
			traceparents <- values
			return response, handlerErr
		}),
	)
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(server, healthServer)
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil {
			fmt.Fprintln(os.Stderr, serveErr)
		}
	}()
	defer server.Stop()

	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(
		dialCtx,
		listener.Addr().String(),
		grpc.WithBlock(),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
	)
	must(err)
	defer conn.Close()
	client := healthpb.NewHealthClient(conn)

	fmt.Println("READY")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		mode := strings.TrimSpace(scanner.Text())
		if mode == "EXIT" {
			return
		}

		ctx, callCancel := context.WithTimeout(context.Background(), 10*time.Second)
		if mode == "VALID_TP" {
			ctx = metadata.AppendToOutgoingContext(ctx, "traceparent", staticTraceparent)
		}
		if mode == "LARGE_NO_TP" {
			ctx = metadata.AppendToOutgoingContext(
				ctx,
				"x-padding",
				strings.Repeat("a", oversizedMetadataValueSize),
			)
		}
		_, err = client.Check(ctx, &healthpb.HealthCheckRequest{})
		callCancel()
		must(err)

		values := <-traceparents
		fmt.Printf("TP_RESULT=%d|%s\n", len(values), strings.Join(values, ","))
	}
	must(scanner.Err())
}

func tlsConfigs() (*tls.Config, *tls.Config) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&privateKey.PublicKey,
		privateKey,
	)
	must(err)
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	must(err)

	certificatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificateDER,
	})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	must(err)

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		panic("failed to install test root certificate")
	}
	return &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		}, &tls.Config{
			RootCAs:    roots,
			ServerName: "localhost",
			MinVersion: tls.VersionTLS12,
		}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
