// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
)

type jsonCodec struct{}

func (jsonCodec) Name() string { return "json" }

func (jsonCodec) Marshal(value any) ([]byte, error) { return json.Marshal(value) }

func (jsonCodec) Unmarshal(data []byte, value any) error { return json.Unmarshal(data, value) }

type request struct{}

type response struct {
	Traceparents string `json:"traceparents"`
}

type traceService interface{}

func handleTraceparents(
	_ any,
	ctx context.Context,
	decode func(any) error,
	_ grpc.UnaryServerInterceptor,
) (any, error) {
	if err := decode(&request{}); err != nil {
		return nil, err
	}

	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("traceparent")
	return &response{Traceparents: fmt.Sprintf("%d:%s", len(values), strings.Join(values, ","))}, nil
}

var service = grpc.ServiceDesc{
	ServiceName: "TraceService",
	HandlerType: (*traceService)(nil),
	Methods: []grpc.MethodDesc{{
		MethodName: "Traceparents",
		Handler:    handleTraceparents,
	}},
}

var (
	useTLS   = flag.Bool("tls", false, "use TLS for the loopback connection")
	certFile = flag.String("cert", "", "server certificate")
	keyFile  = flag.String("key", "", "server private key")
)

func main() {
	flag.Parse()
	encoding.RegisterCodec(jsonCodec{})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen error: %v\n", err)
		os.Exit(1)
	}
	serverOptions := []grpc.ServerOption{grpc.ForceServerCodec(jsonCodec{})}
	if *useTLS {
		serverCredentials, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "server TLS error: %v\n", err)
			os.Exit(1)
		}
		serverOptions = append(serverOptions, grpc.Creds(serverCredentials))
	}
	server := grpc.NewServer(serverOptions...)
	server.RegisterService(&service, struct{}{})
	go func() { _ = server.Serve(listener) }()

	var conn *grpc.ClientConn
	fmt.Println("READY")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		switch scanner.Text() {
		case "REQUEST":
			report(call(listener.Addr().String(), &conn))
		case "EXIT":
			if conn != nil {
				_ = conn.Close()
			}
			server.Stop()
			return
		}
	}
}

func call(address string, conn **grpc.ClientConn) (string, error) {
	if *conn == nil {
		transportCredentials := credentials.TransportCredentials(insecure.NewCredentials())
		if *useTLS {
			transportCredentials = credentials.NewTLS(&tls.Config{ //nolint:gosec
				InsecureSkipVerify: true,
			})
		}
		client, err := grpc.NewClient(
			address,
			grpc.WithTransportCredentials(transportCredentials),
			grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
		)
		if err != nil {
			return "", err
		}
		*conn = client
	}

	var result response
	err := (*conn).Invoke(context.Background(), "/TraceService/Traceparents", &request{}, &result)
	return result.Traceparents, err
}

func report(result string, err error) {
	if err != nil {
		fmt.Printf("ERROR %v\n", err)
		return
	}
	fmt.Printf("TP_RESULT=%s\n", result)
}
