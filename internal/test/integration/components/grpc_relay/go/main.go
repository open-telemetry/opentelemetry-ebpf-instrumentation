// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

// relayServicer is the interface that gRPC uses for HandlerType.
type relayServicer interface {
	Relay(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error)
}

// relayServer implements a gRPC relay that optionally forwards to the next hop.
type relayServer struct {
	nextHop string
}

func (s *relayServer) Relay(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	log.Println("received Relay RPC")
	if s.nextHop != "" {
		if err := callNextHop(ctx, s.nextHop); err != nil {
			return nil, err
		}
	}
	return &emptypb.Empty{}, nil
}

func callNextHop(ctx context.Context, addr string) error {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	return conn.Invoke(ctx, "/relay.Relay/Relay", &emptypb.Empty{}, &emptypb.Empty{})
}

//nolint:revive
func relayHandler(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
	req := new(emptypb.Empty)
	if err := dec(req); err != nil {
		return nil, err
	}
	return srv.(relayServicer).Relay(ctx, req)
}

var relayServiceDesc = grpc.ServiceDesc{
	ServiceName: "relay.Relay",
	HandlerType: (*relayServicer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Relay",
			Handler:    relayHandler,
		},
	},
}

func main() {
	httpPort := os.Getenv("HTTP_PORT")
	grpcPort := os.Getenv("GRPC_PORT")
	nextHop := os.Getenv("NEXT_HOP")

	srv := &relayServer{nextHop: nextHop}

	if grpcPort != "" {
		lis, err := net.Listen("tcp", ":"+grpcPort)
		if err != nil {
			log.Fatal(err)
		}
		s := grpc.NewServer()
		s.RegisterService(&relayServiceDesc, srv)
		log.Printf("gRPC listening on :%s", grpcPort)
		go func() { log.Fatal(s.Serve(lis)) }()
	}

	if httpPort != "" {
		http.HandleFunc("/relay", func(w http.ResponseWriter, r *http.Request) {
			if err := callNextHop(r.Context(), nextHop); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Fprintln(w, "ok")
		})
		http.HandleFunc("/smoke", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		log.Printf("HTTP listening on :%s", httpPort)
		log.Fatal(http.ListenAndServe(":"+httpPort, nil))
	} else {
		// Block forever when running as gRPC-only relay/terminal
		select {}
	}
}
