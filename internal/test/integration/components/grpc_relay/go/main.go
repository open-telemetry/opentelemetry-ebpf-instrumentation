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
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

const grpcCallTimeout = 10 * time.Second

// relayServicer is the interface that gRPC uses for HandlerType.
type relayServicer interface {
	Relay(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error)
}

// relayServer implements a gRPC relay that optionally forwards to the next hop.
type relayServer struct {
	nextHop     string
	nextHopHTTP string // when set, forward via HTTP GET instead of gRPC
}

func (s *relayServer) Relay(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	log.Println("received Relay RPC")
	if s.nextHopHTTP != "" {
		if err := callNextHopHTTP(ctx, s.nextHopHTTP); err != nil {
			return nil, err
		}
	} else if s.nextHop != "" {
		if err := callNextHop(ctx, s.nextHop); err != nil {
			return nil, err
		}
	}
	return &emptypb.Empty{}, nil
}

func callNextHopHTTP(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP relay returned %d", resp.StatusCode)
	}
	return nil
}

// One persistent grpc.NewClient per (addr) — concurrent calls share a single
// HTTP/2 connection and multiplex as separate streams. Without this, every
// request creates its own connection, collapsing multiplex semantics past
// this hop and making it impossible to assert per-stream isolation downstream
var (
	nextHopConnsMu sync.Mutex
	nextHopConns   = map[string]*grpc.ClientConn{}
)

func nextHopConn(addr string) (*grpc.ClientConn, error) {
	nextHopConnsMu.Lock()
	defer nextHopConnsMu.Unlock()
	if c, ok := nextHopConns[addr]; ok {
		return c, nil
	}
	c, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	nextHopConns[addr] = c
	return c, nil
}

func callNextHop(ctx context.Context, addr string) error {
	conn, err := nextHopConn(addr)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, grpcCallTimeout)
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
	healthPort := os.Getenv("HEALTH_PORT")
	nextHop := os.Getenv("NEXT_HOP")
	nextHopHTTP := os.Getenv("NEXT_HOP_HTTP")
	nextHopMux := os.Getenv("NEXT_HOP_MULTIPLEX")
	if nextHopMux == "" {
		nextHopMux = nextHop
	}

	srv := &relayServer{nextHop: nextHop, nextHopHTTP: nextHopHTTP}

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

	// Health check endpoint for gRPC-only services (no HTTP_PORT).
	if healthPort != "" && httpPort == "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		log.Printf("health listening on :%s", healthPort)
		go func() { log.Fatal(http.ListenAndServe(":"+healthPort, mux)) }()
	}

	if httpPort != "" {
		http.HandleFunc("/relay", func(w http.ResponseWriter, r *http.Request) {
			if err := callNextHop(r.Context(), nextHop); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Fprintln(w, "ok")
		})
		http.HandleFunc("/relay-multiplex", func(w http.ResponseWriter, r *http.Request) {
			// Test multiplexed gRPC context propagation: multiple concurrent
			// streams on the same HTTP/2 connection must each get their own
			// trace context (distinct span IDs).
			//
			// grpc.NewClient with default pick_first LB uses a single
			// subconnection (one TCP + HTTP/2 connection). The warmup call
			// forces connection establishment, then concurrent Invokes
			// multiplex as separate HTTP/2 streams on that connection.
			conn, err := grpc.NewClient(nextHopMux, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer conn.Close()

			// Warmup: force TCP + HTTP/2 handshake so subsequent calls reuse this connection.
			warmCtx, warmCancel := context.WithTimeout(r.Context(), grpcCallTimeout)
			if err := conn.Invoke(warmCtx, "/relay.Relay/Relay", &emptypb.Empty{}, &emptypb.Empty{}); err != nil {
				warmCancel()
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			warmCancel()

			// Fire 3 RPCs at the exact same instant using a start barrier.
			// All goroutines wait on the barrier, then call Invoke simultaneously,
			// guaranteeing multiple HTTP/2 streams in-flight on the same connection.
			const n = 3
			var barrier, done sync.WaitGroup
			barrier.Add(n)
			done.Add(n)
			errs := make(chan error, n)
			for i := 0; i < n; i++ {
				go func() {
					defer done.Done()
					barrier.Done()
					barrier.Wait() // all goroutines release at the same instant
					ctx, cancel := context.WithTimeout(r.Context(), grpcCallTimeout)
					defer cancel()
					errs <- conn.Invoke(ctx, "/relay.Relay/Relay", &emptypb.Empty{}, &emptypb.Empty{})
				}()
			}
			done.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
			fmt.Fprintln(w, "ok")
		})
		healthHandler := func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}
		http.HandleFunc("/smoke", healthHandler)
		http.HandleFunc("/health", healthHandler)
		log.Printf("HTTP listening on :%s", httpPort)
		log.Fatal(http.ListenAndServe(":"+httpPort, nil))
	} else {
		// Block forever when running as gRPC-only relay/terminal
		select {}
	}
}
