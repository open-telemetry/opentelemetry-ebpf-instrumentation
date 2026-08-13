// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/emptypb"
)

const grpcCallTimeout = 10 * time.Second

const ownershipTraceparent = "00-33333333333333333333333333333333-4444444444444444-01"

// relayServicer is the interface that gRPC uses for HandlerType.
type relayServicer interface {
	Relay(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error)
}

// relayServer implements a gRPC relay that optionally forwards to the next hop.
type relayServer struct {
	nextHop     string
	nextHopHTTP string // when set, forward via HTTP GET instead of gRPC
	observe     bool
}

func (s *relayServer) Relay(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	log.Println("received Relay RPC")
	if s.observe {
		observeRelay(ctx)
	}
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

var observedConcurrency struct {
	sync.Mutex
	runs map[string]*concurrencyState
}

type concurrencyState struct {
	active    int
	maxActive int
}

type ownershipObservation struct {
	CaseID       string   `json:"case_id"`
	Traceparents []string `json:"traceparents"`
	Peer         string   `json:"peer"`
	MaxActive    int      `json:"max_active"`
	LargeLength  int      `json:"large_length"`
	LargeSHA256  string   `json:"large_sha256"`
}

func observeRelay(ctx context.Context) {
	md, _ := metadata.FromIncomingContext(ctx)
	caseID := ""
	if values := md.Get("x-obi-case"); len(values) == 1 {
		caseID = values[0]
	}
	runID := caseID
	if slash := strings.IndexByte(caseID, '/'); slash >= 0 {
		runID = caseID[:slash]
	}

	observedConcurrency.Lock()
	if observedConcurrency.runs == nil {
		observedConcurrency.runs = map[string]*concurrencyState{}
	}
	state := observedConcurrency.runs[runID]
	if state == nil {
		state = &concurrencyState{}
		observedConcurrency.runs[runID] = state
	}
	state.active++
	if state.active > state.maxActive {
		state.maxActive = state.active
	}
	observedConcurrency.Unlock()
	defer func() {
		observedConcurrency.Lock()
		state.active--
		observedConcurrency.Unlock()
	}()

	if len(md.Get("x-obi-hold")) > 0 {
		time.Sleep(250 * time.Millisecond)
	}
	observedConcurrency.Lock()
	maxActive := state.maxActive
	observedConcurrency.Unlock()
	peerAddr := ""
	if remote, ok := peer.FromContext(ctx); ok {
		peerAddr = remote.Addr.String()
	}
	observation := ownershipObservation{
		Traceparents: md.Get("traceparent"),
		Peer:         peerAddr,
		MaxActive:    maxActive,
	}
	if values := md.Get("x-obi-large"); len(values) == 1 {
		observation.LargeLength = len(values[0])
		observation.LargeSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(values[0])))
	}
	observation.CaseID = caseID
	encoded, _ := json.Marshal(observation)
	log.Printf("OBI_GRPC_OBSERVATION %s", encoded)
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
	var transportCredentials credentials.TransportCredentials
	if os.Getenv("GRPC_NEXT_HOP_TLS") == "1" {
		transportCredentials = credentials.NewTLS(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec
	} else {
		transportCredentials = insecure.NewCredentials()
	}
	options := []grpc.DialOption{grpc.WithTransportCredentials(transportCredentials)}
	if os.Getenv("GRPC_DISABLE_WRITE_BUFFER") == "1" {
		options = append(options, grpc.WithWriteBufferSize(0))
	}
	c, err := grpc.NewClient(addr, options...)
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

	srv := &relayServer{
		nextHop:     nextHop,
		nextHopHTTP: nextHopHTTP,
		observe:     os.Getenv("OBSERVE_TRACEPARENT") == "1",
	}

	if grpcPort != "" {
		lis, err := net.Listen("tcp", ":"+grpcPort)
		if err != nil {
			log.Fatal(err)
		}
		var serverOptions []grpc.ServerOption
		if os.Getenv("GRPC_TLS") == "1" {
			creds, err := credentials.NewServerTLSFromFile(
				"/server_test_cert.pem", "/server_test_key.pem")
			if err != nil {
				log.Fatal(err)
			}
			serverOptions = append(serverOptions, grpc.Creds(creds))
		}
		s := grpc.NewServer(serverOptions...)
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
		ownershipNextHop := os.Getenv("OWNERSHIP_NEXT_HOP")
		if ownershipNextHop != "" {
			http.HandleFunc("/ownership", func(w http.ResponseWriter, r *http.Request) {
				runID := r.URL.Query().Get("run")
				var err error
				if r.URL.Query().Get("mode") == "socket" {
					err = runOwnershipSocketControl(r.Context(), ownershipNextHop, runID)
				} else if r.URL.Query().Get("mode") == "prewrite" {
					err = runOwnershipPrewriteControl(r.Context(), ownershipNextHop, runID)
				} else {
					err = runOwnershipBatch(r.Context(), ownershipNextHop, runID)
				}
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			})
		}
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
		// /self-prop?tp=<traceparent>&n=<calls>: sets traceparent metadata like an SDK.
		// A fresh connection per request keeps the field a literal on every attempt —
		// on a reused channel the encoder would index it after the first call and
		// leave nothing on the wire, making test retries meaningless
		http.HandleFunc("/self-prop", func(w http.ResponseWriter, r *http.Request) {
			tp := r.URL.Query().Get("tp")
			if tp == "" {
				http.Error(w, "missing tp", http.StatusBadRequest)
				return
			}
			n, _ := strconv.Atoi(r.URL.Query().Get("n"))
			if n < 1 {
				n = 3
			}

			conn, err := grpc.NewClient(nextHop, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer conn.Close()

			for i := 0; i < n; i++ {
				ctx, cancel := context.WithTimeout(r.Context(), grpcCallTimeout)
				ctx = metadata.AppendToOutgoingContext(ctx, "traceparent", tp)
				err := conn.Invoke(ctx, "/relay.Relay/Relay", &emptypb.Empty{}, &emptypb.Empty{})
				cancel()
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

type ownershipCase struct {
	name         string
	traceparent  string
	hold         bool
	large        bool
	boundaryLen  int
	entropyBytes int
}

func runOwnershipBatch(ctx context.Context, addr, runID string) error {
	if runID == "" {
		return fmt.Errorf("run is required")
	}
	conn, err := nextHopConn(addr)
	if err != nil {
		return err
	}

	sequential := []ownershipCase{
		{name: "owned-index-1", traceparent: ownershipTraceparent},
		{name: "owned-index-2", traceparent: ownershipTraceparent},
		{name: "owned-index-3", traceparent: ownershipTraceparent},
		{name: "owned-index-4", traceparent: ownershipTraceparent},
		{name: "control-after-index"},
		{name: "owned-continuation", traceparent: ownershipTraceparent, large: true},
		{name: "control-continuation", large: true},
		{name: "control-after-continuation"},
	}
	for length := 32500; length <= 32768; length += 4 {
		sequential = append(sequential, ownershipCase{
			name: fmt.Sprintf("control-prewrite-%d", length), boundaryLen: length,
		})
	}
	for _, testCase := range sequential {
		if err := invokeOwnership(ctx, conn, runID, testCase); err != nil {
			return err
		}
	}

	concurrent := []ownershipCase{
		{name: "mux-owned-1", traceparent: ownershipTraceparent, hold: true},
		{name: "mux-control-1", hold: true},
		{name: "mux-owned-2", traceparent: ownershipTraceparent, hold: true},
		{name: "mux-control-2", hold: true},
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(concurrent))
	for _, testCase := range concurrent {
		wg.Add(1)
		go func(testCase ownershipCase) {
			defer wg.Done()
			errs <- invokeOwnership(ctx, conn, runID, testCase)
		}(testCase)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err
		}
	}
	return invokeOwnership(ctx, conn, runID, ownershipCase{name: "control-after-mux"})
}

func runOwnershipSocketControl(ctx context.Context, addr, runID string) error {
	if runID == "" {
		return fmt.Errorf("run is required")
	}
	conn, err := nextHopConn(addr)
	if err != nil {
		return err
	}
	if err := invokeOwnership(ctx, conn, runID, ownershipCase{
		name: "socket-continuation", entropyBytes: 15020,
	}); err != nil {
		return err
	}
	return invokeOwnership(ctx, conn, runID, ownershipCase{name: "socket-control"})
}

func runOwnershipPrewriteControl(ctx context.Context, addr, runID string) error {
	if runID == "" {
		return fmt.Errorf("run is required")
	}
	conn, err := nextHopConn(addr)
	if err != nil {
		return err
	}
	if err := invokeOwnership(ctx, conn, runID, ownershipCase{name: "prewrite-first-control"}); err != nil {
		return err
	}
	if err := invokeOwnership(ctx, conn, runID, ownershipCase{
		name: "prewrite-capacity", traceparent: ownershipTraceparent, large: true,
	}); err != nil {
		return err
	}
	return invokeOwnership(ctx, conn, runID, ownershipCase{name: "prewrite-postwarm-control"})
}

func invokeOwnership(ctx context.Context, conn *grpc.ClientConn, runID string, testCase ownershipCase) error {
	pairs := []string{"x-obi-case", runID + "/" + testCase.name}
	if testCase.traceparent != "" {
		pairs = append(pairs, "traceparent", testCase.traceparent)
	}
	if testCase.hold {
		pairs = append(pairs, "x-obi-hold", "1")
	}
	if testCase.large {
		pairs = append(pairs, "x-obi-large", ownershipLargeHeader())
	} else if testCase.entropyBytes > 0 {
		pairs = append(pairs, "x-obi-large", ownershipEntropyHeader(testCase.entropyBytes))
	} else if testCase.boundaryLen > 0 {
		pairs = append(pairs, "x-obi-large", strings.Repeat("~", testCase.boundaryLen))
	}
	callCtx, cancel := context.WithTimeout(metadata.AppendToOutgoingContext(ctx, pairs...), grpcCallTimeout)
	defer cancel()
	return conn.Invoke(callCtx, "/relay.Relay/Relay", &emptypb.Empty{}, &emptypb.Empty{})
}

func ownershipLargeHeader() string {
	return ownershipEntropyHeader(32 * 1024)
}

func ownershipEntropyHeader(size int) string {
	data := make([]byte, size)
	state := uint32(0x2769a5c3)
	for i := range data {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		data[i] = byte(state)
	}
	return base64.RawStdEncoding.EncodeToString(data)
}
