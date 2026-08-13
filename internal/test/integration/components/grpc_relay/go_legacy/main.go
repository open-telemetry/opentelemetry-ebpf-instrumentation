// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	callTimeout            = 10 * time.Second
	applicationTraceparent = "00-33333333333333333333333333333333-4444444444444444-01"
)

type ownershipCase struct {
	name         string
	traceparent  string
	hold         bool
	large        bool
	boundaryLen  int
	entropyBytes int
}

var connection struct {
	sync.Mutex
	client *grpc.ClientConn
}

func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/ownership", func(w http.ResponseWriter, r *http.Request) {
		runID := r.URL.Query().Get("run")
		var err error
		if r.URL.Query().Get("mode") == "socket" {
			err = runSocketControl(r.Context(), os.Getenv("OWNERSHIP_NEXT_HOP"), runID)
		} else {
			err = runBatch(r.Context(), os.Getenv("OWNERSHIP_NEXT_HOP"), runID)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	log.Fatal(http.ListenAndServe(":"+os.Getenv("HTTP_PORT"), nil))
}

func clientConn(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	connection.Lock()
	defer connection.Unlock()
	if connection.client != nil {
		return connection.client, nil
	}
	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	connection.client = conn
	return conn, nil
}

func runBatch(ctx context.Context, addr, runID string) error {
	if addr == "" || runID == "" {
		return fmt.Errorf("OWNERSHIP_NEXT_HOP and run are required")
	}
	conn, err := clientConn(ctx, addr)
	if err != nil {
		return err
	}

	sequential := []ownershipCase{
		{name: "owned-index-1", traceparent: applicationTraceparent},
		{name: "owned-index-2", traceparent: applicationTraceparent},
		{name: "owned-index-3", traceparent: applicationTraceparent},
		{name: "owned-index-4", traceparent: applicationTraceparent},
		{name: "control-after-index"},
		{name: "owned-continuation", traceparent: applicationTraceparent, large: true},
		{name: "control-continuation", large: true},
		{name: "control-after-continuation"},
	}
	for length := 32500; length <= 32768; length += 4 {
		sequential = append(sequential, ownershipCase{
			name: fmt.Sprintf("control-prewrite-%d", length), boundaryLen: length,
		})
	}
	for _, testCase := range sequential {
		if err := invoke(ctx, conn, runID, testCase); err != nil {
			return err
		}
	}

	concurrent := []ownershipCase{
		{name: "mux-owned-1", traceparent: applicationTraceparent, hold: true},
		{name: "mux-control-1", hold: true},
		{name: "mux-owned-2", traceparent: applicationTraceparent, hold: true},
		{name: "mux-control-2", hold: true},
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(concurrent))
	for _, testCase := range concurrent {
		wg.Add(1)
		go func(testCase ownershipCase) {
			defer wg.Done()
			errs <- invoke(ctx, conn, runID, testCase)
		}(testCase)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err
		}
	}
	return invoke(ctx, conn, runID, ownershipCase{name: "control-after-mux"})
}

func runSocketControl(ctx context.Context, addr, runID string) error {
	if addr == "" || runID == "" {
		return fmt.Errorf("OWNERSHIP_NEXT_HOP and run are required")
	}
	conn, err := clientConn(ctx, addr)
	if err != nil {
		return err
	}
	if err := invoke(ctx, conn, runID, ownershipCase{
		name: "socket-continuation", entropyBytes: 15020,
	}); err != nil {
		return err
	}
	return invoke(ctx, conn, runID, ownershipCase{name: "socket-control"})
}

func invoke(ctx context.Context, conn *grpc.ClientConn, runID string, testCase ownershipCase) error {
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
	callCtx, cancel := context.WithTimeout(metadata.AppendToOutgoingContext(ctx, pairs...), callTimeout)
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
