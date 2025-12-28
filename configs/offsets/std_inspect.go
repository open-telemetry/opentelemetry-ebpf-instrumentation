// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
)

// This program is used to generate an executable that can be inspected by the go-offsets-tracker tool

// Args defines the arguments for the RPC methods.
type Args struct {
	A, B int
}

// Arith provides methods for arithmetic operations.
type Arith struct{}

// Multiply multiplies two numbers and returns the result.
func (t *Arith) Multiply(args *Args, reply *int) error {
	*reply = args.A * args.B
	return nil
}

type ReadWriteCloserWrapper struct {
	io.Reader
	io.Writer
}

// Close is a no-op to satisfy the io.ReadWriteCloser interface.
func (w *ReadWriteCloserWrapper) Close() error {
	return nil
}

func jsonrpcHandler(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}
	// Wrap the request body and response writer in a ReadWriteCloser.
	conn := &ReadWriteCloserWrapper{Reader: request.Body, Writer: writer}
	// Serve the request using JSON-RPC codec.
	rpc.ServeCodec(jsonrpc.NewServerCodec(conn))
}

func regularGetRequest(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	rt := http.DefaultTransport

	res, err := rt.RoundTrip(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	fmt.Printf("Status: %v\n", res.Status)

	return nil
}

func useDatabaseSQL() error {
	// Open a dummy database connection to trigger compilation of database/sql types
	db, err := sql.Open("mysql", "user:password@tcp(localhost:3306)/dbname")
	if err != nil {
		return err
	}
	defer db.Close()

	// Execute a query to trigger driverConn usage
	_, err = db.Query("SELECT 1")
	return err
}

func main() {
	// Trigger database/sql types to be compiled
	_ = useDatabaseSQL()

	err := regularGetRequest(context.Background(), "http://localhost:8090/rolldice")
	if err != nil {
		os.Exit(1)
	}
	err = http.ListenAndServe(":9090", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// this doesn't need to have any sense!
		writer.WriteHeader(request.ProtoMajor)
	}))
	if err != nil {
		os.Exit(1)
	}
	// Register the Arith service.
	arith := new(Arith)
	rpc.Register(arith)
	err = http.ListenAndServe(":8080", http.HandlerFunc(jsonrpcHandler))
	if err != nil {
		os.Exit(1)
	}
}
