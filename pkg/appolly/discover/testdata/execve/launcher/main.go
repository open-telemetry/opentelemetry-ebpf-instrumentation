// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: %s <server> [args...]", os.Args[0])
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if _, err := io.WriteString(os.Stdout, "L"); err != nil {
		return err
	}
	var input [1]byte
	if _, err := io.ReadFull(os.Stdin, input[:]); err != nil {
		return err
	}
	response, err := http.Get(server.URL)
	if err != nil {
		return err
	}
	if err := response.Body.Close(); err != nil {
		return err
	}
	server.Close()

	// Like grafana-server, replace this process with the server subcommand.
	binary := os.Args[1]
	args := append([]string{binary, "server"}, os.Args[2:]...)
	return syscall.Exec(binary, args, os.Environ())
}
