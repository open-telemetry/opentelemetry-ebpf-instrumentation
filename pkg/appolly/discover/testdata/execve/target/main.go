// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

package main

import (
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if len(os.Args) < 2 || os.Args[1] != "server" {
		return errors.New("expected server subcommand")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if _, err := io.WriteString(os.Stdout, "R"); err != nil {
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
	_, err = io.WriteString(os.Stdout, "S")
	return err
}
