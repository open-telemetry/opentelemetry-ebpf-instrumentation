// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/jackc/pgx/v5"
)

func HTTPHandler() http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		conn, err := pgx.Connect(req.Context(), "postgres://user:password@localhost:5432/testdb")
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close(context.Background())

		rows, err := conn.Query(req.Context(), "SELECT id, name FROM users WHERE id=$1", 1)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		rw.WriteHeader(200)
		rw.Write([]byte("OK"))
	}
}

func main() {
	address := fmt.Sprintf(":%d", 8080)
	log.Printf("starting HTTP server on %s", address)
	err := http.ListenAndServe(address, HTTPHandler())
	log.Printf("HTTP server stopped: %v", err)
}
