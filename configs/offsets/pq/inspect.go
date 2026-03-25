// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/lib/pq"
)

func HTTPHandler() http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		db, err := sql.Open("postgres", "user=postgres dbname=sqltest sslmode=disable password=postgres host=localhost port=5432")
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		defer db.Close()

		rows, err := db.Query("SELECT 1")
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
