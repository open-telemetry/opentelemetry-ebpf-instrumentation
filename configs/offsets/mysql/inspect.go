// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
)

func HTTPHandler() http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		db, err := sql.Open("mysql", "user:password@tcp(localhost:3306)/testdb")
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		defer db.Close()

		rows, err := db.Query("SELECT id, name FROM users WHERE id = ?", 1)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var id int
			var name string
			if err := rows.Scan(&id, &name); err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
				return
			}
		}

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
