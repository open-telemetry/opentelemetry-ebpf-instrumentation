// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"sync/atomic"
)

type job struct {
	ID int64
}

type response struct {
	JobID  int64  `json:"job_id"`
	Result string `json:"result"`
}

var (
	jobCounter atomic.Int64
	workCh     = make(chan job)
)

func main() {
	port := envOrDefault("PORT", "8080")

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte("try GET /receive and GET /dispatch\n"))
	})
	mux.HandleFunc("/receive", receive)
	mux.HandleFunc("/dispatch", dispatch)

	addr := ":" + port
	slog.Info("starting channel links example", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func dispatch(rw http.ResponseWriter, req *http.Request) {
	jobID := jobCounter.Add(1)
	workCh <- job{ID: jobID}

	out := response{
		JobID:  jobID,
		Result: "dispatched to waiting receiver",
	}

	rw.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(rw).Encode(out); err != nil {
		slog.Warn("encode response", "error", err, "path", req.URL.Path)
	}
}

func receive(rw http.ResponseWriter, req *http.Request) {
	item := <-workCh

	rw.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(rw).Encode(response{
		JobID:  item.ID,
		Result: "received from channel",
	}); err != nil {
		slog.Warn("encode response", "error", err, "path", req.URL.Path)
	}
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}

	return fallback
}
