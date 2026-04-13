// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

type checkoutResponse struct {
	Status          string `json:"status"`
	InventoryStatus int    `json:"inventory_status"`
	InventoryBody   string `json:"inventory_body"`
}

func main() {
	backendURL := os.Getenv("BACKEND_URL")
	if backendURL == "" {
		backendURL = "http://localhost:8081"
	}

	client := &http.Client{Timeout: 3 * time.Second}
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/checkout", func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, backendURL+"/inventory?sku=sku-123", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		for _, headerName := range []string{"x-tenant-id", "x-user-segment", "authorization", "x-request-id"} {
			if value := r.Header.Get(headerName); value != "" {
				req.Header.Set(headerName, value)
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		out := checkoutResponse{
			Status:          "ok",
			InventoryStatus: resp.StatusCode,
			InventoryBody:   string(body),
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(out); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	addr := ":8080"
	log.Printf("frontend listening on %s, backend=%s", addr, backendURL)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("frontend server failed: %v", err)
	}
}
