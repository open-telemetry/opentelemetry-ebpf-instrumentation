// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"time"
)

type inventoryResponse struct {
	SKU       string `json:"sku"`
	InStock   bool   `json:"in_stock"`
	Warehouse string `json:"warehouse"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/inventory", func(w http.ResponseWriter, r *http.Request) {
		sku := r.URL.Query().Get("sku")
		if sku == "" {
			sku = "sku-123"
		}

		// Add realistic jitter so trace timelines are easier to compare in screenshots.
		delayMillis := 40 + rand.Intn(90)
		time.Sleep(time.Duration(delayMillis) * time.Millisecond)

		resp := inventoryResponse{
			SKU:       sku,
			InStock:   true,
			Warehouse: "us-central",
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	addr := ":8081"
	log.Printf("backend listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("backend server failed: %v", err)
	}
}
