// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package main implements a mock TypeSafe Jev API server for integration testing.
// It responds to POST /api/v1/systemone with the same headers
// and JSON body structure that the real Jev API returns.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

const systemOneResponse = `{
  "id": "dec_test123abc456",
  "model": "jev-1.13",
  "provider": "jev-ai.org",
  "answers": {
    "refund_requested": {
      "type": "noul",
      "noul": 0.92
    }
  },
  "usage": {
    "input_tokens": 503,
    "output_tokens": 70,
    "charged_tokens": 503
  },
  "latency_ms": 1056
}`

const choiceQuestionResponse = `{
  "id": "dec_choice789xyz",
  "model": "jev-1.13",
  "provider": "jev-ai.org",
  "answers": {
    "refund_action": {
      "type": "choice",
      "choice": "full_refund",
      "confidence": 0.95
    }
  },
  "usage": {
    "input_tokens": 620,
    "output_tokens": 85,
    "charged_tokens": 620
  },
  "latency_ms": 1200
}`

func handleSystemOne(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	var req map[string]json.RawMessage
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if _, ok := req["state"]; !ok {
		http.Error(w, "state field is required", http.StatusBadRequest)
		return
	}
	if _, ok := req["questions"]; !ok {
		http.Error(w, "questions field is required", http.StatusBadRequest)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "application/json")

	// Check if the request contains a choice question to return different response
	var questions map[string]json.RawMessage
	if err := json.Unmarshal(req["questions"], &questions); err == nil {
		for _, q := range questions {
			var qDef map[string]interface{}
			if err := json.Unmarshal(q, &qDef); err == nil {
				if qType, ok := qDef["type"].(string); ok && qType == "choice" {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(choiceQuestionResponse))
					return
				}
			}
		}
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(systemOneResponse))
}

func main() {
	port := os.Getenv("JEV_PORT")
	if port == "" {
		port = "8084"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/systemone", handleSystemOne)
	mux.HandleFunc("/v1/systemone", handleSystemOne) // OpenRouter path

	addr := ":" + port
	log.Printf("mock Jev server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
