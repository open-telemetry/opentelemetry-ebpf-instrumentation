// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

var httpClient = &http.Client{
	// Transport: &http.Transport{
	// 	ForceAttemptHTTP2: false,
	// 	TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
	// },
	Transport: &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	},
}

func openAIBaseURL() string {
	if v := os.Getenv("OPENAI_BASE_URL"); v != "" {
		return v
	}
	return "http://localhost:8081"
}

func proxyPost(w http.ResponseWriter, path string, payload any, raiseForStatus bool) {
	body, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	url := openAIBaseURL() + path
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if raiseForStatus && resp.StatusCode >= http.StatusBadRequest {
		http.Error(w, fmt.Sprintf("upstream returned status %d: %s", resp.StatusCode, respBody), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(respBody)
}

func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode("ok!")
}

func messages(w http.ResponseWriter, _ *http.Request) {
	payload := map[string]any{
		"input":        "How do I check if a Python object is an instance of a class?",
		"instructions": "You are a coding assistant that talks like a pirate.",
		"model":        "gpt-5-mini",
	}
	proxyPost(w, "/v1/responses", payload, true)
}

func errorMessages(w http.ResponseWriter, _ *http.Request) {
	payload := map[string]any{
		"input":        "How do I check if a Python object is an instance of a class?",
		"instructions": "You are a coding assistant that talks like a pirate.",
		"model":        "gpt-5-mini",
	}
	proxyPost(w, "/v1/responses?error", payload, false)
}

func embeddings(w http.ResponseWriter, _ *http.Request) {
	payload := map[string]any{
		"input":      "The food was delicious",
		"model":      "text-embedding-3-small",
		"dimensions": 256,
	}
	proxyPost(w, "/v1/embeddings", payload, true)
}

func chat(w http.ResponseWriter, _ *http.Request) {
	payload := map[string]any{
		"messages": []map[string]any{
			{"role": "system", "content": "You are a helpful travel assistant."},
			{"role": "user", "content": "Plan a 6-day luxury trip to London for 3 people with a $4400 budget."},
		},
		"model":       "gpt-4o-mini",
		"temperature": 0.7,
	}
	proxyPost(w, "/v1/chat/completions", payload, true)
}

func conversations(w http.ResponseWriter, _ *http.Request) {
	payload := map[string]any{
		"items": []map[string]any{
			{"type": "message", "role": "user", "content": "Hello! I am learning Python and need some guidance."},
		},
		"metadata": map[string]any{"topic": "python-help", "user": "nino"},
		"model":    "gpt-5-mini",
	}
	proxyPost(w, "/v1/conversations", payload, true)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", health)
	mux.HandleFunc("GET /messages", messages)
	mux.HandleFunc("GET /error", errorMessages)
	mux.HandleFunc("GET /embeddings", embeddings)
	mux.HandleFunc("GET /chat", chat)
	mux.HandleFunc("GET /conversations", conversations)

	const port = 8080
	fmt.Printf("Server running: port=%d process_id=%d\n", port, os.Getpid())
	log.Fatal(http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", port), mux))
}
