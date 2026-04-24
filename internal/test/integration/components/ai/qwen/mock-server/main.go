// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package main implements a mock Qwen (DashScope) API server for integration testing.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

const chatResponseBody = `{
  "model":"qwen-plus",
  "id":"chatcmpl-a1ad370d-b4b0-90bb-9a87-a131fd0687d6",
  "choices":[
    {
      "message":{
        "content":"你好！我是通义千问（Qwen）。",
        "role":"assistant"
      },
      "index":0,
      "finish_reason":"stop"
    }
  ],
  "created":1776830068,
  "object":"chat.completion",
  "usage":{
    "total_tokens":88,
    "completion_tokens":66,
    "prompt_tokens":22
  }
}`

const generationResponseBody = `{
  "request_id":"req_abcdef0123456789",
  "output":{
    "text":"eBPF lets you run safe, efficient programs inside the Linux kernel.",
    "finish_reason":"stop"
  },
  "usage":{
    "input_tokens":12,
    "output_tokens":10,
    "total_tokens":22
  }
}`

const errorResponseBody = `{
  "error": {
    "message": "insufficient quota",
    "type": "insufficient_quota"
  }
}`

func setQwenHeaders(h http.Header, requestID string) {
	h.Set("Content-Type", "application/json")
	h.Set("X-Request-Id", requestID)
	h.Set("X-DashScope-Request-Id", requestID)
	h.Set("X-Dashscope-Call-Gateway", "true")
}

func handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	var req struct {
		Model    string          `json:"model"`
		Messages json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}
	if req.Model == "" || len(req.Messages) == 0 {
		http.Error(w, "request validation failed", http.StatusBadRequest)
		return
	}

	if r.URL.Query().Has("error") {
		const errorResponseID = "chatcmpl-err-429-insufficient-quota"
		setQwenHeaders(w.Header(), errorResponseID)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(errorResponseBody))
		return
	}

	const chatResponseID = "chatcmpl-a1ad370d-b4b0-90bb-9a87-a131fd0687d6"
	setQwenHeaders(w.Header(), chatResponseID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(chatResponseBody))
}

func handleGeneration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	var req struct {
		Model  string `json:"model"`
		Prompt string `json:"prompt"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}
	if req.Model == "" || strings.TrimSpace(req.Prompt) == "" {
		http.Error(w, "request validation failed", http.StatusBadRequest)
		return
	}

	const generationResponseID = "req_abcdef0123456789"
	setQwenHeaders(w.Header(), generationResponseID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(generationResponseBody))
}

func main() {
	port := os.Getenv("QWEN_PORT")
	if port == "" {
		port = "8085"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/compatible-mode/v1/chat/completions", handleChatCompletions)
	mux.HandleFunc("/api/v1/services/aigc/text-generation/generation", handleGeneration)

	addr := ":" + port
	log.Printf("mock Qwen server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
