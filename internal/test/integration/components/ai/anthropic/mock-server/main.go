// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package main implements a mock Anthropic API server for integration testing.
// It responds to POST /v1/messages with the same headers and gzip-compressed
// body that the real Anthropic API returns, supporting both streaming and non-streaming modes.
package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

const messagesBody = `{"model":"claude-sonnet-4-6","id":"msg_01QCj5VkxPS3NQUtrt5Npjcr","type":"message","role":"assistant","content":[{"type":"text","text":"Quantum computing uses quantum mechanical phenomena like superposition and entanglement to process information in ways that can solve certain complex problems exponentially faster than classical computers."}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":15,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":0},"output_tokens":35,"service_tier":"standard","inference_geo":"global"}}`

const streamingBody = `event: message_start
data: {"type":"message_start","message":{"model":"claude-sonnet-4-6","id":"msg_017VX1VDFNbm2uGebyvLmHwv","type":"message","role":"assistant","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":17,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":0},"output_tokens":2,"service_tier":"standard","inference_geo":"global"}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: ping
data: {"type": "ping"}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"With elegant syntax and indentation true,"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"\nPython turns complex problems into something you can do."}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"input_tokens":17,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":37}}

event: message_stop
data: {"type":"message_stop"}

`

const errorBody = `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"},"request_id":"req_011CZLkWqu2dABS8vFB9G6Lz"}`

type messagesRequest struct {
	Messages  json.RawMessage `json:"messages"`
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	Stream    bool            `json:"stream"`
	System    string          `json:"system"`
	Tools     json.RawMessage `json:"tools"`
}

func setResponseHeaders(h http.Header) {
	h.Set("Anthropic-Ratelimit-Input-Tokens-Limit", "30000")
	h.Set("Anthropic-Ratelimit-Input-Tokens-Remaining", "30000")
	h.Set("Anthropic-Ratelimit-Input-Tokens-Reset", "2026-03-22T21:16:35Z")
	h.Set("Anthropic-Ratelimit-Output-Tokens-Limit", "8000")
	h.Set("Anthropic-Ratelimit-Output-Tokens-Remaining", "8000")
	h.Set("Anthropic-Ratelimit-Output-Tokens-Reset", "2026-03-22T21:16:36Z")
	h.Set("Anthropic-Ratelimit-Requests-Limit", "50")
	h.Set("Anthropic-Ratelimit-Requests-Remaining", "49")
	h.Set("Anthropic-Ratelimit-Requests-Reset", "2026-03-22T21:16:35Z")
	h.Set("Anthropic-Ratelimit-Tokens-Limit", "38000")
	h.Set("Anthropic-Ratelimit-Tokens-Remaining", "38000")
	h.Set("Anthropic-Ratelimit-Tokens-Reset", "2026-03-22T21:16:35Z")
	h.Set("Anthropic-Organization-Id", "ed46523f-a4ac-48c5-9bc3-415a29c51d84")
	h.Set("Request-Id", "req_011CZJp7UUz53CtoQA8w3WdW")
	h.Set("X-Robots-Tag", "none")
	h.Set("Cf-Cache-Status", "DYNAMIC")
	h.Set("Cf-Ray", "9e0837d84bac9491-LHR")
	h.Set("Server", "cloudflare")
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	h.Set("Connection", "keep-alive")
}

func setErrorResponseHeaders(h http.Header) {
	h.Set("X-Should-Retry", "false")
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	h.Set("X-Envoy-Upstream-Service-Time", "7")
	h.Set("Request-Id", "req_011CZLkWqu2dABS8vFB9G6Lz")
	h.Set("Vary", "Accept-Encoding")
	h.Set("Server-Timing", "x-originResponse;dur=9")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	h.Set("Date", "Mon, 23 Mar 2026 21:50:35 GMT")
	h.Set("Cf-Cache-Status", "DYNAMIC")
	h.Set("Content-Type", "application/json")
	h.Set("Connection", "keep-alive")
	h.Set("Server", "cloudflare")
	h.Set("Content-Encoding", "gzip")
	h.Set("Set-Cookie", "_cfuvid=nTnkXk.dcxJEj9RUcl8JcGFxmia957_qPZLrtvXk2Qc-1774302634.9994936-1.0.1.1-o0yyvBwW9qJYIwiT9_GiweQSzlgE_LdIL4WYG4enwZQ; HttpOnly; SameSite=None; Secure; Path=/; Domain=api.anthropic.com")
	h.Set("X-Robots-Tag", "none")
	h.Set("Cf-Ray", "9e10a70cbee0b8d2-AMS")
}

func handleMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	var req messagesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	var validationErrors []string
	if len(req.Messages) == 0 {
		validationErrors = append(validationErrors, "messages cannot be empty")
	}
	if req.Model == "" {
		validationErrors = append(validationErrors, "model cannot be empty")
	}
	if req.MaxTokens == 0 {
		validationErrors = append(validationErrors, "max_tokens cannot be empty")
	}
	if len(validationErrors) > 0 {
		http.Error(w, "request validation failed:\n"+strings.Join(validationErrors, "\n"), http.StatusBadRequest)
		return
	}

	if r.URL.Query().Has("error") {
		h := w.Header()
		setErrorResponseHeaders(h)
		w.WriteHeader(http.StatusServiceUnavailable)

		gz := gzip.NewWriter(w)
		if _, err := gz.Write([]byte(errorBody)); err != nil {
			log.Printf("error writing gzip error body: %v", err)
			return
		}
		if err := gz.Close(); err != nil {
			log.Printf("error closing gzip writer for error: %v", err)
		}
		return
	}

	h := w.Header()
	setResponseHeaders(h)

	if req.Stream {
		h.Set("Content-Type", "text/event-stream")
		h.Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(streamingBody))
		if err != nil {
			log.Printf("error writing streaming body: %v", err)
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		return
	}

	h.Set("Content-Encoding", "gzip")
	h.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	gz := gzip.NewWriter(w)
	if _, err := gz.Write([]byte(messagesBody)); err != nil {
		log.Printf("error writing gzip body: %v", err)
		return
	}
	if err := gz.Close(); err != nil {
		log.Printf("error closing gzip writer: %v", err)
	}
}

func main() {
	port := os.Getenv("ANTHROPIC_PORT")
	if port == "" {
		port = "8082"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/messages", handleMessages)

	addr := ":" + port
	log.Printf("mock Anthropic server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
