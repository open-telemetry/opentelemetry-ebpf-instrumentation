// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package main implements a mock AWS Bedrock Runtime API server for integration testing.
// It responds to POST /model/{modelId}/invoke with the same headers and JSON body
// structure that the real Bedrock Runtime API returns.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const claudeResponse = `{
  "content": [{"type": "text", "text": "eBPF is a technology that allows running sandboxed programs in the Linux kernel without changing kernel source code."}],
  "stop_reason": "end_turn",
  "usage": {"input_tokens": 25, "output_tokens": 22}
}`

const titanResponse = `{
  "results": [
    {
      "outputText": "eBPF enables efficient observability and networking by attaching custom logic to kernel events.",
      "completionReason": "FINISH"
    }
  ]
}`

const errorResponse = `{
  "__type": "ValidationException",
  "message": "The provided model identifier is invalid."
}`

func handleInvoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	// Extract model ID from path: /model/{modelId}/invoke
	path := r.URL.Path
	const prefix = "/model/"
	idx := strings.Index(path, prefix)
	if idx < 0 {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	remainder := path[idx+len(prefix):]
	slashIdx := strings.Index(remainder, "/")
	modelID := remainder
	if slashIdx >= 0 {
		modelID = remainder[:slashIdx]
	}

	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("X-Amzn-Requestid", "mock-request-id-12345678")

	// Return error for nonexistent model
	if strings.Contains(modelID, "nonexistent") {
		// Error responses do not include token-count headers
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(errorResponse))
		return
	}

	// Determine response type based on model ID prefix
	var responseBody string
	var inputTokens, outputTokens int

	var reqMap map[string]json.RawMessage
	_ = json.Unmarshal(body, &reqMap)

	if strings.HasPrefix(modelID, "amazon.titan") {
		responseBody = titanResponse
		inputTokens = 8
		outputTokens = 16
	} else {
		// Default: Claude / Messages API format
		responseBody = claudeResponse
		inputTokens = 25
		outputTokens = 22
	}

	h.Set("X-Amzn-Bedrock-Input-Token-Count", strconv.Itoa(inputTokens))
	h.Set("X-Amzn-Bedrock-Output-Token-Count", strconv.Itoa(outputTokens))
	h.Set("X-Amzn-Bedrock-Invocation-Latency", "450")

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(responseBody))
}

func main() {
	port := os.Getenv("BEDROCK_PORT")
	if port == "" {
		port = "8086"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/model/", handleInvoke)

	addr := ":" + port
	log.Printf("mock Bedrock server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
