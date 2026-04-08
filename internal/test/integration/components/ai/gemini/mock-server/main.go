// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package main implements a mock Google AI Studio (Gemini) API server for integration testing.
// It responds to POST /v1beta/models/{model}:generateContent with the same headers
// and JSON body structure that the real Gemini API returns.
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

const generateContentResponse = `{
  "candidates": [
    {
      "content": {
        "parts": [
          {
            "text": "eBPF (extended Berkeley Packet Filter) is a technology that allows running sandboxed programs in the Linux kernel without changing kernel source code. It enables efficient observability, networking, and security use cases by attaching custom logic to kernel events."
          }
        ],
        "role": "model"
      },
      "finishReason": "STOP",
      "safetyRatings": [
        {
          "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
          "probability": "NEGLIGIBLE"
        }
      ]
    }
  ],
  "usageMetadata": {
    "promptTokenCount": 12,
    "candidatesTokenCount": 45,
    "totalTokenCount": 57
  },
  "modelVersion": "gemini-2.0-flash",
  "responseId": "resp_abc123def456"
}`

const systemInstructionResponse = `{
  "candidates": [
    {
      "content": {
        "parts": [
          {
            "functionCall": {
              "name": "get_weather",
              "args": {
                "location": "San Francisco"
              }
            }
          }
        ],
        "role": "model"
      },
      "finishReason": "STOP"
    }
  ],
  "usageMetadata": {
    "promptTokenCount": 28,
    "candidatesTokenCount": 8,
    "totalTokenCount": 36
  },
  "modelVersion": "gemini-2.0-flash",
  "responseId": "resp_sys789ghi012"
}`

const errorResponse = `{
  "error": {
    "code": 404,
    "message": "models/gemini-nonexistent is not found for API version v1beta, or is not supported for generateContent.",
    "status": "NOT_FOUND"
  }
}`

func handleGenerateContent(w http.ResponseWriter, r *http.Request) {
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

	if _, ok := req["contents"]; !ok {
		http.Error(w, "contents field is required", http.StatusBadRequest)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("X-Goog-Api-Client", "genai-go/1.0.0")
	h.Set("X-Gemini-Service-Tier", "default")

	if strings.Contains(r.URL.Path, "gemini-nonexistent") {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(errorResponse))
		return
	}

	if _, ok := req["systemInstruction"]; ok {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(systemInstructionResponse))
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(generateContentResponse))
}

func main() {
	port := os.Getenv("GEMINI_PORT")
	if port == "" {
		port = "8083"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1beta/models/", handleGenerateContent)

	addr := ":" + port
	log.Printf("mock Gemini server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
