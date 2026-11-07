// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// tpclient-go is the Go hop of the tpclient chain for large HTTP/1 headers:
// it receives a request with a large cookie and forwards one to UPSTREAM.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const (
	largeCookieBytes = 12 * 1024
	spanIDStep       = 0x10
)

var largeCookie = "session=" + strings.Repeat("a", largeCookieBytes)

// hop is what each service of the chain reports about the request it received.
type hop struct {
	Service      string          `json:"service"`
	Traceparents []string        `json:"traceparents"`
	Downstream   json.RawMessage `json:"downstream,omitempty"`
}

func main() {
	upstream := os.Getenv("UPSTREAM")
	if upstream == "" {
		log.Fatal("UPSTREAM is required")
	}

	http.HandleFunc("/smoke", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/large-tp", func(w http.ResponseWriter, r *http.Request) {
		forward(w, r, upstream, true)
	})
	http.HandleFunc("/large-no-tp", func(w http.ResponseWriter, r *http.Request) {
		forward(w, r, upstream, false)
	})

	log.Fatal(http.ListenAndServe(":6003", nil))
}

func forward(w http.ResponseWriter, r *http.Request, upstream string, withTraceparent bool) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upstream+r.URL.Path, http.NoBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// net/http writes headers sorted by name, so the cookie goes out before the traceparent
	req.Header.Set("Cookie", largeCookie)
	if withTraceparent {
		traceparent, err := nextTraceparent(r.Header.Get("Traceparent"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req.Header.Set("Traceparent", traceparent)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	received := hop{Service: "go", Traceparents: r.Header.Values("Traceparent")}
	if err := json.NewDecoder(resp.Body).Decode(&received.Downstream); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(received); err != nil {
		log.Printf("writing response: %v", err)
	}
}

// nextTraceparent keeps the trace and advances the span ID, like a real client span would.
func nextTraceparent(traceparent string) (string, error) {
	parts := strings.Split(traceparent, "-")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid traceparent %q", traceparent)
	}
	spanID, err := strconv.ParseUint(parts[2], 16, 64)
	if err != nil {
		return "", fmt.Errorf("invalid traceparent span ID %q: %w", parts[2], err)
	}
	parts[2] = fmt.Sprintf("%016x", spanID+spanIDStep)
	return strings.Join(parts, "-"), nil
}
