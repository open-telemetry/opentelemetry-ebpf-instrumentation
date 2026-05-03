// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Minimal Go HTTP service used as a counterpart to the Node tpclient in the
// traceparent extraction integration tests. Three instances are chained
// (a -> b -> c).
//
// On the data-delivery side, the eBPF gotracer uses handle_light_weight_thread_buf
// (u_buf_is_user=1) to capture the raw HTTP bytes at netFdRead/netFdWrite.
// On the traceparent-extraction side, the readContinuedLineSlice uretprobe fires
// for each individual header line returned by the textproto reader, which lets OBI
// find the traceparent even when it is preceded by large headers — independently
// of how much data was buffered when the initial readMIMEHeader entry probe fired.
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// Args: route port [upstream]
//
// upstream is either a full base URL (e.g. http://localhost:8001) or empty
// when this is the last node of the chain.
func main() {
	if len(os.Args) < 3 {
		log.Fatalf("usage: %s route port [upstream]", os.Args[0])
	}
	route := os.Args[1]
	port := os.Args[2]
	var upstream string
	if len(os.Args) >= 4 {
		upstream = os.Args[3]
	}

	// Skip TLS verification on outgoing chained calls: the Node sibling uses
	// a self-signed cert and we are inside the same docker network.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/smoke", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/with-huge-tp", func(w http.ResponseWriter, r *http.Request) {
		if upstream == "" {
			fmt.Fprintf(w, "End of chain (%s)", route)
			return
		}
		downstream := upstream + "/with-huge-tp"
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, downstream, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Forward the incoming traceparent and re-add a large filler so the
		// eBPF chunked parser is exercised at every hop of the chain.
		if tp := r.Header.Get("traceparent"); tp != "" {
			req.Header.Set("traceparent", nextTraceparent(tp))
		}
		// Lower-case header name sorts before "Traceparent": net/http writes
		// headers in canonical order so the filler reaches the wire first.
		req.Header.Set("big-filler", strings.Repeat("X", 2500))

		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(w, "%s/with-huge-tp -> %s", route, string(body))
	})

	addr := ":" + port
	log.Printf("Service %s (Go) listening on %s, upstream=%q", strings.ToUpper(route), addr, upstream)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}
}

// nextTraceparent increments the span ID by 0x10 to mirror the Node service
// behavior. If the input does not parse it is returned unchanged so the
// downstream side still observes a traceparent (eBPF will then override the
// span ID via proxy detection, exactly as in the Node chain).
func nextTraceparent(tp string) string {
	parts := strings.Split(tp, "-")
	if len(parts) != 4 {
		return tp
	}
	span, err := strconv.ParseUint(parts[2], 16, 64)
	if err != nil {
		return tp
	}
	parts[2] = fmt.Sprintf("%016x", span+0x10)
	return strings.Join(parts, "-")
}
