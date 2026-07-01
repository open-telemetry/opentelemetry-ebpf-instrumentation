// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// HTTP server emitting USDT probes via salp (libstapsdt-backed). Mirrors the
// other custom_span_* samples so the integration test exercises auto-discover
// against a runtime-generated .so produced from Go too.
//
// processOrder is a top-level //go:noinline function so OBI can attach a
// Go function-mode span at main.processOrder. The function_span attach
// uses per-RET uprobes (not kernel uretprobe) to avoid corrupting Go's
// stack — see pkg/ebpf/instrumenter.go and pkg/ebpf/usdt.go.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/mmcshane/salp"
)

var (
	orderStart *salp.Probe
	orderEnd   *salp.Probe
	cacheHit   *salp.Probe
)

//go:noinline
func processOrder(id uint64, customer string) {
	orderStart.Fire(id, customer)
	time.Sleep(20 * time.Millisecond)
	orderEnd.Fire(id, int32(0))
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8394"
	}

	provider := salp.NewProvider("custom_span_go")
	orderStart = salp.MustAddProbe(provider, "order_start", salp.Uint64, salp.String)
	orderEnd = salp.MustAddProbe(provider, "order_end", salp.Uint64, salp.Int32)
	cacheHit = salp.MustAddProbe(provider, "cache_hit", salp.String)
	if err := provider.Load(); err != nil {
		log.Fatalf("provider.Load: %v", err)
	}

	http.HandleFunc("/smoke", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	http.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseUint(r.URL.Query().Get("id"), 10, 64)
		if id == 0 {
			id = 1
		}
		customer := r.URL.Query().Get("customer")
		if customer == "" {
			customer = "anonymous"
		}
		processOrder(id, customer)
		_, _ = w.Write([]byte("ok"))
	})

	http.HandleFunc("/cache", func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		if key == "" {
			key = "default"
		}
		cacheHit.Fire(key)
		_, _ = w.Write([]byte("ok"))
	})

	fmt.Fprintf(os.Stderr, "custom_span_go listening on :%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
