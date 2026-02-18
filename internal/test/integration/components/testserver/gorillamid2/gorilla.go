// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gorillamid2 // import "go.opentelemetry.io/obi/internal/test/integration/components/testserver/gorillamid2"

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"

	"go.opentelemetry.io/obi/internal/test/integration/components/testserver/std"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("I'm authenticating this request\n")
		next.ServeHTTP(w, r.WithContext(r.Context()))
	})
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("I'm logging this request\n")
		next.ServeHTTP(w, r.WithContext(r.Context()))
	})
}

func Setup(port, stdPort int) {
	log := slog.With("component", "gorilla.Server")
	r := mux.NewRouter()
	var handler http.Handler
	handler = std.HTTPHandler(log, stdPort)
	handler = AuthMiddleware(handler)
	handler = LoggingMiddleware(handler)
	r.PathPrefix("/").Handler(handler)

	address := fmt.Sprintf(":%d", port)
	log.Info("starting HTTP server with middleware", "address", address)
	err := http.ListenAndServe(address, handler)
	log.Error("HTTP server has unexpectedly stopped", "error", err)
}
