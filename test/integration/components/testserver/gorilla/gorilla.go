// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gorilla

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"

	"go.opentelemetry.io/obi/test/integration/components/testserver/std"
)

func Setup(port, stdPort int) {
	log := slog.With("component", "gorilla.Server")
	r := mux.NewRouter()
	r.PathPrefix("/").HandlerFunc(std.HTTPHandler(log, stdPort))

	address := fmt.Sprintf(":%d", port)
	log.Info("starting HTTP server", "address", address)
	err := http.ListenAndServe(address, r)
	log.Error("HTTP server has unexpectedly stopped", "error", err)
}
