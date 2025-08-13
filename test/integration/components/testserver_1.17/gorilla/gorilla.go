// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gorilla

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"go.opentelemetry.io/obi/test/integration/components/testserver_1.17/std"
)

func Setup(port, stdPort int) {
	r := mux.NewRouter()
	r.PathPrefix("/").HandlerFunc(std.HTTPHandler(stdPort))

	address := fmt.Sprintf(":%d", port)
	fmt.Printf("starting HTTP server at address %s\n", address)
	err := http.ListenAndServe(address, r)
	fmt.Printf("HTTP server has unexpectedly stopped %w\n", err)
}
