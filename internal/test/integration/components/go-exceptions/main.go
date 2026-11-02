// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

var errSentinel = errors.New("sentinel")

type store struct{ name string }

// Name faults on its first instruction when s is nil.
//
//go:noinline
func (s *store) Name() string { return s.name }

func writeResponse(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	_, _ = fmt.Fprintln(w, message)
}

// serveCase serves /case/<name>/<id>. Messages carry the id, so that a test
// can tell the records of each request apart.
func serveCase(w http.ResponseWriter, r *http.Request) {
	// strings.Cut needs Go 1.18, and the fixture builds with Go 1.17
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/case/"), "/", 2)
	name, id := parts[0], ""
	if len(parts) == 2 {
		id = parts[1]
	}
	if name != "panic-nethttp" {
		defer func() {
			if value := recover(); value != nil {
				writeResponse(w, http.StatusInternalServerError, fmt.Sprint(value))
			}
		}()
	}

	var err error
	switch name {
	case "healthy":
		writeResponse(w, http.StatusOK, "")
		return
	case "fmt":
		err = fmt.Errorf("fmt:%s", id)
	case "fmt-wrap":
		err = fmt.Errorf("wrap:%s: %w", id, errSentinel)
	case "sentinel":
		err = errSentinel
	case "handled-fmt":
		err = fmt.Errorf("handled:%s", id)
		writeResponse(w, http.StatusOK, err.Error())
		return
	case "child-fmt":
		result := make(chan error)
		go func() { result <- fmt.Errorf("child:%s", id) }()
		err = <-result
	case "panic-string", "panic-nethttp":
		panic("panic:" + id)
	case "panic-after-write":
		w.WriteHeader(http.StatusAccepted)
		panic("panic:" + id)
	case "panic-nil-pointer":
		var value *string
		panic(*value) //nolint:govet // Exercises the runtime nil-pointer panic path.
	case "panic-nil-receiver":
		var s *store
		_ = s.Name()
	default:
		http.NotFound(w, r)
		return
	}
	writeResponse(w, http.StatusInternalServerError, err.Error())
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/case/", serveCase)
	log.Fatal(http.ListenAndServe(os.Getenv("LISTEN_ADDR"), mux))
}
