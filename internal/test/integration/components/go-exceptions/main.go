// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"
)

var errSentinel = errors.New("sentinel")

type store struct{ name string }

// Name faults on its first instruction when s is nil.
//
//go:noinline
func (s *store) Name() string { return s.name }

func panicMappedFile() {
	file, err := os.CreateTemp("", "go-exceptions-mapped-*")
	if err != nil {
		panic(err)
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := file.Truncate(int64(os.Getpagesize())); err != nil {
		panic(err)
	}
	data, err := syscall.Mmap(int(file.Fd()), 0, os.Getpagesize(), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := syscall.Munmap(data); err != nil {
			log.Printf("unmap panic fixture: %v", err)
		}
	}()
	if err := file.Truncate(0); err != nil {
		panic(err)
	}

	// Accessing the truncated mapping raises a recoverable errorAddressString.
	previous := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(previous)
	panic(data[0])
}

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
	case "goexit":
		writeResponse(w, http.StatusOK, "ready")
		w.(http.Flusher).Flush()
		for {
			if _, err := os.Stat("/tmp/goexit-release"); err == nil {
				runtime.Goexit()
			}
			time.Sleep(10 * time.Millisecond)
		}
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
	case "panic-divide":
		zero := 0
		panic(1 / zero)
	case "panic-nil-channel":
		var ch chan int
		close(ch)
	case "panic-mapped-file":
		panicMappedFile()
	case "panic-index":
		items := []int{1, 2, 3}
		index := 5
		panic(items[index])
	case "panic-slice":
		items := []int{1, 2, 3}
		end := 5
		panic(items[:end])
	case "panic-slice-three-index":
		items := []int{1, 2, 3}
		limit := 5
		panic(items[0:1:limit])
	case "panic-slice-conversion":
		items := []int{1, 2, 3}
		panic((*[5]int)(items))
	case "panic-standard-error":
		panic(errors.New("boom"))
	case "panic-int":
		panic(5)
	case "panic-int8":
		panic(int8(-128))
	case "panic-uint64":
		panic(^uint64(0))
	case "panic-bool":
		panic(true)
	case "panic-wrapped-error":
		panic(fmt.Errorf("failed: %w", errSentinel))
	case "panic-multiple-errors":
		panic(fmt.Errorf("%w and %w", errSentinel, errors.New("second")))
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
