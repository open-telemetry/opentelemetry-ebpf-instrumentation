// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/grafana/gomemcache/memcache"
)

const memcachedAddr = "memcached:11211"

func newClient() *memcache.Client {
	client := memcache.New(memcachedAddr)
	client.Timeout = 5 * time.Second
	client.ConnectTimeout = 5 * time.Second
	return client
}

func memcachedPath() ([]byte, error) {
	client := newClient()
	defer client.Close()

	if err := client.Set(&memcache.Item{Key: "session-key", Value: []byte("value"), Expiration: 300}); err != nil {
		return nil, err
	}

	item, err := client.Get("session-key")
	if err != nil {
		return nil, err
	}

	if err := client.Delete("session-key"); err != nil {
		return nil, err
	}

	return item.Value, nil
}

func memcachedErrorPath() {
	client := newClient()
	defer client.Close()

	// Trigger a CLIENT_ERROR by trying to increment a non-numeric value.
	// memcached responds: CLIENT_ERROR cannot increment or decrement non-numeric value
	if err := client.Set(&memcache.Item{Key: "error-key", Value: []byte("not-a-number"), Expiration: 300}); err != nil {
		return
	}

	_, _ = client.Increment("error-key", 1)
}

func memcachedNoreplyPath() error {
	conn, err := net.DialTimeout("tcp", memcachedAddr, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write([]byte("set touch-key 0 300 5 noreply\r\nvalue\r\ntouch touch-key 60 noreply\r\n"))
	return err
}

func writeResponse(rw http.ResponseWriter, body []byte) {
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(body)
}

func HTTPHandler(log *slog.Logger) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		log.Debug("received request", "url", req.RequestURI)

		switch req.URL.Path {
		case "/memcached":
			value, err := memcachedPath()
			if err != nil {
				log.Debug("memcached path failed", "error", err)
				rw.WriteHeader(http.StatusInternalServerError)
				return
			}
			writeResponse(rw, value)
		case "/memcached-error":
			memcachedErrorPath()
			writeResponse(rw, []byte("error triggered"))
		case "/memcached-noreply":
			if err := memcachedNoreplyPath(); err != nil {
				log.Debug("memcached noreply path failed", "error", err)
				rw.WriteHeader(http.StatusInternalServerError)
				return
			}
			writeResponse(rw, []byte("noreply triggered"))
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}
}

func main() {
	log := slog.With("component", "gomemcached")
	address := ":8080"
	log.Info("starting HTTP server", "address", address, "process_id", os.Getpid())
	err := http.ListenAndServe(address, HTTPHandler(log)) //nolint:gosec // test component, no timeouts needed
	log.Error("HTTP server has unexpectedly stopped", "error", err)
}
