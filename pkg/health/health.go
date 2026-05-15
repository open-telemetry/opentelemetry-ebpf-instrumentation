// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package health exposes a watchdog-style health endpoint for OBI.
//
// Each long-running subsystem registers a name and receives a Tick function
// that it must call from inside its own work-loop select. A parent supervisor
// polls /healthz, compares now_unix_ns to each subsystem's last_tick_unix_ns,
// and decides on its own threshold whether OBI is stuck.
package health // import "go.opentelemetry.io/obi/pkg/health"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// Path is the URL path served by the health endpoint.
	Path = "/healthz"

	schemaVersion = 1
)

func log() *slog.Logger {
	return slog.With("component", "health")
}

type subsystem struct {
	enabled    bool
	tickCount  atomic.Uint64
	lastTickNs atomic.Int64
}

// Tracker holds per-subsystem heartbeat state. It is safe for concurrent use.
type Tracker struct {
	mu    sync.RWMutex
	subs  map[string]*subsystem
	start time.Time
}

// NewTracker builds an empty tracker.
func NewTracker() *Tracker {
	return &Tracker{
		subs:  make(map[string]*subsystem),
		start: time.Now(),
	}
}

// Register declares a subsystem and returns its tick function.
//
// When enabled is false the subsystem still appears in the JSON output (with
// enabled:false) so the supervisor sees a stable schema across configurations,
// but the returned tick is a no-op.
//
// The returned tick is safe for concurrent use; one atomic add + one atomic
// store per call, no allocations.
func (t *Tracker) Register(name string, enabled bool) func() {
	t.mu.Lock()
	defer t.mu.Unlock()

	s, ok := t.subs[name]
	if !ok {
		s = &subsystem{enabled: enabled}
		t.subs[name] = s
	}

	if !enabled {
		return func() {}
	}

	return func() {
		s.tickCount.Add(1)
		s.lastTickNs.Store(time.Now().UnixNano())
	}
}

type snapshot struct {
	Enabled        bool   `json:"enabled"`
	TickCount      uint64 `json:"tick_count"`
	LastTickUnixNs int64  `json:"last_tick_unix_ns"`
}

type response struct {
	SchemaVersion   int                 `json:"schema_version"`
	NowUnixNs       int64               `json:"now_unix_ns"`
	ProcessUptimeNs int64               `json:"process_uptime_ns"`
	Subsystems      map[string]snapshot `json:"subsystems"`
}

// ServeHTTP emits the JSON snapshot. HTTP status is always 200; staleness is
// the supervisor's call, not OBI's.
func (t *Tracker) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	t.mu.RLock()

	subs := make(map[string]snapshot, len(t.subs))
	for name, s := range t.subs {
		subs[name] = snapshot{
			Enabled:        s.enabled,
			TickCount:      s.tickCount.Load(),
			LastTickUnixNs: s.lastTickNs.Load(),
		}
	}
	start := t.start

	t.mu.RUnlock()

	now := time.Now()
	resp := response{
		SchemaVersion:   schemaVersion,
		NowUnixNs:       now.UnixNano(),
		ProcessUptimeNs: now.Sub(start).Nanoseconds(),
		Subsystems:      subs,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(&resp)
}

// TickEvery invokes beat at the given interval until ctx is cancelled. It is
// the canonical "agent-level" heartbeat source: subsystem agents run this in
// their own goroutine so a stalled scheduler or a panicked agent stops ticks.
func TickEvery(ctx context.Context, beat func(), interval time.Duration) {
	if beat == nil {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			beat()
		}
	}
}

// ListenAndServe runs a standalone HTTP server exposing the tracker on the
// given port at Path, until ctx is cancelled. It mirrors the shutdown
// behavior of the existing Prometheus endpoint: on unexpected exit it sends
// SIGINT to the process for graceful shutdown instead of os.Exit.
func ListenAndServe(ctx context.Context, port int, t *Tracker) error {
	mux := http.NewServeMux()
	mux.Handle(Path, t)

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	l := log().With("port", port, "path", Path)
	l.Info("starting health endpoint")

	srvErr := make(chan error, 1)
	go func() {
		err := server.ListenAndServe()
		if !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
			return
		}
		srvErr <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			l.Warn("error closing health endpoint", "err", err)
		}
		return nil

	case err := <-srvErr:
		if err == nil {
			return nil
		}
		l.Error("health endpoint exited unexpectedly", "err", err)
		// match prommgr behavior: interrupt for graceful shutdown
		if kerr := syscall.Kill(os.Getpid(), syscall.SIGINT); kerr != nil {
			l.Error("unable to send SIGINT after health endpoint failure", "err", kerr)
		}
		return err
	}
}
