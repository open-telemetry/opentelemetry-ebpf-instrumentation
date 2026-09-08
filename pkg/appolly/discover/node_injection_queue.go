// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"log/slog"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

// nodeInjectionQueueLen bounds how many discovered Node.js processes can wait
// for injection. A dropped target loses trace-context propagation and runtime
// metrics for that process, nothing else.
const nodeInjectionQueueLen = 100

// nodeInjectionQueue performs Node.js agent injections on a single worker
// goroutine, off the discovery loop.
//
// Injection waits on the target: for the runtime to install its own SIGUSR1
// handler, for the application's files to be searched for a handler of its
// own, and for the inspector to accept a connection. None of that may hold up
// process discovery.
type nodeInjectionQueue struct {
	log     *slog.Logger
	inject  func(app.PID)
	targets chan app.PID
	done    chan struct{}
	mu      sync.Mutex
	stopped bool
}

func newNodeInjectionQueue(log *slog.Logger, inject func(app.PID)) *nodeInjectionQueue {
	return &nodeInjectionQueue{
		log:     log,
		inject:  inject,
		targets: make(chan app.PID, nodeInjectionQueueLen),
		done:    make(chan struct{}),
	}
}

// start launches the worker. Targets are injected one at a time, in the order
// they were discovered.
func (q *nodeInjectionQueue) start(ctx context.Context) {
	go func() {
		defer close(q.done)
		defer q.stop()

		for {
			select {
			case <-ctx.Done():
				return
			case pid := <-q.targets:
				// A ready target and a cancelled context make both select
				// cases eligible. No new injection may start once shutdown
				// has begun.
				if ctx.Err() != nil {
					return
				}
				q.inject(pid)
			}
		}
	}()
}

func (q *nodeInjectionQueue) stop() {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.stopped = true
}

// enqueue never blocks: a slow injection holds the worker while process
// discovery keeps running.
func (q *nodeInjectionQueue) enqueue(pid app.PID) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.stopped {
		q.log.Debug("node injection queue stopped, skipping agent injection", "pid", pid)
		return
	}

	select {
	case q.targets <- pid:
	default:
		q.log.Warn("node injection queue is full, skipping agent injection", "pid", pid)
	}
}

// wait joins the worker.
func (q *nodeInjectionQueue) wait() {
	<-q.done
}
