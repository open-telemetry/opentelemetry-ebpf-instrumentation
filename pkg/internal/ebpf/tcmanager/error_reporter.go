// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tcmanager // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tcmanager"

import "sync"

const errorBufferLen = 16

type errorReporter struct {
	// mutex prevents close from racing with a send to ch.
	mutex  sync.RWMutex
	ch     chan error
	closed bool
}

func newErrorReporter() errorReporter {
	return errorReporter{ch: make(chan error, errorBufferLen)}
}

func (r *errorReporter) enqueue(err error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	if r.closed {
		return
	}

	select {
	case r.ch <- err:
	default:
	}
}

func (r *errorReporter) close() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.closed {
		return
	}

	r.closed = true
	close(r.ch)
}
