// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tcmanager // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tcmanager"

import "sync"

const errorBufferLen = 16

type errorReporter struct {
	mutex  sync.RWMutex
	errors chan error
	closed bool
}

func newErrorReporter() errorReporter {
	return errorReporter{errors: make(chan error, errorBufferLen)}
}

func (r *errorReporter) channel() chan error {
	return r.errors
}

func (r *errorReporter) emit(err error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	if r.closed {
		return
	}

	select {
	case r.errors <- err:
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
	close(r.errors)
}
