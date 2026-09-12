// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import "errors"

var (
	errProcessReplaced      = errors.New("process is no longer the one that was injected")
	errSignalWouldTerminate = errors.New("process has no SIGUSR1 handler, signaling it would terminate it")
)

// procCatchesSIGUSR1 is a no-op on non-Linux platforms.
func procCatchesSIGUSR1(_ int) bool { return false }

// procStartTime is a no-op on non-Linux platforms.
func procStartTime(_ int) uint64 { return 0 }

// signalInspectorOpen is a no-op on non-Linux platforms.
func signalInspectorOpen(_ int, _ uint64) error { return errProcessReplaced }
