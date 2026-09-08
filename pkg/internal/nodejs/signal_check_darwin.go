// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import "debug/elf"

// isNodeRuntime is a no-op on non-Linux platforms.
func isNodeRuntime(_ int, _ *elf.File) bool {
	return true
}

// sigusr1Disposition is a no-op on non-Linux platforms.
func sigusr1Disposition(_ int) signalDisposition {
	return signalDispositionHandled
}

// hasUserSIGUSR1Handler is a no-op on non-Linux platforms.
func hasUserSIGUSR1Handler(_ int, _ *elf.File) signalCheckResult {
	return signalCheckNotFound
}

// sourceSIGUSR1Reference is a no-op on non-Linux platforms.
func sourceSIGUSR1Reference(_ int) sourceScanResult {
	return sourceScanClean
}
