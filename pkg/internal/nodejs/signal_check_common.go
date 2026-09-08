// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

type signalCheckResult int

const (
	signalCheckNotFound signalCheckResult = iota // no SIGUSR1 handler detected
	signalCheckFound                             // SIGUSR1 handler detected
	signalCheckFailed                            // detection failed (e.g. stripped symbols)
)

type sourceScanResult int

const (
	sourceScanClean       sourceScanResult = iota // scanned, no SIGUSR1 reference
	sourceScanFound                               // a SIGUSR1 reference was found
	sourceScanUnavailable                         // the application files could not be scanned
)

type signalDisposition int

const (
	signalDispositionUnknown signalDisposition = iota // the kernel's signal mask could not be read
	signalDispositionHandled                          // SIGUSR1 is caught or ignored, so it cannot terminate the process
	signalDispositionFatal                            // SIGUSR1 is neither caught nor ignored: the default action terminates
)
