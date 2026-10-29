// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

// SetupExceptionPipelineTest exposes test fixtures to external-package pipeline
// tests, which import the exporter and cannot share this package without a cycle.
func SetupExceptionPipelineTest(t *testing.T, now func() time.Duration) {
	t.Helper()
	registerTestExceptionDecoder(t)
	previousClock, previousPIDs := pidsFilterMonoNow, readNamespacePIDs
	pidsFilterMonoNow = now
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		return []app.PID{pid}, nil
	}
	t.Cleanup(func() {
		pidsFilterMonoNow, readNamespacePIDs = previousClock, previousPIDs
	})
}
