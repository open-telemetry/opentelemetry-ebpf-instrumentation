// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harness // import "go.opentelemetry.io/obi/internal/test/oats/harness"

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"

	"github.com/onsi/ginkgo/v2"

	"go.opentelemetry.io/obi/internal/test/weavercheck"
)

const (
	// weaverAdminURL is where a weaver-wired OATS group publishes weaver's admin
	// /stop endpoint on the test host; weaverReportPath is the host path weaver
	// writes its live-check report to. Groups that don't front lgtm with a
	// weaver-tapping collector have nothing listening here and are skipped.
	weaverAdminURL   = "http://localhost:4320/stop"
	weaverReportPath = "/tmp/obi-weaver-out/live_check.json"
)

// validateWeaver stops the weaver live-check container (if this group wired one
// in front of lgtm) and enforces OBI's semantic-convention validation on the
// emitted telemetry via the shared weavercheck package — the same logic the
// Docker and Kubernetes suites use. Groups without weaver are detected by the
// admin port being unreachable and skipped; any other failure fails the spec.
func validateWeaver() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	report, err := weavercheck.FetchReport(ctx, weaverAdminURL, weaverReportPath)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			// No weaver wired for this group — nothing to validate.
			return
		}
		ginkgo.Fail(fmt.Sprintf("weaver: %v", err))
		return
	}
	weavercheck.Validate(ginkgo.GinkgoT(), report)
}
