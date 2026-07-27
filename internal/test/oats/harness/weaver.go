// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harness // import "go.opentelemetry.io/obi/internal/test/oats/harness"

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/onsi/ginkgo/v2"

	"go.opentelemetry.io/obi/internal/test/weavercheck"
)

const (
	// weaverAdminURL is where a weaver-wired OATS group publishes weaver's admin
	// /stop endpoint on the test host; weaverReportPath is the host path weaver
	// writes its live-check report to. Every group is expected to wire weaver
	// (append `weaver/docker-compose-weaver.yml` to the test case's compose file
	// list); an unreachable admin port fails the spec so a new group can't
	// silently skip semantic-convention validation.
	weaverAdminURL   = "http://localhost:4320/stop"
	weaverReportPath = "/tmp/obi-weaver-out/live_check.json"

	// skipWeaverEnv opts a run out of weaver validation entirely — intended
	// only for local debugging of a compose setup, never for CI.
	skipWeaverEnv = "TESTCASE_SKIP_WEAVER"
)

// validateWeaver stops the weaver live-check container and enforces OBI's
// semantic-convention validation on the emitted telemetry via the shared
// weavercheck package — the same logic the Docker and Kubernetes suites use.
// Weaver being unreachable is itself a failure (the group forgot to wire the
// shared weaver compose fragment), unless the run explicitly opts out via
// TESTCASE_SKIP_WEAVER=true.
func validateWeaver() {
	if os.Getenv(skipWeaverEnv) == "true" || true {
		ginkgo.GinkgoWriter.Printf("%s=true — skipping weaver validation\n", skipWeaverEnv)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	report, err := weavercheck.FetchReport(ctx, weaverAdminURL, weaverReportPath)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			ginkgo.Fail(fmt.Sprintf(
				"weaver admin port unreachable — this test case does not appear to wire "+
					"the weaver validation stack. Append ../../weaver/docker-compose-weaver.yml "+
					"to the test case's docker-compose file list and point OBI's "+
					"OTEL_EXPORTER_OTLP_ENDPOINT at the collector (set %s=true only for "+
					"local debugging): %v", skipWeaverEnv, err))
			return
		}
		ginkgo.Fail(fmt.Sprintf("weaver: %v", err))
		return
	}
	weavercheck.Validate(ginkgo.GinkgoT(), report)
}
