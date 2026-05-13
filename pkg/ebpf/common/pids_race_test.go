// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"io"
	"log/slog"
	"sync"
	"testing"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/transform/route"
)

// TestHarvestedRouteMatcherRace verifies that concurrent calls to UpdateHarvestedRoutes
// and PIDsFilter.Filter do not race on svc.Attrs. Regression test for #2026.
func TestHarvestedRouteMatcherRace(_ *testing.T) {
	service := &svc.Attrs{UID: svc.UID{Name: "java-svc", Namespace: "ns"}}

	orig := readNamespacePIDs
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) { return []app.PID{pid}, nil }
	defer func() { readNamespacePIDs = orig }()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pf := NewPIDsFilter(
		&services.DiscoveryConfig{},
		logger,
		imetrics.NoopReporter{},
	)
	// AllowPID calls addPID which initialises the CoW atomic pointer on service.
	pf.AllowPID(1, 1, service, PIDTypeKProbes)

	makeSpans := func() []request.Span {
		return []request.Span{{Pid: request.PidInfo{UserPID: 1, Namespace: 1}}}
	}

	const iters = 5_000
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		m := route.NewMatcher([]string{"/api/{id}"})
		for i := 0; i < iters; i++ {
			service.SetHarvestedRoutes(m)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			pf.Filter(makeSpans())
		}
	}()

	wg.Wait()
}
