// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"sync"
	"testing"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/transform/route"
)

// TestHarvestedRouteMatcherRace reproduces the race described in
// https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2026
//
// The race is between:
//   - a time.AfterFunc goroutine (simulated here) writing svc.Attrs.routeMatcher
//     via SetHarvestedRoutes on the original *svc.Attrs
//   - PIDsFilter.Filter reading *info.service (dereferencing the same pointer) to copy
//     the struct into a span
//
// Run with: go test -race ./pkg/ebpf/common/... -run TestHarvestedRouteMatcherRace
func TestHarvestedRouteMatcherRace(t *testing.T) {
	// service simulates ie.FileInfo.Service — the *svc.Attrs pointer that attacher
	// stores in the PIDsFilter and that the AfterFunc callback later writes to.
	// InitHarvestedRoutes is called here just as the attacher does it before
	// registering the service with the PIDsFilter.
	service := &svc.Attrs{UID: svc.UID{Name: "java-svc", Namespace: "ns"}}
	service.InitHarvestedRoutes()

	// Override readNamespacePIDs so AllowPID doesn't try to read /proc.
	orig := readNamespacePIDs
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) { return []app.PID{pid}, nil }
	defer func() { readNamespacePIDs = orig }()

	pf := NewPIDsFilter(
		&services.DiscoveryConfig{},
		nil,
		imetrics.NoopReporter{},
	)
	// AllowPID stores &service into pf.current[ns][pid].service — same pointer.
	pf.AllowPID(1, 1, service, PIDTypeKProbes)

	// Fake incoming spans whose PID matches the registered entry.
	makeSpans := func() []request.Span {
		return []request.Span{{Pid: request.PidInfo{UserPID: 1, Namespace: 1}}}
	}

	const iters = 5_000
	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: simulates the time.AfterFunc callback that calls SetHarvestedRoutes
	// on the original *svc.Attrs after the Java harvest delay.
	go func() {
		defer wg.Done()
		m := route.NewMatcher([]string{"/api/{id}"})
		for i := 0; i < iters; i++ {
			service.SetHarvestedRoutes(m) // write to *svc.Attrs.HarvestedRouteMatcher
		}
	}()

	// Goroutine 2: simulates the hot-path eBPF span reader calling Filter,
	// which dereferences *info.service (= &service above) to copy into each span.
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			pf.Filter(makeSpans()) // reads *info.service including routeMatcher
		}
	}()

	wg.Wait()
}
