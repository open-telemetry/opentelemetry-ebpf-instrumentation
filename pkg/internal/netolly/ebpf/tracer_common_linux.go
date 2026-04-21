// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"

import (
	"github.com/cilium/ebpf"
)

// lookupPacketStats is a common function called by LookupPacketStats().
// Returns ErrTracerTerminated after Close().
func lookupPacketStats(m *ebpf.Map) (NetPacketCount, error) {
	if m == nil {
		return NetPacketCount{}, ErrTracerTerminated
	}
	var perCPUCounts []NetPacketCount
	if err := m.Lookup(uint32(0), &perCPUCounts); err != nil {
		return NetPacketCount{}, err
	}
	var sum NetPacketCount
	for _, pc := range perCPUCounts {
		sum.Total += pc.Total
		sum.Ignored += pc.Ignored
	}
	return sum, nil
}
