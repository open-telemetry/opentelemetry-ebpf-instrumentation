// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"

import (
	"errors"

	"github.com/cilium/ebpf"
)

var ErrTracerTerminated = errors.New("flow tracer terminated")

const (
	// DirectionUnset is a convenience value to specify an unset/removed direction field
	DirectionUnset = 0xFF
	// DirectionIngress and DirectionEgress values according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
	DirectionIngress = 0
	DirectionEgress  = 1

	// InitiatorSrc and InitiatorDst values set accordingly to flows_common.h definition
	InitiatorSrc = 1
	InitiatorDst = 2

	InterfaceUnset = 0xFFFFFFFF
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
