// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

type outgoingTraceHandoffReaper struct{}

type OutgoingTraceHandoffReaperStats struct {
	Scans                uint64
	Retired              uint64
	ClaimConflicts       uint64
	StuckClaimConflicts  uint64
	FullScans            uint64
	OldestAgeNanoseconds uint64
}

func (ctx *EBPFEventContext) StartOutgoingTraceHandoffReaper() func() {
	return func() {}
}

func (ctx *EBPFEventContext) NotifyOutgoingTraceHandoffMapsLoaded() {}

func (ctx *EBPFEventContext) StopOutgoingTraceHandoffReaper() {}

func (ctx *EBPFEventContext) OutgoingTraceHandoffReaperStats() OutgoingTraceHandoffReaperStats {
	return OutgoingTraceHandoffReaperStats{}
}
