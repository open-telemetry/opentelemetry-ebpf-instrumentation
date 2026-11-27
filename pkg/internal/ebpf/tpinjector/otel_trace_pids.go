// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tpinjector // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
)

// Packed states match bpf/tpinjector/maps/otel_traces_pids.h.
const (
	otelPIDUnknown uint64 = iota
	otelPIDNonExporter
	otelPIDExporter
)

const (
	otelPIDBits             = 2
	otelPIDsPerWord         = 64 / otelPIDBits
	otelPIDWords            = ebpfcommon.PIDBitmapWords * otelPIDBits
	otelPIDStateMask uint64 = (1 << otelPIDBits) - 1
)

type otelTracePIDs struct {
	mu    sync.Mutex
	words []uint64
}

func (p *otelTracePIDs) exporter(pid app.PID) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	word := uint64(pid) / otelPIDsPerWord
	return word < uint64(len(p.words)) &&
		p.words[word]>>((pid%otelPIDsPerWord)*otelPIDBits)&otelPIDStateMask == otelPIDExporter
}

func (p *otelTracePIDs) set(m *ebpf.Map, pid app.PID, state uint64) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	word := uint32(pid / otelPIDsPerWord)
	if word >= otelPIDWords {
		return fmt.Errorf("pid %d is beyond the BPF exporter classification", pid)
	}
	if p.words == nil {
		p.words = make([]uint64, otelPIDWords)
	}

	shift := (pid % otelPIDsPerWord) * otelPIDBits
	states := p.words[word]&^(otelPIDStateMask<<shift) | state<<shift
	if states == p.words[word] {
		return nil
	}
	if err := m.Put(word, states); err != nil {
		return fmt.Errorf("writing word %d of the BPF exporter classification: %w", word, err)
	}
	p.words[word] = states
	return nil
}
