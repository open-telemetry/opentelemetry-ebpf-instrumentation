// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"errors"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
)

// ratioKeySpace is the number of TraceIDRatioBased keys: the 63 bits left of a
// trace id's last 8 bytes once the OpenTelemetry Go SDK shifts them right by one
const ratioKeySpace = 1 << 63

// pidSampler returns the pid_samplers entry (bpf/maps/pid_samplers.h) of a
// process with the service's sampler, or the global one when it has none. The
// default parentbased_always_on needs no entry.
func pidSampler(service, global *services.SamplerConfig) (BpfSamplerT, bool) {
	cfg := service
	if cfg == nil {
		cfg = global
	}
	if cfg == nil {
		return BpfSamplerT{}, false
	}

	ratio, parentBased := cfg.TraceIDRatio()
	if parentBased && ratio >= 1 {
		return BpfSamplerT{}, false
	}

	sampler := BpfSamplerT{Threshold: ratioThreshold(ratio)}
	if parentBased {
		sampler.ParentBased = 1
	}

	return sampler, true
}

// ratioThreshold is the threshold of the OpenTelemetry Go SDK TraceIDRatioBased sampler
func ratioThreshold(ratio float64) uint64 {
	switch {
	case ratio >= 1:
		return ratioKeySpace
	case ratio <= 0:
		return 0
	default:
		return uint64(ratio * ratioKeySpace)
	}
}

// WritePIDSampler sets the sampler eBPF applies to the traces the process starts
func WritePIDSampler(m *ebpf.Map, pid app.PID, service, global *services.SamplerConfig) error {
	sampler, ok := pidSampler(service, global)
	if !ok {
		return DeletePIDSampler(m, pid)
	}

	return m.Put(uint32(pid), sampler)
}

// DeletePIDSampler leaves the process with the default sampler
func DeletePIDSampler(m *ebpf.Map, pid app.PID) error {
	if err := m.Delete(uint32(pid)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}

	return nil
}
