// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf_test

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"
)

func TestSharedMapsAcrossTracersArePinnedAndCompatible(t *testing.T) {
	genericSpec, err := generictracer.LoadBpf()
	require.NoError(t, err)
	goSpec, err := gotracer.LoadBpf()
	require.NoError(t, err)
	tpSpec, err := tpinjector.LoadBpf()
	require.NoError(t, err)

	specs := []struct {
		name string
		spec *ebpf.CollectionSpec
	}{
		{name: "generictracer", spec: genericSpec},
		{name: "gotracer", spec: goSpec},
		{name: "tpinjector", spec: tpSpec},
	}

	type mapOccurrence struct {
		tracer string
		spec   *ebpf.MapSpec
	}

	byName := make(map[string][]mapOccurrence)
	for _, s := range specs {
		for name, m := range s.spec.Maps {
			if strings.HasPrefix(name, ".") {
				continue
			}
			// PerCPUArray scratch buffers stay private per tracer to avoid preemption
			// races between kprobes and uprobes; ProgramArray tail-call tables are per-ELF.
			if m.Type == ebpf.PerCPUArray || m.Type == ebpf.ProgramArray {
				continue
			}
			byName[name] = append(byName[name], mapOccurrence{tracer: s.name, spec: m})
		}
	}

	for name, occurrences := range byName {
		if len(occurrences) < 2 {
			continue
		}

		first := occurrences[0]
		for _, occ := range occurrences {
			assert.True(t,
				occ.spec.Pinning == ebpfconvenience.PinInternal || occ.spec.Pinning == ebpf.PinByName,
				"shared map %s in %s must be pinned (OBI_PIN_INTERNAL or LIBBPF_PIN_BY_NAME), got pinning=%d",
				name, occ.tracer, occ.spec.Pinning)
			assert.Equal(t, first.spec.Type, occ.spec.Type, "shared map %s type mismatch (%s vs %s)", name, first.tracer, occ.tracer)
			assert.Equal(t, first.spec.KeySize, occ.spec.KeySize, "shared map %s key size mismatch (%s vs %s)", name, first.tracer, occ.tracer)
			assert.Equal(t, first.spec.ValueSize, occ.spec.ValueSize, "shared map %s value size mismatch (%s vs %s)", name, first.tracer, occ.tracer)
			assert.Equal(t, first.spec.MaxEntries, occ.spec.MaxEntries, "shared map %s max entries mismatch (%s vs %s)", name, first.tracer, occ.tracer)
			assert.Equal(t, first.spec.Flags, occ.spec.Flags, "shared map %s flags mismatch (%s vs %s)", name, first.tracer, occ.tracer)
			assert.Equal(t, first.spec.Pinning, occ.spec.Pinning, "shared map %s pinning mismatch (%s vs %s)", name, first.tracer, occ.tracer)
		}
	}
}
