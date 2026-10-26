// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"log/slog"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestDisableJavaHTTP1Atomics(t *testing.T) {
	spec, err := LoadBpf()
	require.NoError(t, err)
	atomics := 0
	for _, program := range spec.Programs {
		for _, instruction := range program.Instructions {
			if instruction.OpCode.AtomicOp() == asm.CmpXchg {
				atomics++
			}
		}
	}
	require.Positive(t, atomics, "generated programs contain the reservation ownership instructions")
	previous := ebpfcommon.SupportsJavaHTTP1ReservationCleanup
	t.Cleanup(func() { ebpfcommon.SupportsJavaHTTP1ReservationCleanup = previous })
	ebpfcommon.SupportsJavaHTTP1ReservationCleanup = func() bool { return false }
	tracer := &Tracer{cfg: &obi.Config{}, log: slog.Default()}
	tracer.cfg.EBPF.ContextPropagation = config.ContextPropagationHeaders
	bundles, err := tracer.LoadSpecs()
	require.NoError(t, err)
	require.Len(t, bundles, 1)
	require.False(t, bundles[0].Constants["g_bpf_java_http1_enabled"].(bool))
	for name, program := range bundles[0].Spec.Programs {
		for _, instruction := range program.Instructions {
			require.NotEqual(t, asm.CmpXchg, instruction.OpCode.AtomicOp(), name)
		}
	}
}
