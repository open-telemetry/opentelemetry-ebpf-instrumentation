// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gotracer

import (
	"log/slog"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
)

func TestDisableJavaHTTP1Atomics(t *testing.T) {
	spec, err := LoadBpf()
	require.NoError(t, err)
	var enabled bool
	require.NoError(t, spec.Variables["g_bpf_java_http1_enabled"].Get(&enabled))
	require.False(t, enabled, "Java reservations stay disabled in the Go tracer")
	atomics := 0
	for _, program := range spec.Programs {
		for _, instruction := range program.Instructions {
			if instruction.OpCode.AtomicOp() == asm.CmpXchg {
				atomics++
			}
		}
	}
	require.Positive(t, atomics, "Go includes the shared HTTP parser's Java reservation instructions")
	previous := ebpfcommon.SupportsJavaHTTP1ReservationCleanup
	previousPropagation := supportsContextPropagationWithProbe
	t.Cleanup(func() {
		ebpfcommon.SupportsJavaHTTP1ReservationCleanup = previous
		supportsContextPropagationWithProbe = previousPropagation
	})
	ebpfcommon.SupportsJavaHTTP1ReservationCleanup = func() bool { return false }
	supportsContextPropagationWithProbe = func(*slog.Logger) bool { return false }
	tracer := &Tracer{cfg: &config.EBPFTracer{}, log: slog.Default()}
	bundles, err := tracer.LoadSpecs()
	require.NoError(t, err)
	require.Len(t, bundles, 1)
	for name, program := range bundles[0].Spec.Programs {
		for _, instruction := range program.Instructions {
			require.NotEqual(t, asm.CmpXchg, instruction.OpCode.AtomicOp(), name)
		}
	}
}
