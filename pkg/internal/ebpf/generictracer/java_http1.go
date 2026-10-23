// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// Older kernels reject unknown atomic encodings before eliminating branches
// behind a false feature constant. Remove this feature's unreachable CMPXCHG
// instructions as well as setting g_bpf_java_http1_enabled to false.
func disableJavaHTTP1Atomics(spec *ebpf.CollectionSpec) {
	for _, program := range spec.Programs {
		for n, instruction := range program.Instructions {
			if instruction.OpCode.AtomicOp() == asm.CmpXchg {
				program.Instructions[n] = asm.Mov.Imm(asm.R0, -1).WithMetadata(instruction.Metadata)
			}
		}
	}
}
