// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Source: https://github.com/cilium/cilium/blob/e896ab6a0c4caf5cd7f394350dc68a2a2bf2bc9a/bpf/include/bpf/compiler.h

/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_COMPILER_H_
#define __BPF_COMPILER_H_

#ifndef __maybe_unused
#define __maybe_unused __attribute__((__unused__))
#endif

#ifndef __nobuiltin
#if __clang_major__ >= 10
#define __nobuiltin(X) __attribute__((no_builtin(X)))
#else
#define __nobuiltin(X)
#endif
#endif

#ifndef __throw_build_bug
#define __throw_build_bug() __builtin_trap()
#endif

#ifndef barrier
#define barrier() asm volatile("" : : : "memory")
#endif

#ifndef barrier_data
#define barrier_data(ptr) asm volatile("" : : "r"(ptr) : "memory")
#endif

// barrier_var makes the compiler treat var as an opaque value it can no longer
// reason about at compile time. Useful before masking a value into a verifier
// bound: without it the compiler may prove the mask is a no-op (because a prior
// clamp already bounded the value) and delete the AND, leaving the verifier with
// only a range fact that is lost across a stack spill/reload.
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var))
#endif

/* The LOAD_CONSTANT macro is used to define a named constant that will be replaced
 * at runtime by the Go code. This replaces usage of a bpf_map for storing values, which
 * eliminates a bpf_map_lookup_elem per kprobe hit. The constants are best accessed with a
 * dedicated inlined function.
 */
#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))

#endif /* __BPF_COMPILER_H_ */
