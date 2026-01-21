// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <shared/obi_ctx.h>

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("kprobe")
static __always_inline void __dummy() {
}
