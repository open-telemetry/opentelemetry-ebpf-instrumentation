// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>
#include <common/trace_lifecycle.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, client_trace_publication_transaction_t);
    __uint(max_entries, 1);
    __uint(pinning, OBI_PIN_INTERNAL);
} client_trace_publication_mem SEC(".maps");

static __always_inline client_trace_publication_transaction_t *
client_trace_publication_transaction_mem(void) {
    return bpf_map_lookup_elem(&client_trace_publication_mem, &(u32){0});
}
