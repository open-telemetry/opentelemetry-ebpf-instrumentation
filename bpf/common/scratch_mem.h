// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#define SCRATCH_MEM_SIZED(NAME, SIZE)                                                              \
    struct {                                                                                       \
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                                                   \
        __uint(key_size, sizeof(u32));                                                             \
        __uint(value_size, SIZE);                                                                  \
        __uint(max_entries, 1);                                                                    \
    } NAME##_storage SEC(".maps");                                                                 \
                                                                                                   \
    static __always_inline void *NAME##_mem(void) {                                                \
        return bpf_map_lookup_elem(&NAME##_storage, &(u32){0});                                    \
    }

#define SCRATCH_MEM_TYPED(NAME, TYPE) SCRATCH_MEM_SIZED(NAME, sizeof(TYPE))
#define SCRATCH_MEM(NAME) SCRATCH_MEM_TYPED(NAME, NAME)

#define SCRATCH_MEM_TYPED_PINNED(NAME, TYPE)                                                       \
    struct {                                                                                       \
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                                                   \
        __type(key, u32);                                                                          \
        __type(value, TYPE);                                                                       \
        __uint(max_entries, 1);                                                                    \
        __uint(pinning, OBI_PIN_INTERNAL);                                                         \
    } NAME##_storage SEC(".maps");                                                                 \
                                                                                                   \
    static __always_inline TYPE *NAME##_mem(void) {                                                \
        return bpf_map_lookup_elem(&NAME##_storage, &(u32){0});                                    \
    }
