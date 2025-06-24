#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#define SCRATCH_MEM_TYPED(NAME, TYPE)                                                              \
    struct {                                                                                       \
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                                                   \
        __type(key, u32);                                                                          \
        __type(value, TYPE);                                                                       \
        __uint(max_entries, 1);                                                                    \
    } NAME##_storage SEC(".maps");                                                                 \
                                                                                                   \
    static __always_inline TYPE *NAME##_mem(void) {                                                \
        return bpf_map_lookup_elem(&NAME##_storage, &(u32){0});                                    \
    }

#define SCRATCH_MEM(NAME) SCRATCH_MEM_TYPED(NAME, NAME)
