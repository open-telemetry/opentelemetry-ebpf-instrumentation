#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);   // the pid_tid
    __type(value, u64); // the req ptr
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} upstream_init_args SEC(".maps");
