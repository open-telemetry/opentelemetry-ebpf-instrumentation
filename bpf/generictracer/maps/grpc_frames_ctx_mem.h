#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <generictracer/types/grpc_frames_ctx.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, grpc_frames_ctx_t);
    __uint(max_entries, 1);
} grpc_frames_ctx_mem SEC(".maps");
