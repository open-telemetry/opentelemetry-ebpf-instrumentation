// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>

#include <common/sampler.h>
#include <common/tp_info.h>

#include <maps/pid_samplers.h>

#include <pid/pid.h>

// The key the OpenTelemetry Go SDK TraceIDRatioBased sampler compares with its
// threshold: the trace id's last 8 bytes, big endian, shifted right by one
static __always_inline u64 trace_id_ratio_key(const unsigned char *trace_id) {
    u64 low = 0;
    __builtin_memcpy(&low, trace_id + TRACE_ID_SIZE_BYTES - sizeof(low), sizeof(low));

    return bpf_be64_to_cpu(low) >> 1;
}

static __always_inline const sampler_t *current_sampler(void) {
    const u32 pid = obi_pid(bpf_get_current_pid_tgid());

    return bpf_map_lookup_elem(&pid_samplers, &pid);
}

static __always_inline u8 sampler_decision(const sampler_t *sampler, const tp_info_t *tp) {
    return trace_id_ratio_key(tp->trace_id) < sampler->threshold ? k_flag_sampled : 0;
}

// A trace this process starts takes its sampler's decision
static __always_inline void sample_new_trace(tp_info_t *tp) {
    const sampler_t *sampler = current_sampler();

    tp->flags = sampler ? sampler_decision(sampler, tp) : k_flag_sampled;
}

// A span continuing a trace from another process keeps the parent's decision
// under a parent based sampler, and takes its own otherwise
static __always_inline void sample_remote_child(tp_info_t *tp) {
    const sampler_t *sampler = current_sampler();
    if (!sampler || sampler->parent_based) {
        return;
    }

    tp->flags = (u8)(tp->flags & ~k_flag_sampled) | sampler_decision(sampler, tp);
}
