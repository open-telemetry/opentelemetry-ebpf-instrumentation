// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/sampling_math.h>
#include <common/sampling_decision.h>
#include <common/tp_info.h>

#include <maps/samplers.h>

enum sampler_evaluation_result : s8 {
    k_sampler_evaluation_unavailable = -2,
    k_sampler_evaluation_error = -1,
    k_sampler_evaluation_drop = 0,
    k_sampler_evaluation_record = 1,
};

static __always_inline const sampler_config_t *sampler_config_for_process(const u32 host_tgid) {
    const sampler_config_t *config = bpf_map_lookup_elem(&sampler_overrides, &host_tgid);
    if (config) {
        return config;
    }

    const u32 zero = 0;
    return bpf_map_lookup_elem(&global_sampler_config, &zero);
}

static __always_inline u8 snapshot_sampler_readiness(const u32 host_tgid,
                                                     const u64 start_time,
                                                     process_readiness_t *snapshot) {
    const process_readiness_t *readiness = bpf_map_lookup_elem(&sampler_ready_pids, &host_tgid);
    if (!readiness) {
        return 0;
    }
    __builtin_memcpy(snapshot, readiness, sizeof(*snapshot));
    if (!snapshot->ready || !snapshot->epoch) {
        return 0;
    }
    return start_time ? process_incarnation_matches(snapshot->start_time, start_time)
                      : process_incarnation_matches_current(host_tgid, snapshot->start_time);
}

static __always_inline u8 sampler_readiness_matches(const u32 host_tgid,
                                                    const u64 start_time,
                                                    const process_readiness_t *expected) {
    const process_readiness_t *current = bpf_map_lookup_elem(&sampler_ready_pids, &host_tgid);
    if (!current || !current->ready || !current->epoch ||
        current->start_time != expected->start_time || current->epoch != expected->epoch ||
        current->config_epoch != expected->config_epoch || current->ready != expected->ready) {
        return 0;
    }
    return start_time ? process_incarnation_matches(current->start_time, start_time)
                      : process_incarnation_matches_current(host_tgid, current->start_time);
}

static __always_inline u8 sampler_process_is_ready_for_incarnation(const u32 host_tgid,
                                                                   const u64 start_time) {
    process_readiness_t readiness = {};
    return snapshot_sampler_readiness(host_tgid, start_time, &readiness);
}

static __always_inline u8 sampler_process_is_ready(const u32 host_tgid) {
    return sampler_process_is_ready_for_incarnation(host_tgid, 0);
}

static __always_inline s8 sampler_type_decision(const u8 type,
                                                const u64 trace_id_upper_bound,
                                                const unsigned char *trace_id) {
    switch (type) {
    case k_sampler_always_on:
        return 1;
    case k_sampler_always_off:
        return 0;
    case k_sampler_trace_id_ratio:
        return sampler_trace_id_ratio(trace_id, trace_id_upper_bound);
    default:
        return -1;
    }
}

static __always_inline s8 sampler_delegate_decision(const sampler_delegate_t *delegate,
                                                    const unsigned char *trace_id) {
    return sampler_type_decision(delegate->type, delegate->trace_id_upper_bound, trace_id);
}

static __always_inline s8 sampler_decision_for_process_incarnation(const unsigned char *trace_id,
                                                                   u8 has_parent,
                                                                   u8 parent_remote,
                                                                   u8 parent_sampled,
                                                                   const u32 host_tgid,
                                                                   const u64 start_time) {
    process_readiness_t readiness = {};
    if (!snapshot_sampler_readiness(host_tgid, start_time, &readiness)) {
        return k_sampler_evaluation_unavailable;
    }

    const sampler_config_t *config = sampler_config_for_process(host_tgid);
    if (!config || config->type == k_sampler_invalid || !config->publication_epoch ||
        config->publication_epoch != readiness.config_epoch) {
        return k_sampler_evaluation_error;
    }
    const u32 config_epoch = config->publication_epoch;

    s8 decision;
    if (config->type != k_sampler_parent_based) {
        decision = sampler_type_decision(config->type, config->trace_id_upper_bound, trace_id);
    } else if (!has_parent) {
        decision = sampler_delegate_decision(&config->root, trace_id);
    } else if (parent_remote) {
        decision = sampler_delegate_decision(parent_sampled ? &config->remote_parent_sampled
                                                            : &config->remote_parent_not_sampled,
                                             trace_id);
    } else {
        decision = sampler_delegate_decision(parent_sampled ? &config->local_parent_sampled
                                                            : &config->local_parent_not_sampled,
                                             trace_id);
    }

    if (!sampler_readiness_matches(host_tgid, start_time, &readiness)) {
        return k_sampler_evaluation_unavailable;
    }
    config = sampler_config_for_process(host_tgid);
    if (!config || config->publication_epoch != config_epoch) {
        return k_sampler_evaluation_unavailable;
    }
    return decision;
}

static __always_inline s8 sampler_decision_for_process(const unsigned char *trace_id,
                                                       u8 has_parent,
                                                       u8 parent_remote,
                                                       u8 parent_sampled,
                                                       const u32 host_tgid) {
    return sampler_decision_for_process_incarnation(
        trace_id, has_parent, parent_remote, parent_sampled, host_tgid, 0);
}

static __always_inline s8 sampler_decision(const unsigned char *trace_id,
                                           u8 has_parent,
                                           u8 parent_remote,
                                           u8 parent_sampled) {
    return sampler_decision_for_process(
        trace_id, has_parent, parent_remote, parent_sampled, bpf_get_current_pid_tgid() >> 32);
}

static __always_inline u8 apply_sampling_decision_for_process_mode(tp_info_t *tp,
                                                                   u8 has_parent,
                                                                   u8 parent_remote,
                                                                   const u32 host_tgid,
                                                                   const u64 start_time,
                                                                   u8 require_sampler) {
    tp->parent_remote = has_parent && parent_remote;
    if (tp->sampling_decision == k_sampling_decision_applied) {
        return 1;
    }
    if (tp->sampling_decision == k_sampling_decision_fail_closed) {
        tp->flags &= ~k_flag_sampled;
        return 0;
    }

    tp->sampling_decision = k_sampling_decision_pending;
    const s8 decision = sampler_decision_for_process_incarnation(
        tp->trace_id, has_parent, parent_remote, tp->flags & k_flag_sampled, host_tgid, start_time);
    if (decision == k_sampler_evaluation_unavailable && !require_sampler) {
        // Primary tracers retain the existing userspace sampler as a fallback. Auto SDK callers
        // require a synchronous eBPF decision and use require_sampler to fail closed instead.
        return 1;
    }
    if (decision < k_sampler_evaluation_drop) {
        apply_fail_closed_sampler_result(tp);
        return 0;
    }

    apply_sampler_result(tp, decision);
    return 1;
}

static __always_inline u8 apply_sampling_decision_for_process(tp_info_t *tp,
                                                              u8 has_parent,
                                                              u8 parent_remote,
                                                              const u32 host_tgid) {
    return apply_sampling_decision_for_process_mode(tp, has_parent, parent_remote, host_tgid, 0, 0);
}

static __always_inline u8 apply_sampling_decision_for_process_incarnation(
    tp_info_t *tp, u8 has_parent, u8 parent_remote, const u32 host_tgid, const u64 start_time) {
    return apply_sampling_decision_for_process_mode(
        tp, has_parent, parent_remote, host_tgid, start_time, 0);
}

static __always_inline u8 apply_sampling_decision(tp_info_t *tp, u8 has_parent, u8 parent_remote) {
    return apply_sampling_decision_for_process_mode(
        tp, has_parent, parent_remote, bpf_get_current_pid_tgid() >> 32, 0, 0);
}

static __always_inline u8 apply_required_sampling_decision(tp_info_t *tp,
                                                           u8 has_parent,
                                                           u8 parent_remote) {
    return apply_sampling_decision_for_process_mode(
        tp, has_parent, parent_remote, bpf_get_current_pid_tgid() >> 32, 0, 1);
}

static __always_inline const process_readiness_t *go_auto_sdk_readiness() {
    const u32 host_tgid = bpf_get_current_pid_tgid() >> 32;
    return bpf_map_lookup_elem(&go_auto_sdk_ready, &host_tgid);
}

static __always_inline u8 go_auto_sdk_readiness_is_current(const process_readiness_t *readiness) {
    const u32 host_tgid = bpf_get_current_pid_tgid() >> 32;
    return readiness && process_incarnation_matches_current(host_tgid, readiness->start_time);
}

static __always_inline u8
go_auto_sdk_readiness_matches_sampler(const process_readiness_t *readiness) {
    const u32 host_tgid = bpf_get_current_pid_tgid() >> 32;
    return go_auto_sdk_readiness_is_current(readiness) && readiness->ready && readiness->epoch &&
           sampler_process_is_ready_for_incarnation(host_tgid, readiness->start_time);
}

static __always_inline u32 go_auto_sdk_activation_epoch() {
    const process_readiness_t *readiness = go_auto_sdk_readiness();
    if (!go_auto_sdk_readiness_matches_sampler(readiness)) {
        return 0;
    }
    return readiness->epoch;
}

static __always_inline u32 go_auto_sdk_global_activation_epoch() {
    const process_readiness_t *readiness = go_auto_sdk_readiness();
    if (!go_auto_sdk_readiness_matches_sampler(readiness) || !readiness->auto_sdk_global_ready) {
        return 0;
    }
    return readiness->epoch;
}

static __always_inline u8 go_auto_sdk_is_ready() {
    return go_auto_sdk_activation_epoch() != 0;
}

static __always_inline void disable_go_auto_sdk() {
    const u32 host_tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&go_auto_sdk_ready, &host_tgid);
}
