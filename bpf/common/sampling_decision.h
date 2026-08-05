// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/tp_info.h>

enum sampling_decision_state : u8 {
    k_sampling_decision_pending = 0,
    k_sampling_decision_applied = 1,
    k_sampling_decision_fail_closed = 2,
};

static __always_inline void reset_sampling_decision(tp_info_t *tp) {
    tp->sampling_decision = k_sampling_decision_pending;
}

static __always_inline void apply_sampler_result(tp_info_t *tp, u8 sampled) {
    tp->sampling_decision = k_sampling_decision_applied;
    tp->flags &= ~k_flag_sampled;
    if (sampled) {
        tp->flags |= k_flag_sampled;
    }
}

static __always_inline void apply_fail_closed_sampler_result(tp_info_t *tp) {
    tp->sampling_decision = k_sampling_decision_fail_closed;
    tp->flags &= ~k_flag_sampled;
}

static __always_inline void copy_sampling_state(tp_info_t *dest, const tp_info_t *src) {
    dest->flags = src->flags;
    dest->sampling_decision = src->sampling_decision;
    dest->parent_remote = src->parent_remote;
}

static __always_inline void inherit_parent_sampling_state(tp_info_t *dest,
                                                          const tp_info_t *parent) {
    dest->flags = parent->flags;
    reset_sampling_decision(dest);
}
