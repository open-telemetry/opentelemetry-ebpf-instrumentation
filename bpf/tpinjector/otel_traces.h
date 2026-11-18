// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <pid/pid.h>
#include <tpinjector/maps/otel_traces_pids.h>

static __always_inline enum otel_pid_state otel_pid_state(u32 pid) {
    const u32 word = pid / k_otel_pids_per_word;
    const u64 *states = bpf_map_lookup_elem(&otel_traces_pids, &word);
    if (!states) {
        return k_otel_pid_unknown;
    }

    // Discovery and exporter status share one load, so their handoff cannot tear.
    return (*states >> ((pid % k_otel_pids_per_word) * k_otel_pid_bits)) &
           ((1U << k_otel_pid_bits) - 1);
}

static __always_inline bool exports_otel_traces(void) {
    const u32 pid = obi_pid(bpf_get_current_pid_tgid());
    if (pid == 0) {
        return false;
    }

    const enum otel_pid_state state = otel_pid_state(pid);
    if (state != k_otel_pid_unknown) {
        return state == k_otel_pid_exporter;
    }

    return otel_pid_state(obi_parent_pid()) == k_otel_pid_exporter;
}
