// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>
#include <pid/pid.h>
#include <pid/types/pid_filter.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, k_valid_pids_words);
    __type(key, u32);
    __type(value, u64);
    __uint(pinning, OBI_PIN_INTERNAL);
} otel_traces_pids SEC(".maps");

// Userspace marks trace exporters whose OBI spans are suppressed. Check the live
// bitmap before writing headers because detection can happen after probe attachment.
static __always_inline bool exports_otel_traces() {
    return pid_selected(&otel_traces_pids, obi_pid(bpf_get_current_pid_tgid()));
}
