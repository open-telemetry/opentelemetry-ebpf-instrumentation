// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>
#include <pid/types/pid_filter.h>

enum otel_pid_state {
    k_otel_pid_unknown = 0,
    k_otel_pid_non_exporter = 1,
    k_otel_pid_exporter = 2,
};

// Two bits per PID keep discovery and exporter status in one word. 1 MiB.
enum {
    k_otel_pid_bits = 2,
    k_otel_pids_per_word = sizeof(u64) * 8 / k_otel_pid_bits,
    k_otel_pid_words = k_valid_pids_words * k_otel_pid_bits,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, k_otel_pid_words);
    __type(key, u32);
    __type(value, u64);
    __uint(pinning, OBI_PIN_INTERNAL);
} otel_traces_pids SEC(".maps");
