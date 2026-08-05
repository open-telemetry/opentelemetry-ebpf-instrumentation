// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/tp_info.h>

typedef struct sk_outgoing_trace_handoff {
    tp_info_pid_t tp;
    outgoing_trace_token_t token;
} sk_outgoing_trace_handoff_t;

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, sk_outgoing_trace_handoff_t);
} sk_tp_info_pid_map SEC(".maps");
