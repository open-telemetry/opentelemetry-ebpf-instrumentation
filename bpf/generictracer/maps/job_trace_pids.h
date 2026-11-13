// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <pid/types/pid_info.h>

enum { k_max_job_trace_pids = 1 << 14 };

// processes of the services that opted into job traces, keyed like pid_samplers
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, k_max_job_trace_pids);
    __type(key, pid_info_t);
    __type(value, u8);
    __uint(pinning, OBI_PIN_INTERNAL);
} job_trace_pids SEC(".maps");
