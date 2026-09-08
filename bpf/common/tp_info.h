// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#define TRACE_ID_SIZE_BYTES 16
#define SPAN_ID_SIZE_BYTES 8

// Values from https://www.w3.org/TR/trace-context/
enum tp_flags : u8 {
    k_flag_sampled = 1,
};

typedef struct tp_info {
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
    unsigned char parent_id[SPAN_ID_SIZE_BYTES];
    u64 ts;
    u8 flags;
    u8 _pad[7];
} tp_info_t;

// how a client span got its parent, decided where the parent is adopted
enum parent_status : u8 {
    // no parent was found
    k_parent_status_none = 0,
    // the parent request was still being served when this span started
    k_parent_status_live = 1,
    // the parent request may already have ended when this span started: once a
    // response is under way only its content says where it ends, so userspace
    // settles the link against the parent span's real end timestamp
    k_parent_status_conditional = 2,
};

_Static_assert(k_parent_status_conditional == 2,
               "value mirrored in pkg/ebpf/common (parentStatusConditional)");

typedef struct tp_info_pid {
    tp_info_t tp;
    u32 pid;
    u8 valid;
    u8 written;
    u8 req_type;
    u8 response_sent;
} tp_info_pid_t;
