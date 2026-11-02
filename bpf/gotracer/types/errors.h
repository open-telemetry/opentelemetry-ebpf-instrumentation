// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

enum go_exception_kind : u8 {
    k_go_exception_formatted_error = 0,
    k_go_exception_panic = 1,
};

// Per-PID capture settings, written from user space for selected processes
enum go_exception_pid_flags : u8 {
    k_go_exception_pid_enabled = 1 << 0,
    k_go_exception_pid_panics = 1 << 1,
    k_go_exception_pid_formatted_errors = 1 << 2,
};

enum {
    k_go_exception_message_max_len = 128,
    k_go_exception_max_frames = 32,
};

// Payload of a k_exception_runtime_go exception_events record
typedef struct go_exception_payload {
    // enum go_exception_kind
    u8 kind;
    // the message was longer than message holds
    u8 message_truncated;
    u16 message_len;
    // number of valid entries in pcs, innermost frame first
    u16 frames;
    u8 _pad2[2];
    unsigned char message[k_go_exception_message_max_len];
    // runtime return addresses
    u64 pcs[k_go_exception_max_frames];
} go_exception_payload_t;
