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
    u8 _pad;
    // number of valid entries in pcs, innermost frame first
    u16 frames;
    // bit 0: words 0-1 were read; bit 1: word 2; bit 2: scalar in word 0;
    // bit 3: runtime metadata identifies a predeclared string
    u8 value_read;
    u8 _pad2[3];
    // runtime type address used to classify the panic value
    u64 value_type;
    // string header, or boundsError's index, limit and signed/code fields
    u64 value[3];
    unsigned char message[k_go_exception_message_max_len];
    // runtime return addresses
    u64 pcs[k_go_exception_max_frames];
} go_exception_payload_t;
