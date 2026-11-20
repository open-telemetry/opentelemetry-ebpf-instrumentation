// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

enum {
    k_python_exception_max_frames = 24,
    k_python_exception_message_max = 256,
};

enum python_exception_flags : u8 {
    k_python_exception_none = 0,
    // outer frames beyond k_python_exception_max_frames were dropped
    k_python_exception_truncated = 2,
    // the message was longer than k_python_exception_message_max
    k_python_exception_message_truncated = 4,
};

typedef struct python_exception_frame {
    u64 code;  // PyCodeObject*
    u32 instr; // code units into the code object's bytecode
    u32 _pad;
} python_exception_frame_t;

// PyCodeObject and str offsets that user space needs to symbolize the frames.
typedef struct python_exception_layout {
    u8 minor;
    u8 code_filename;
    u8 code_name;
    u8 code_linetable;
    u8 code_firstlineno;
    u8 unicode_ascii_data;
    u8 unicode_compact_data;
    u8 _pad;
} python_exception_layout_t;

// The exception_events payload of k_exception_runtime_python records. Only
// the first frame_count frames are sent, innermost first.
typedef struct python_exception_payload {
    u64 type;    // PyTypeObject*
    u32 obi_pid; // raising process in OBI's PID namespace
    u16 message_len;
    u8 message_kind; // PEP 393 kind, 0 without a message
    u8 frame_count;
    enum python_exception_flags flags;
    u8 _pad[7];
    python_exception_layout_t layout;
    unsigned char message[k_python_exception_message_max];
    python_exception_frame_t frames[k_python_exception_max_frames];
} python_exception_payload_t;
