// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

enum {
    k_python_exception_max_frames = 24,
    k_python_exception_message_max = 256,
    // exceptions recorded from the reported one's __cause__/__context__ chain
    k_python_exception_max_links = 1,
    k_python_exception_link_max_frames = 8,
    k_python_exception_link_message_max = 128,
    // arguments a message renders; each takes an equal part of its buffer
    k_python_exception_max_args = 4,
};

enum python_exception_flags : u8 {
    k_python_exception_none = 0,
    // outer frames beyond the recorded ones were dropped
    k_python_exception_truncated = 2,
};

// How one exception argument is stored in a message buffer.
enum python_exception_arg_kind : u8 {
    k_python_arg_none = 0,
    // PEP 393 str code units of one, two or four bytes
    k_python_arg_str1 = 1,
    k_python_arg_str2 = 2,
    k_python_arg_str4 = 4,
    // the int's ob_size, or lv_tag on 3.12+, followed by its digits
    k_python_arg_int = 8,
};

// How a link relates to the exception recorded before it.
enum python_exception_relation : u8 {
    k_python_exception_cause = 1,
    k_python_exception_context = 2,
};

typedef struct python_exception_frame {
    u64 code;  // PyCodeObject*
    u32 instr; // code units into the code object's bytecode
    u32 _pad;
} python_exception_frame_t;

// The exception arguments a message is rendered from. A single argument fills
// the buffer; with more, argument i takes part i of k_python_exception_max_args.
typedef struct python_exception_message {
    u16 len[k_python_exception_max_args];
    enum python_exception_arg_kind kind[k_python_exception_max_args];
    u8 count; // 0 without a message
    // bit i: argument i was longer than its part
    u8 truncated;
    // arguments after the stored ones were not recorded
    u8 more;
    u8 quote_single; // Use repr() for a lone string argument.
} python_exception_message_t;

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

// An exception that CPython prints before the one it is linked from.
typedef struct python_exception_link {
    u64 type; // PyTypeObject*
    python_exception_message_t message;
    unsigned char text[k_python_exception_link_message_max];
    // the innermost frames of its traceback, innermost first
    python_exception_frame_t frames[k_python_exception_link_max_frames];
    u8 frame_count;
    enum python_exception_relation relation;
    enum python_exception_flags flags;
    u8 _pad[5];
} python_exception_link_t;

// The exception_events payload of k_exception_runtime_python records. Only
// the first frame_count frames are sent, innermost first.
typedef struct python_exception_payload {
    u64 type;    // PyTypeObject*
    u32 obi_pid; // raising process in OBI's PID namespace
    u8 frame_count;
    enum python_exception_flags flags;
    u8 link_count;
    u8 _pad;
    python_exception_layout_t layout;
    python_exception_message_t message;
    unsigned char text[k_python_exception_message_max];
    // links[0] is the exception this one was raised from or while handling
    python_exception_link_t links[k_python_exception_max_links];
    python_exception_frame_t frames[k_python_exception_max_frames];
} python_exception_payload_t;
