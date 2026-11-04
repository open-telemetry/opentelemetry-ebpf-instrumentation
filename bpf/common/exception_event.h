// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/tp_info.h>

#include <pid/types/pid_info.h>

enum exception_runtime : u8 {
    k_exception_runtime_java = 1,
    k_exception_runtime_nodejs = 2,
    k_exception_runtime_python = 3,
    k_exception_runtime_ruby = 4,
};

// How an exception was associated with a server request.
enum exception_owner : u8 {
    k_exception_owner_none = 0,
    // the request was still being served
    k_exception_owner_ongoing = 1,
    // the latest request on the connection that started before capture_ns,
    // whose response was already sent
    k_exception_owner_after_response = 2,
    // resolved from the server request of the throwing thread
    k_exception_owner_thread = 3,
    // a multiplexed connection without a stream id: no request is attached
    k_exception_owner_ambiguous = 4,
};

// Every exception_events record starts with this header, followed by
// payload_len bytes whose layout is defined by the runtime.
typedef struct exception_event_header {
    // bpf_ktime_get_ns() when the exception was thrown, not when it is emitted
    u64 capture_ns;
    tp_info_t tp;
    // filled with task_pid(), as span events are
    pid_info_t pid;
    u32 payload_len;
    u8 runtime;
    u8 owner;
    u8 _pad[6];
} exception_event_header_t;
