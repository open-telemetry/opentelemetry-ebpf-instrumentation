// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/tp_info.h>

typedef struct go_h2_framer_func_invocation {
    u64 framer_ptr;
    tp_info_t tp;
    s64 frame_offset;
    u32 stream_id;
    u16 s_port;
    u16 d_port;
    u8 frame_type;
    bool reserved_padding;
    bool awaiting_continuation;
    u8 _pad[5];
} go_h2_framer_func_invocation_t;
