// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/h2_defs.h>

#include <gotracer/go_common.h>
#include <gotracer/go_offsets.h>
#include <gotracer/types/go_h2.h>

enum go_h2_continuation_result : u8 {
    k_go_h2_continuation_ignored = 0,
    k_go_h2_continuation_ready = 1,
    k_go_h2_continuation_invalid = 2,
};

static __always_inline u8 prepare_go_h2_continuation(struct pt_regs *ctx,
                                                     go_h2_framer_func_invocation_t *f_info,
                                                     go_offset_const writer_n_offset,
                                                     s64 max_n) {
    void *framer = GO_PARAM1(ctx);
    const u32 stream_id = (u32)(u64)GO_PARAM2(ctx);
    const bool end_headers = (bool)(u64)GO_PARAM3(ctx);
    if (!f_info || !f_info->awaiting_continuation || !framer || f_info->framer_ptr != (u64)framer ||
        f_info->stream_id != stream_id) {
        return k_go_h2_continuation_ignored;
    }

    off_table_t *ot = get_offsets_table();
    const u64 framer_w_pos = go_offset_of(ot, (go_offset){.v = _framer_w_pos});
    const u64 writer_n_pos = go_offset_of(ot, (go_offset){.v = writer_n_offset});
    if (framer_w_pos == (u64)-1 || writer_n_pos == (u64)-1) {
        return k_go_h2_continuation_invalid;
    }

    void *writer = 0;
    s64 n = -1;
    long err = bpf_probe_read_user(
        &writer, sizeof(writer), (unsigned char *)framer + framer_w_pos + k_go_iface_data_offset);
    if (!err && writer) {
        err = bpf_probe_read_user(&n, sizeof(n), (unsigned char *)writer + writer_n_pos);
    }
    if (err || !writer || n < 0 || n >= max_n) {
        return k_go_h2_continuation_invalid;
    }

    f_info->frame_offset = n;
    f_info->frame_type = k_h2_frame_continuation;
    f_info->reserved_padding = false;
    f_info->awaiting_continuation = !end_headers;
    return k_go_h2_continuation_ready;
}
