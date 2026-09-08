// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>

#include <common/h2_defs.h>
#include <common/scratch_mem.h>
#include <common/tracing.h>

enum go_h2_user_write_result : u8 {
    k_go_h2_user_write_bypass = 0,
    k_go_h2_user_write_committed = 1,
    k_go_h2_user_write_pristine = 2,
    k_go_h2_user_write_uncertain = 3,
};

enum go_h2_user_write_step : u8 {
    k_go_h2_write_field = 1,
    k_go_h2_write_frame_len = 2,
    k_go_h2_write_writer_len = 3,
    k_go_h2_restore_writer_len = 4,
    k_go_h2_restore_frame_len = 5,
    k_go_h2_finish_frame_len = 6,
    k_go_h2_finish_writer_len = 7,
};

SCRATCH_MEM_SIZED(go_h2_field, k_h2_tp_hpack_huffman_size)
SCRATCH_MEM_SIZED(go_h2_readback, k_h2_tp_hpack_huffman_size)

static __always_inline long
go_h2_write_user(void *dst, const void *src, u32 size, enum go_h2_user_write_step step) {
    if (g_go_h2_write_fail_step == step) {
        return -1;
    }
    return bpf_probe_write_user(dst, src, size);
}

static __always_inline void make_go_h2_field(unsigned char *field, const tp_info_t *tp) {
    field[0] = k_hpack_literal_no_index;
    field[1] = k_hpack_tp_name_huffman_len | k_hpack_huffman_flag;
    __builtin_memcpy(
        field + k_hpack_tp_name_offset, k_hpack_tp_huffman, k_hpack_tp_name_huffman_len);
    field[k_hpack_tp_val_offset_huffman - 1] = k_hpack_value_len_tp;
    make_tp_string(field + k_hpack_tp_val_offset_huffman, tp);
}

static __always_inline u8 go_h2_metadata_state(void *n_ptr,
                                               s64 original_n,
                                               s64 new_n,
                                               unsigned char *frame_ptr,
                                               const unsigned char original_len[3],
                                               const unsigned char new_len[3]) {
    s64 current_n = -1;
    unsigned char current_len[3] = {};
    long err = bpf_probe_read_user(&current_n, sizeof(current_n), n_ptr);
    err |= bpf_probe_read_user(current_len, sizeof(current_len), frame_ptr);
    if (err) {
        return k_go_h2_user_write_uncertain;
    }

    if (current_n == original_n && current_len[0] == original_len[0] &&
        current_len[1] == original_len[1] && current_len[2] == original_len[2]) {
        return k_go_h2_user_write_pristine;
    }
    if (current_n == new_n && current_len[0] == new_len[0] && current_len[1] == new_len[1] &&
        current_len[2] == new_len[2]) {
        return k_go_h2_user_write_committed;
    }
    return k_go_h2_user_write_uncertain;
}

static __always_inline u8 settle_go_h2_metadata(void *n_ptr,
                                                s64 original_n,
                                                s64 new_n,
                                                unsigned char *frame_ptr,
                                                const unsigned char original_len[3],
                                                const unsigned char new_len[3]) {
    const u8 state =
        go_h2_metadata_state(n_ptr, original_n, new_n, frame_ptr, original_len, new_len);
    if (state != k_go_h2_user_write_uncertain) {
        return state;
    }

    const long restore_n_err =
        go_h2_write_user(n_ptr, &original_n, sizeof(original_n), k_go_h2_restore_writer_len);
    const long restore_frame_err =
        go_h2_write_user(frame_ptr, original_len, 3, k_go_h2_restore_frame_len);
    const u8 restored =
        go_h2_metadata_state(n_ptr, original_n, new_n, frame_ptr, original_len, new_len);
    if (!restore_n_err && !restore_frame_err && restored == k_go_h2_user_write_pristine) {
        return restored;
    }
    if (restored != k_go_h2_user_write_uncertain) {
        return restored;
    }

    const long finish_frame_err = go_h2_write_user(frame_ptr, new_len, 3, k_go_h2_finish_frame_len);
    const long finish_n_err =
        go_h2_write_user(n_ptr, &new_n, sizeof(new_n), k_go_h2_finish_writer_len);
    const u8 finished =
        go_h2_metadata_state(n_ptr, original_n, new_n, frame_ptr, original_len, new_len);
    if (!finish_frame_err && !finish_n_err && finished == k_go_h2_user_write_committed) {
        return finished;
    }
    if (finished != k_go_h2_user_write_uncertain) {
        return finished;
    }

    return k_go_h2_user_write_uncertain;
}

static __always_inline u8 append_go_h2_traceparent(void *writer,
                                                   u64 n_offset,
                                                   void *buf,
                                                   s64 frame_offset,
                                                   s64 n,
                                                   s64 cap,
                                                   u32 stream_id,
                                                   const tp_info_t *tp) {
    if (!writer || !buf || !tp || frame_offset < 0 || n < 0 || cap < 0 || n > cap ||
        frame_offset > n) {
        return k_go_h2_user_write_bypass;
    }
    if ((u64)frame_offset > k_h2_max_frame_len + k_h2_frame_header_len ||
        (u64)n > k_h2_max_frame_len + k_h2_frame_header_len ||
        (u64)n - (u64)frame_offset < k_h2_frame_header_len) {
        return k_go_h2_user_write_bypass;
    }

    bpf_clamp_umax(frame_offset, k_h2_max_frame_len + k_h2_frame_header_len);
    bpf_clamp_umax(n, k_h2_max_frame_len + k_h2_frame_header_len);

    unsigned char frame_header[k_h2_frame_header_len] = {};
    unsigned char *frame_ptr = (unsigned char *)buf + (u64)frame_offset;
    if (bpf_probe_read_user(frame_header, sizeof(frame_header), frame_ptr) != 0) {
        return k_go_h2_user_write_bypass;
    }

    const u32 payload_len =
        ((u32)frame_header[0] << 16) | ((u32)frame_header[1] << 8) | frame_header[2];
    u32 wire_stream_id = 0;
    __builtin_memcpy(&wire_stream_id, &frame_header[k_h2_frame_stream_id_offset], sizeof(u32));
    wire_stream_id = bpf_ntohl(wire_stream_id) & 0x7fffffff;

    if (!payload_len || frame_header[3] != k_h2_frame_headers || wire_stream_id != stream_id ||
        !(frame_header[4] & k_h2_flag_end_headers) ||
        (u64)n != (u64)frame_offset + k_h2_frame_header_len + payload_len ||
        payload_len + k_h2_tp_hpack_huffman_size > k_h2_default_max_frame_size ||
        (u64)cap - (u64)n < k_h2_tp_hpack_huffman_size) {
        return k_go_h2_user_write_bypass;
    }

    unsigned char *field = go_h2_field_mem();
    unsigned char *readback = go_h2_readback_mem();
    if (!field || !readback) {
        return k_go_h2_user_write_bypass;
    }
    make_go_h2_field(field, tp);

    unsigned char *field_ptr = (unsigned char *)buf + (u64)n;
    long err = go_h2_write_user(field_ptr, field, k_h2_tp_hpack_huffman_size, k_go_h2_write_field);
    err |= bpf_probe_read_user(readback, k_h2_tp_hpack_huffman_size, field_ptr);
    if (err || bpf_memcmp(field, readback, k_h2_tp_hpack_huffman_size) != 0) {
        return k_go_h2_user_write_pristine;
    }

    void *n_ptr = (unsigned char *)writer + n_offset;
    const unsigned char original_len[3] = {
        frame_header[0],
        frame_header[1],
        frame_header[2],
    };
    const u32 new_payload_len = payload_len + k_h2_tp_hpack_huffman_size;
    const unsigned char new_len[3] = {
        (u8)(new_payload_len >> 16),
        (u8)(new_payload_len >> 8),
        (u8)new_payload_len,
    };
    const s64 new_n = n + k_h2_tp_hpack_huffman_size;

    // Keep the original writer length authoritative until the full field is present and the
    // frame metadata is ready. Publishing writer.n is the final commit step.
    err = go_h2_write_user(frame_ptr, new_len, sizeof(new_len), k_go_h2_write_frame_len);
    if (err) {
        return settle_go_h2_metadata(n_ptr, n, new_n, frame_ptr, original_len, new_len);
    }

    err = go_h2_write_user(n_ptr, &new_n, sizeof(new_n), k_go_h2_write_writer_len);
    if (err) {
        return settle_go_h2_metadata(n_ptr, n, new_n, frame_ptr, original_len, new_len);
    }

    return settle_go_h2_metadata(n_ptr, n, new_n, frame_ptr, original_len, new_len);
}
