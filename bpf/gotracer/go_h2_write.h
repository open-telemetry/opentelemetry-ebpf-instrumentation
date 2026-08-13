// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>

#include <common/go_h2_stream_state.h>
#include <common/h2_defs.h>
#include <common/scratch_mem.h>
#include <common/trace_util.h>
#include <common/tracing.h>

enum go_h2_user_write_result : u8 {
    k_go_h2_user_write_bypass = 0,
    k_go_h2_user_write_committed = 1,
    k_go_h2_user_write_pristine = 2,
    k_go_h2_user_write_uncertain = 3,
    k_go_h2_user_write_deferred = 4,
};

static __always_inline u8 go_h2_state_after_user_write(u8 state, u8 result) {
    if (state != k_go_h2_state_obi_pending) {
        return state;
    }
    if (result == k_go_h2_user_write_committed) {
        return k_go_h2_state_obi_written;
    }
    if (result == k_go_h2_user_write_uncertain) {
        return k_go_h2_state_skip;
    }
    return state;
}

SCRATCH_MEM_SIZED(go_h2_field, k_h2_tp_hpack_size);
SCRATCH_MEM_SIZED(go_h2_readback, k_h2_tp_hpack_size);
SCRATCH_MEM_SIZED(go_h2_continuation, k_h2_tp_continuation_size);
SCRATCH_MEM_SIZED(go_h2_continuation_readback, k_h2_tp_continuation_size);

static __always_inline void make_go_h2_field(unsigned char *field, const tp_info_t *tp) {
    field[0] = k_hpack_literal_no_index;
    field[1] = k_hpack_tp_name_len;
    __builtin_memcpy(field + k_hpack_tp_name_offset, k_hpack_tp_name, k_hpack_tp_name_len);
    field[k_hpack_tp_val_offset - 1] = k_hpack_value_len_tp;
    make_tp_string(field + k_hpack_tp_val_offset, tp);
}

static __always_inline u8 commit_go_h2_reserved_padding(void *buf,
                                                        s64 n,
                                                        u32 stream_id,
                                                        const tp_info_t *tp) {
    if (!buf || !tp || n < k_h2_frame_header_len + 1 + k_h2_tp_hpack_size ||
        (u64)n > k_h2_default_max_frame_size + k_h2_frame_header_len) {
        return k_go_h2_user_write_bypass;
    }
    bpf_clamp_umax(n, k_h2_default_max_frame_size + k_h2_frame_header_len);

    unsigned char frame_header[k_h2_frame_header_len] = {};
    if (bpf_probe_read_user(frame_header, sizeof(frame_header), buf) != 0) {
        return k_go_h2_user_write_bypass;
    }
    u32 wire_stream_id = 0;
    __builtin_memcpy(&wire_stream_id, &frame_header[5], sizeof(wire_stream_id));
    wire_stream_id = bpf_ntohl(wire_stream_id) & 0x7fffffff;
    if (frame_header[3] != k_h2_frame_headers || wire_stream_id != stream_id ||
        !(frame_header[4] & k_h2_flag_end_headers) || !(frame_header[4] & k_h2_flag_padded)) {
        return k_go_h2_user_write_bypass;
    }

    unsigned char *pad_length_ptr = (unsigned char *)buf + k_h2_frame_header_len;
    u8 pad_length = 0;
    if (bpf_probe_read_user(&pad_length, sizeof(pad_length), pad_length_ptr) != 0 ||
        pad_length != k_h2_tp_hpack_size) {
        return k_go_h2_user_write_bypass;
    }

    unsigned char *field = go_h2_field_mem();
    unsigned char *readback = go_h2_readback_mem();
    if (!field || !readback) {
        return k_go_h2_user_write_bypass;
    }
    make_go_h2_field(field, tp);
    unsigned char *field_ptr = (unsigned char *)buf + (u64)n - k_h2_tp_hpack_size;
    long err = bpf_probe_write_user(field_ptr, field, k_h2_tp_hpack_size);
    err |= bpf_probe_read_user(readback, k_h2_tp_hpack_size, field_ptr);
    if (err || bpf_memcmp(field, readback, k_h2_tp_hpack_size) != 0) {
        return k_go_h2_user_write_pristine;
    }

    const u8 consumed_padding = 0;
    u8 pad_readback = k_h2_tp_hpack_size;
    err = bpf_probe_write_user(pad_length_ptr, &consumed_padding, sizeof(consumed_padding));
    err |= bpf_probe_read_user(&pad_readback, sizeof(pad_readback), pad_length_ptr);
    if (!err && pad_readback == consumed_padding) {
        return k_go_h2_user_write_committed;
    }
    return pad_readback == k_h2_tp_hpack_size ? k_go_h2_user_write_pristine
                                              : k_go_h2_user_write_uncertain;
}

static __always_inline u8 append_go_h2_traceparent_preflush(void *writer,
                                                            u64 n_offset,
                                                            void *buf,
                                                            s64 n,
                                                            s64 cap,
                                                            u32 stream_id,
                                                            u8 frame_type,
                                                            const tp_info_t *tp) {
    if (!writer || !buf || !tp || n < k_h2_frame_header_len || cap < n ||
        (u64)n > k_h2_default_max_frame_size + k_h2_frame_header_len) {
        return k_go_h2_user_write_bypass;
    }
    bpf_clamp_umax(n, k_h2_default_max_frame_size + k_h2_frame_header_len);

    unsigned char frame_header[k_h2_frame_header_len] = {};
    if (bpf_probe_read_user(frame_header, sizeof(frame_header), buf) != 0) {
        return k_go_h2_user_write_bypass;
    }
    u32 wire_stream_id = 0;
    __builtin_memcpy(&wire_stream_id, &frame_header[5], sizeof(wire_stream_id));
    wire_stream_id = bpf_ntohl(wire_stream_id) & 0x7fffffff;
    const u32 payload_len = (u32)n - k_h2_frame_header_len;
    if (frame_header[3] != frame_type || wire_stream_id != stream_id ||
        !(frame_header[4] & k_h2_flag_end_headers) ||
        payload_len + k_h2_tp_hpack_size > k_h2_default_max_frame_size ||
        (u64)cap - (u64)n < k_h2_tp_hpack_size) {
        return k_go_h2_user_write_bypass;
    }

    unsigned char *field = go_h2_field_mem();
    unsigned char *readback = go_h2_readback_mem();
    if (!field || !readback) {
        return k_go_h2_user_write_bypass;
    }
    make_go_h2_field(field, tp);

    long err = bpf_probe_write_user((unsigned char *)buf + (u64)n, field, k_h2_tp_hpack_size);
    err |= bpf_probe_read_user(readback, k_h2_tp_hpack_size, (unsigned char *)buf + (u64)n);
    if (err || bpf_memcmp(field, readback, k_h2_tp_hpack_size) != 0) {
        return k_go_h2_user_write_pristine;
    }

    void *n_ptr = (unsigned char *)writer + n_offset;
    const s64 new_n = n + k_h2_tp_hpack_size;
    s64 n_readback = -1;
    err = bpf_probe_write_user(n_ptr, &new_n, sizeof(new_n));
    err |= bpf_probe_read_user(&n_readback, sizeof(n_readback), n_ptr);
    if (!err && n_readback == new_n) {
        return k_go_h2_user_write_committed;
    }

    err = bpf_probe_write_user(n_ptr, &n, sizeof(n));
    err |= bpf_probe_read_user(&n_readback, sizeof(n_readback), n_ptr);
    return !err && n_readback == n ? k_go_h2_user_write_pristine : k_go_h2_user_write_uncertain;
}

static __always_inline bool restore_go_h2_metadata(void *n_ptr,
                                                   s64 original_n,
                                                   unsigned char *frame_ptr,
                                                   const unsigned char original_len[3]) {
    s64 n_readback = -1;
    unsigned char len_readback[3] = {};
    long err = bpf_probe_write_user(n_ptr, &original_n, sizeof(original_n));
    err |= bpf_probe_write_user(frame_ptr, original_len, 3);
    err |= bpf_probe_read_user(&n_readback, sizeof(n_readback), n_ptr);
    err |= bpf_probe_read_user(len_readback, sizeof(len_readback), frame_ptr);
    return !err && n_readback == original_n && len_readback[0] == original_len[0] &&
           len_readback[1] == original_len[1] && len_readback[2] == original_len[2];
}

static __always_inline bool
restore_go_h2_split_metadata(void *n_ptr, s64 original_n, unsigned char *flags_ptr, u8 flags) {
    s64 n_readback = -1;
    u8 flags_readback = 0;
    long err = bpf_probe_write_user(n_ptr, &original_n, sizeof(original_n));
    err |= bpf_probe_write_user(flags_ptr, &flags, sizeof(flags));
    err |= bpf_probe_read_user(&n_readback, sizeof(n_readback), n_ptr);
    err |= bpf_probe_read_user(&flags_readback, sizeof(flags_readback), flags_ptr);
    return !err && n_readback == original_n && flags_readback == flags;
}

static __always_inline u8 append_go_h2_traceparent_continuation(void *writer,
                                                                u64 n_offset,
                                                                void *buf,
                                                                s64 n,
                                                                s64 cap,
                                                                unsigned char *frame_ptr,
                                                                const unsigned char header[9],
                                                                const tp_info_t *tp) {
    if ((u64)cap - (u64)n < k_h2_tp_continuation_size) {
        return k_go_h2_user_write_bypass;
    }
    unsigned char *continuation = go_h2_continuation_mem();
    unsigned char *readback = go_h2_continuation_readback_mem();
    if (!continuation || !readback) {
        return k_go_h2_user_write_bypass;
    }
    bpf_memset(continuation, 0, k_h2_tp_continuation_size);
    continuation[2] = k_h2_tp_hpack_size;
    continuation[3] = k_h2_frame_continuation;
    continuation[4] = k_h2_flag_end_headers;
    __builtin_memcpy(continuation + 5, header + 5, sizeof(u32));
    make_go_h2_field(continuation + k_h2_frame_header_len, tp);

    long err = bpf_probe_write_user(
        (unsigned char *)buf + (u64)n, continuation, k_h2_tp_continuation_size);
    err |= bpf_probe_read_user(readback, k_h2_tp_continuation_size, (unsigned char *)buf + (u64)n);
    if (err || bpf_memcmp(continuation, readback, k_h2_tp_continuation_size) != 0) {
        return k_go_h2_user_write_pristine;
    }

    void *n_ptr = (unsigned char *)writer + n_offset;
    unsigned char *flags_ptr = frame_ptr + 4;
    const u8 original_flags = header[4];
    const u8 continued_flags = original_flags & ~k_h2_flag_end_headers;
    u8 flags_readback = 0;
    err = bpf_probe_write_user(flags_ptr, &continued_flags, sizeof(continued_flags));
    err |= bpf_probe_read_user(&flags_readback, sizeof(flags_readback), flags_ptr);
    if (err || flags_readback != continued_flags) {
        return restore_go_h2_split_metadata(n_ptr, n, flags_ptr, original_flags)
                   ? k_go_h2_user_write_pristine
                   : k_go_h2_user_write_uncertain;
    }

    const s64 new_n = n + k_h2_tp_continuation_size;
    s64 n_readback = -1;
    err = bpf_probe_write_user(n_ptr, &new_n, sizeof(new_n));
    err |= bpf_probe_read_user(&n_readback, sizeof(n_readback), n_ptr);
    if (err || n_readback != new_n) {
        return restore_go_h2_split_metadata(n_ptr, n, flags_ptr, original_flags)
                   ? k_go_h2_user_write_pristine
                   : k_go_h2_user_write_uncertain;
    }
    return k_go_h2_user_write_committed;
}

static __always_inline u8 append_go_h2_traceparent(void *writer,
                                                   u64 n_offset,
                                                   void *buf,
                                                   s64 frame_offset,
                                                   s64 n,
                                                   s64 cap,
                                                   u32 stream_id,
                                                   u8 frame_type,
                                                   const tp_info_t *tp,
                                                   bool allow_split) {
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

    unsigned char frame_header[9] = {};
    unsigned char *frame_ptr = (unsigned char *)buf + (u64)frame_offset;
    if (bpf_probe_read_user(frame_header, sizeof(frame_header), frame_ptr) != 0) {
        return k_go_h2_user_write_bypass;
    }
    const u32 payload_len =
        ((u32)frame_header[0] << 16) | ((u32)frame_header[1] << 8) | frame_header[2];
    u32 wire_stream_id = 0;
    __builtin_memcpy(&wire_stream_id, &frame_header[5], sizeof(wire_stream_id));
    wire_stream_id = bpf_ntohl(wire_stream_id) & 0x7fffffff;
    if (!payload_len || frame_header[3] != frame_type || wire_stream_id != stream_id ||
        (u64)n != (u64)frame_offset + k_h2_frame_header_len + payload_len) {
        return k_go_h2_user_write_bypass;
    }
    if (!(frame_header[4] & k_h2_flag_end_headers)) {
        return k_go_h2_user_write_deferred;
    }
    if (payload_len + k_h2_tp_hpack_size > k_h2_default_max_frame_size) {
        if (!allow_split) {
            return k_go_h2_user_write_bypass;
        }
        return append_go_h2_traceparent_continuation(
            writer, n_offset, buf, n, cap, frame_ptr, frame_header, tp);
    }
    if ((u64)cap - (u64)n < k_h2_tp_hpack_size) {
        return k_go_h2_user_write_bypass;
    }

    unsigned char *field = go_h2_field_mem();
    unsigned char *readback = go_h2_readback_mem();
    if (!field || !readback) {
        return k_go_h2_user_write_bypass;
    }
    make_go_h2_field(field, tp);

    void *n_ptr = (unsigned char *)writer + n_offset;
    unsigned char original_len[3] = {frame_header[0], frame_header[1], frame_header[2]};
    const u32 new_payload_len = payload_len + k_h2_tp_hpack_size;
    const unsigned char new_len[3] = {
        (u8)(new_payload_len >> 16),
        (u8)(new_payload_len >> 8),
        (u8)new_payload_len,
    };
    const s64 new_n = n + k_h2_tp_hpack_size;

    long err = bpf_probe_write_user((unsigned char *)buf + (u64)n, field, k_h2_tp_hpack_size);
    err |= bpf_probe_read_user(readback, k_h2_tp_hpack_size, (unsigned char *)buf + (u64)n);
    if (err || bpf_memcmp(field, readback, k_h2_tp_hpack_size) != 0) {
        return k_go_h2_user_write_pristine;
    }

    err = bpf_probe_write_user(frame_ptr, new_len, sizeof(new_len));
    err |= bpf_probe_read_user(frame_header, sizeof(new_len), frame_ptr);
    if (err || frame_header[0] != new_len[0] || frame_header[1] != new_len[1] ||
        frame_header[2] != new_len[2]) {
        return restore_go_h2_metadata(n_ptr, n, frame_ptr, original_len)
                   ? k_go_h2_user_write_pristine
                   : k_go_h2_user_write_uncertain;
    }

    s64 n_readback = -1;
    err = bpf_probe_write_user(n_ptr, &new_n, sizeof(new_n));
    err |= bpf_probe_read_user(&n_readback, sizeof(n_readback), n_ptr);
    if (err || n_readback != new_n) {
        return restore_go_h2_metadata(n_ptr, n, frame_ptr, original_len)
                   ? k_go_h2_user_write_pristine
                   : k_go_h2_user_write_uncertain;
    }

    return k_go_h2_user_write_committed;
}
