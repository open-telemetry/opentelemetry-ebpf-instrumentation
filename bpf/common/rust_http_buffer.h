// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/h2_defs.h>
#include <common/h2_traceparent.h>
#include <common/http1_traceparent.h>
#include <common/tracing.h>
#include <logger/bpf_dbg.h>
#include <maps/rust_protocol.h>

enum { k_rust_max_buffer = 1 << 24 };

typedef struct rust_http_args {
    rust_http_request_t request;
    u64 buffer;
    u64 limit;
    u64 start_len;
    u64 hpack_buffer;
    u64 sender;
    u32 stream_id;
    u32 _pad;
} rust_http_args_t;

static __always_inline bool rust_read_u64(u64 object, u32 offset, u64 *value) {
    return object && bpf_probe_read_user(value, sizeof(*value), (void *)(object + offset)) == 0;
}

// Keep the bounded scan separate from task bookkeeping for the verifier.
static __noinline bool
rust_http1_rewrite_traceparent(u64 address, u64 len, const tp_info_t *wire, unsigned char *buf) {
    if (!buf || len < TRACE_PARENT_HEADER_LEN) {
        return false;
    }

    u32 captured = min(len, TRACE_BUF_SIZE - 1);
    bpf_clamp_umax(captured, TRACE_BUF_SIZE - 1);
    if (bpf_probe_read_user(buf, captured, (void *)address) != 0) {
        return false;
    }
    buf[captured] = '\0';

    unsigned char *header = bpf_strstr_tp_loop__legacy(buf, captured);
    if (!header) {
        return false;
    }

    u32 offset = header - buf;
    if (offset > captured - TRACE_PARENT_HEADER_LEN) {
        return false;
    }
    bpf_clamp_umax(offset, TRACE_BUF_SIZE - TRACE_PARENT_HEADER_LEN);
    if (offset) {
        u32 previous = offset - 1;
        // Preserve the bound after subtraction even when the verifier loses offset != 0.
        bpf_clamp_umax(previous, TRACE_BUF_SIZE - 1);
        if (buf[previous] != '\n') {
            return false;
        }
    }

    unsigned char *value = buf + offset + TP_LOWER_SIZE;
    make_tp_string(value, wire);
    return bpf_probe_write_user(
               (void *)(address + offset + TP_LOWER_SIZE), value, TP_MAX_VAL_LENGTH) == 0;
}

static __always_inline bool rust_hpack_append(rust_http_args_t *args,
                                              const rust_protocol_config_t *config) {
    u64 ptr = 0;
    u64 len = 0;
    u64 cap = 0;
    if (!rust_read_u64(args->hpack_buffer, config->bytes_ptr, &ptr) ||
        !rust_read_u64(args->hpack_buffer, config->bytes_len, &len) ||
        !rust_read_u64(args->hpack_buffer, config->bytes_cap, &cap) || cap > k_rust_max_buffer ||
        cap < len || cap - len < k_h2_tp_hpack_size || ptr + cap < ptr) {
        bpf_dbg_printk("rust hpack buffer rejected len=%llu cap=%llu", len, cap);
        return false;
    }

    unsigned char header[k_h2_tp_hpack_size];
    make_h2_traceparent(header, &args->request.wire);

    const u64 new_len = len + sizeof(header);
    const long result = bpf_probe_write_user((void *)(ptr + len), header, sizeof(header));
    if (result) {
        bpf_dbg_printk("rust hpack payload write failed err=%ld", result);
        return false;
    }

    if (bpf_probe_write_user(
            (void *)(args->hpack_buffer + config->bytes_len), &new_len, sizeof(new_len)) != 0) {
        bpf_dbg_printk("rust hpack length commit failed stream=%u", args->stream_id);
        return false;
    }

    return true;
}

static __always_inline bool rust_http2_append(rust_http_args_t *args,
                                              const rust_protocol_config_t *config) {
    u64 ptr = 0;
    u64 len = 0;
    u64 cap = 0;
    u64 remaining = 0;
    if (!rust_read_u64(args->buffer, config->bytes_ptr, &ptr) ||
        !rust_read_u64(args->buffer, config->bytes_len, &len) ||
        !rust_read_u64(args->buffer, config->bytes_cap, &cap) ||
        !rust_read_u64(args->limit, config->limit_remaining, &remaining) ||
        cap > k_rust_max_buffer || (ptr + cap) < ptr || (len < args->start_len) ||
        (len - args->start_len) < k_h2_frame_header_len || cap < len ||
        (cap - len) < k_h2_tp_hpack_size || remaining < k_h2_tp_hpack_size) {
        bpf_dbg_printk(
            "rust h2 buffer rejected stream=%u len=%llu cap=%llu", args->stream_id, len, cap);
        return false;
    }

    enum {
        k_frame_length_size = 3,
        k_frame_type_offset = k_frame_length_size,
        k_frame_flags_offset = k_frame_type_offset + sizeof(u8),
    };
    unsigned char head[k_h2_frame_header_len];
    const void *frame_start = (const void *)(ptr + args->start_len);
    const long read_result = bpf_probe_read_user(head, sizeof(head), frame_start);
    if (read_result != 0) {
        bpf_dbg_printk("rust h2 frame header unreadable stream=%u", args->stream_id);
        return false;
    }

    const u8 frame_type = head[k_frame_type_offset];
    if (frame_type != k_h2_frame_headers) {
        bpf_dbg_printk("rust h2 expected HEADERS stream=%u type=%u", args->stream_id, frame_type);
        return false;
    }

    const bool headers_complete = (head[k_frame_flags_offset] & k_h2_flag_end_headers) != 0;
    if (!headers_complete) {
        bpf_dbg_printk("rust h2 incomplete HEADERS stream=%u", args->stream_id);
        return false;
    }

    const u32 payload = ((u32)head[0] << 16) | ((u32)head[1] << 8) | head[2];
    const unsigned char *stream_id = head + k_h2_frame_stream_id_offset;
    const u32 stream = ((u32)(stream_id[0] & ~k_h2_reserved_bit_mask) << 24) |
                       ((u32)stream_id[1] << 16) | ((u32)stream_id[2] << 8) | stream_id[3];

    if (stream != args->stream_id || (payload + k_h2_frame_header_len != len - args->start_len) ||
        (payload > k_h2_default_max_frame_size - k_h2_tp_hpack_size)) {
        bpf_dbg_printk("rust h2 frame rejected stream=%u expected=%u len=%u",
                       stream,
                       args->stream_id,
                       payload);
        return false;
    }

    unsigned char header[k_h2_tp_hpack_size];
    make_h2_traceparent(header, &args->request.wire);

    const long write_result = bpf_probe_write_user((void *)(ptr + len), header, sizeof(header));
    if (write_result != 0) {
        bpf_dbg_printk("rust h2 payload write failed stream=%u err=%ld", stream, write_result);
        return false;
    }

    const unsigned char old_head[k_frame_length_size] = {head[0], head[1], head[2]};
    const u32 new_payload = payload + sizeof(header);
    head[0] = new_payload >> 16;
    head[1] = new_payload >> 8;
    head[2] = new_payload;

    const u64 new_len = len + sizeof(header);
    const u64 new_remaining = remaining - sizeof(header);
    if (bpf_probe_write_user((void *)(ptr + args->start_len), head, sizeof(old_head)) != 0) {
        bpf_dbg_printk("rust h2 frame length write failed stream=%u", stream);
        return false;
    }

    if (bpf_probe_write_user((void *)(args->limit + config->limit_remaining),
                             &new_remaining,
                             sizeof(new_remaining)) != 0) {
        bpf_dbg_printk("rust h2 limit commit failed stream=%u; rollback", stream);
        bpf_probe_write_user((void *)(ptr + args->start_len), old_head, sizeof(old_head));
        return false;
    }

    if (bpf_probe_write_user(
            (void *)(args->buffer + config->bytes_len), &new_len, sizeof(new_len)) != 0) {
        bpf_dbg_printk("rust h2 length commit failed stream=%u; rollback", stream);
        bpf_probe_write_user(
            (void *)(args->limit + config->limit_remaining), &remaining, sizeof(remaining));
        bpf_probe_write_user((void *)(ptr + args->start_len), old_head, sizeof(old_head));
        return false;
    }

    args->request.inject = 0;
    return true;
}
