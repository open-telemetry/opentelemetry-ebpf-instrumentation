// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

#include <common/scratch_mem.h>
#include <common/trace_util.h>

enum {
    k_http1_max_header_bytes = 16 * 1024,
    // Copied and scanned per step, so a short header block costs one small read.
    k_http1_read_chunk_bytes = 1024,
};

enum { k_ascii_lowercase_bit = 0x20 };

enum http1_header_phase : u8 {
    k_http1_request_line,
    k_http1_header_name,
    k_http1_header_space,
    k_http1_header_value,
    k_http1_skip_header,
    k_http1_headers_done,
};

enum http1_memory : u8 {
    k_http1_memory_any,
    k_http1_memory_user,
};

typedef struct http1_header_scan {
    u32 bytes;
    u16 line_length;
    enum http1_header_phase phase;
    u8 name_length;
    u8 value_length;
    unsigned char previous;
    bool present;
    bool valid;
    bool trace_nonzero;
    bool span_nonzero;
    unsigned char header[TRACE_PARENT_HEADER_LEN + 1];
    u8 _pad[1];
} http1_header_scan_t;

SCRATCH_MEM_SIZED(http1_header_buf, k_http1_read_chunk_bytes);

const char TP_LOWER[] = "traceparent: ";
const char TP_HEADER[] = "traceparent";
const u32 TP_LOWER_SIZE = sizeof(TP_LOWER) - 1;
const u32 TP_HEADER_SIZE = sizeof(TP_HEADER) - 1;

/**
The functions below implement a byte scanning state machine, to handle
header splits across multiple buffer events for HTTP1 requests.
*/

// http1_scan_value consumes one value of the traceparent value and validates it one by one
static __always_inline void http1_scan_value(http1_header_scan_t *scan, unsigned char c) {
    const u32 pos = scan->value_length;
    if (pos >= k_hpack_value_len_tp || c == '\r') {
        scan->valid = false;
        scan->phase = k_http1_headers_done;
        return;
    }

    scan->header[TP_LOWER_SIZE + pos] = c;

    if (pos == k_tp_val_dash1 || pos == k_tp_val_dash2 || pos == k_tp_val_dash3) {
        scan->valid &= c == '-';
    } else {
        scan->valid &= reverse_hex[c] != 0xff;
    }

    if (pos >= k_tp_val_trace_id_start && pos < k_tp_val_dash2) {
        scan->trace_nonzero |= c != '0';
    }

    if (pos >= k_tp_val_span_id_start && pos < k_tp_val_dash3) {
        scan->span_nonzero |= c != '0';
    }

    scan->value_length++;
    if (scan->value_length == k_hpack_value_len_tp) {
        const unsigned char *value = scan->header + TP_LOWER_SIZE;
        scan->valid &= !((value[0] | k_ascii_lowercase_bit) == 'f' &&
                         (value[1] | k_ascii_lowercase_bit) == 'f');
        scan->valid &= scan->trace_nonzero && scan->span_nonzero;
        scan->phase = k_http1_headers_done;
    }
}

// http1_scan_header_byte handles one byte increments of the scanned value
static __always_inline void http1_scan_header_byte(http1_header_scan_t *scan, unsigned char c) {
    scan->bytes++;
    if (c == '\n') {
        if (scan->line_length == 0 || (scan->line_length == 1 && scan->previous == '\r') ||
            scan->present) {
            scan->valid = false;
            scan->phase = k_http1_headers_done;
            return;
        }

        scan->line_length = 0;
        scan->name_length = 0;
        scan->phase = k_http1_header_name;

        return;
    }

    scan->previous = c;
    scan->line_length++;
    if (scan->phase == k_http1_header_name) {
        const u32 pos = scan->name_length;
        if (pos < TP_HEADER_SIZE) {
            if ((c | k_ascii_lowercase_bit) != (unsigned char)TP_HEADER[pos]) {
                scan->phase = k_http1_skip_header;
                return;
            }

            scan->name_length++;
        } else if (c == ':') {
            scan->present = true;
            scan->valid = true;
            scan->phase = k_http1_header_space;
            __builtin_memcpy(scan->header, TP_LOWER, TP_LOWER_SIZE);
        } else {
            scan->phase = k_http1_skip_header;
        }

        return;
    }

    if (scan->phase == k_http1_header_space) {
        if (c == ' ' || c == '\t') {
            return;
        }

        scan->phase = k_http1_header_value;
    }

    if (scan->phase == k_http1_header_value) {
        http1_scan_value(scan, c);
    }
}

struct http1_read_ctx {
    http1_header_scan_t *scan;
    unsigned char *buf; // the chunk of src the scan is in
    const unsigned char *src;
    u32 len;
    u8 _pad[4];
};

static __always_inline long
http1_probe_read(void *dst, u32 len, const void *src, enum http1_memory memory) {
    if (memory == k_http1_memory_user) {
        return bpf_probe_read_user(dst, len, src);
    }
    return bpf_probe_read(dst, len, src);
}

// Reads the next chunk of src only when the scan reaches it, so a short header
// block costs one small read. Keeping the whole scan in one bpf_loop keeps the
// verifier from walking the code after it once per chunk.
static __always_inline int
http1_read_header_byte(u32 index, struct http1_read_ctx *ctx, enum http1_memory memory) {
    if (index >= k_http1_max_header_bytes) {
        return 1;
    }

    const u32 offset = index % k_http1_read_chunk_bytes;
    if (offset == 0) {
        u32 chunk = ctx->len - index;
        bpf_clamp_umax(chunk, k_http1_read_chunk_bytes);
        if (http1_probe_read(ctx->buf, chunk, ctx->src + index, memory) != 0) {
            ctx->scan->valid = false;
            ctx->scan->phase = k_http1_headers_done;
            return 1;
        }
    }

    http1_scan_header_byte(ctx->scan, ctx->buf[offset]);
    return ctx->scan->phase == k_http1_headers_done;
}

// One callback per memory kind, so each program loads only the read helper it uses.
static int http1_read_any_byte(u32 index, void *data) {
    return http1_read_header_byte(index, data, k_http1_memory_any);
}

static int http1_read_user_byte(u32 index, void *data) {
    return http1_read_header_byte(index, data, k_http1_memory_user);
}

static __always_inline void http1_read_headers(http1_header_scan_t *scan,
                                               const unsigned char *src,
                                               u32 len,
                                               enum http1_memory memory) {
    if (scan->phase == k_http1_headers_done || scan->bytes >= k_http1_max_header_bytes) {
        return;
    }

    unsigned char *buf = http1_header_buf_mem();
    if (!buf) {
        return;
    }

    struct http1_read_ctx ctx = {
        .scan = scan,
        .buf = buf,
        .src = src,
        .len = min(len, k_http1_max_header_bytes - scan->bytes),
    };

    if (memory == k_http1_memory_user) {
        bpf_loop(ctx.len, http1_read_user_byte, &ctx, 0);
    } else {
        bpf_loop(ctx.len, http1_read_any_byte, &ctx, 0);
    }

    if (scan->bytes >= k_http1_max_header_bytes) {
        scan->phase = k_http1_headers_done;
        if (scan->value_length != k_hpack_value_len_tp) {
            scan->valid = false;
        }
    }
}
