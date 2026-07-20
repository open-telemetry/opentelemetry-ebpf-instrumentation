// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/algorithm.h>
#include <common/globals.h>
#include <common/http_buf_size.h>

// 55+13
#define TRACE_PARENT_HEADER_LEN 68

struct callback_ctx {
    unsigned char *buf;
    u32 pos;
    u8 _pad[4];
};

enum : u32 {
    k_tp_pos_not_found = 0xFFFFFFFFU,
    k_tp_max_scan_loops = TRACE_BUF_SIZE - TRACE_PARENT_HEADER_LEN,
};

static unsigned char *hex = (unsigned char *)"0123456789abcdef";
static unsigned char *reverse_hex =
    (unsigned char *)"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\xff\xff\xff\xff\xff\xff"
                     "\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";

static __always_inline void urand_bytes(unsigned char *buf, u32 size) {
    for (int i = 0; i < size; i += sizeof(u32)) {
        *((u32 *)&buf[i]) = bpf_get_prandom_u32();
    }
}

static __always_inline void decode_hex(unsigned char *dst, const unsigned char *src, u32 src_len) {
    for (u32 i = 1, j = 0; i < src_len; i += 2) {
        unsigned char p = *src++;
        unsigned char q = *src++;

        unsigned char a = reverse_hex[p & 0xff];
        unsigned char b = reverse_hex[q & 0xff];

        a = a & 0x0f;
        b = b & 0x0f;

        dst[j++] = ((a << 4) | b) & 0xff;
    }
}

static __always_inline void encode_hex(unsigned char *dst, const unsigned char *src, u32 src_len) {
    for (u32 i = 0, j = 0; i < src_len; i++) {
        unsigned char p = src[i];
        dst[j++] = hex[(p >> 4) & 0xff];
        dst[j++] = hex[p & 0x0f];
    }
}

static __always_inline bool is_traceparent(const unsigned char *p) {
    if (((p[0] == 'T') || (p[0] == 't')) && (p[1] == 'r') && (p[2] == 'a') && (p[3] == 'c') &&
        (p[4] == 'e') && ((p[5] == 'p') || (p[5] == 'P')) && (p[6] == 'a') && (p[7] == 'r') &&
        (p[8] == 'e') && (p[9] == 'n') && (p[10] == 't') && (p[11] == ':') && (p[12] == ' ')) {
        return true;
    }

    return false;
}

static __always_inline bool is_eoh(const unsigned char *p) {
    return p[0] == '\r' && p[1] == '\n' && p[2] == '\r' && p[3] == '\n';
}

static int tp_match(u32 index, void *data) {
    if (index >= (TRACE_BUF_SIZE - TRACE_PARENT_HEADER_LEN)) {
        return 1;
    }

    struct callback_ctx *ctx = data;
    unsigned char *s = &(ctx->buf[index]);

    if (is_traceparent(s)) {
        ctx->pos = index;
        return 1;
    }

    return 0;
}

static __always_inline u32 traceparent_scan_loop_count(const u16 buf_len) {
    if (buf_len < TRACE_PARENT_HEADER_LEN) {
        return 0;
    }

    return min((u32)buf_len - TRACE_PARENT_HEADER_LEN + 1, k_tp_max_scan_loops);
}

static __always_inline unsigned char *bpf_strstr_tp_loop(unsigned char *buf, const u16 buf_len) {
    if (!g_bpf_traceparent_enabled) {
        return NULL;
    }

    const u32 nr_loops = traceparent_scan_loop_count(buf_len);

    if (nr_loops == 0) {
        return NULL;
    }

    struct callback_ctx data = {.buf = buf, .pos = k_tp_pos_not_found};

    bpf_loop(nr_loops, tp_match, &data, 0);

    if (data.pos != k_tp_pos_not_found) {
        return (data.pos > (TRACE_BUF_SIZE - TRACE_PARENT_HEADER_LEN)) ? NULL : &buf[data.pos];
    }

    return NULL;
}

static __always_inline unsigned char *bpf_strstr_tp_loop__legacy(unsigned char *buf,
                                                                 const u16 buf_len) {
    if (!g_bpf_traceparent_enabled) {
        return NULL;
    }

    if (buf_len < TRACE_PARENT_HEADER_LEN) {
        return NULL;
    }

    // Limited best-effort search to stay within insns limit
    const u16 k_besteffort_max_loops = 350;

    for (u16 i = 0; i < k_besteffort_max_loops; i++) {
        // buf is null terminated
        if (*buf == '\0') {
            return NULL;
        }

        if (is_traceparent(buf)) {
            // here we validate if the actual traceparent value is complete,
            // i.e. we haven't hit any incomplete traceparent - notice that
            // everything here is constant (13 is the offset from
            // 'Traceparent: ' and TRACE_PARENT_HEADER_LEN is also a constant
            // - this allows the 5.10 kernel to prune this instead of tripping
            for (u8 j = 13; j < TRACE_PARENT_HEADER_LEN; j++) {
                if (buf[j] == '\0') {
                    return NULL;
                }
            }

            return buf;
        }

        ++buf;
    }

    return NULL;
}
