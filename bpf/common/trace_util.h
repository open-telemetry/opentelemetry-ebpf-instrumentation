// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/algorithm.h>
#include <common/globals.h>
#include <common/http_buf_size.h>
#include <common/sampling_decision.h>
#include <common/tp_info.h>

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
    k_http1_legacy_scan_loops = 350,
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

static __always_inline void new_trace_id(tp_info_t *tp) {
    urand_bytes(tp->trace_id, TRACE_ID_SIZE_BYTES);
    tp->flags |= k_flag_random;
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

static __always_inline void encode_traceparent_flags(unsigned char *dst, u8 flags) {
    flags &= k_flag_mask;
    dst[0] = hex[(flags >> 4) & 0x0f];
    dst[1] = hex[flags & 0x0f];
}

static __always_inline u8 valid_traceparent_hex(const unsigned char *value, u8 len) {
    if (len > TRACE_ID_SIZE_BYTES * 2) {
        return 0;
    }
    u8 invalid = 0;
#pragma clang loop unroll(disable)
    for (u8 i = 0; i < len; i++) {
        const unsigned char c = value[i];
        const u8 digit_offset = c - '0';
        const u8 lower_offset = c - 'a';
        const u8 invalid_digit = (digit_offset | (u8)(9 - digit_offset)) >> 7;
        const u8 invalid_lower = (lower_offset | (u8)(5 - lower_offset)) >> 7;
        invalid |= invalid_digit & invalid_lower;
    }
    return invalid ^ 1;
}

static __always_inline u8 nonzero_traceparent_id(const unsigned char *value, u8 len) {
    if (len > TRACE_ID_SIZE_BYTES * 2) {
        return 0;
    }
    u8 difference = 0;
#pragma clang loop unroll(disable)
    for (u8 i = 0; i < len; i++) {
        difference |= value[i] ^ '0';
    }
    return (difference | (u8)(0 - difference)) >> 7;
}

static __noinline __attribute__((unused)) u8 valid_traceparent_value(const unsigned char *value) {
    enum {
        k_version_len = 2,
        k_trace_id_start = 3,
        k_trace_id_len = TRACE_ID_SIZE_BYTES * 2,
        k_span_id_start = k_trace_id_start + k_trace_id_len + 1,
        k_span_id_len = SPAN_ID_SIZE_BYTES * 2,
        k_flags_start = k_span_id_start + k_span_id_len + 1,
        k_flags_len = 2,
    };

    u8 valid = value[k_version_len] == '-';
    valid &= value[k_span_id_start - 1] == '-';
    valid &= value[k_flags_start - 1] == '-';
    valid &= valid_traceparent_hex(value, k_version_len);
    valid &= !(value[0] == 'f' && value[1] == 'f');
    valid &= valid_traceparent_hex(value + k_trace_id_start, k_trace_id_len);
    valid &= nonzero_traceparent_id(value + k_trace_id_start, k_trace_id_len);
    valid &= valid_traceparent_hex(value + k_span_id_start, k_span_id_len);
    valid &= nonzero_traceparent_id(value + k_span_id_start, k_span_id_len);
    valid &= valid_traceparent_hex(value + k_flags_start, k_flags_len);
    return valid;
}

static __always_inline u8 valid_traceparent_value_length(const unsigned char *value,
                                                         u64 value_len) {
    enum { k_traceparent_value_len = 55 };

    if (!value || value_len < k_traceparent_value_len || !valid_traceparent_value(value)) {
        return 0;
    }
    if (value[0] == '0' && value[1] == '0') {
        return value_len == k_traceparent_value_len;
    }
    return value_len == k_traceparent_value_len || value[k_traceparent_value_len] == '-';
}

static __always_inline u8 traceparent_flags_for_version(const unsigned char *value, u8 flags) {
    if (!value || value[0] != '0' || value[1] != '0') {
        return flags & k_flag_sampled;
    }
    return flags & k_flag_mask;
}

static __always_inline u8 valid_traceparent_header(const unsigned char *header) {
    enum { k_traceparent_prefix_len = 13 };
    return valid_traceparent_value(header + k_traceparent_prefix_len);
}

static __always_inline u8 valid_http_traceparent_value(const unsigned char *value,
                                                       const unsigned char next) {
    if (!valid_traceparent_value(value)) {
        return 0;
    }

    if (value[0] == '0' && value[1] == '0') {
        return next == '\r';
    }
    return next == '\r' || next == '-';
}

static __always_inline u8 valid_http_traceparent_header(const unsigned char *header) {
    enum {
        k_traceparent_prefix_len = 13,
        k_traceparent_value_len = 55,
    };
    const unsigned char *value = header + k_traceparent_prefix_len;
    return valid_http_traceparent_value(value, value[k_traceparent_value_len]) &&
           value[k_traceparent_value_len] == '\r' && value[k_traceparent_value_len + 1] == '\n';
}

static __always_inline void commit_outbound_traceparent(tp_info_t *tp) {
    if (tp->sampling_decision == k_sampling_decision_pending) {
        // A successful wire write does not replace the userspace sampler fallback.
        return;
    }
    tp->sampling_decision = k_sampling_decision_applied;
}

static __always_inline void preserve_outbound_traceparent(tp_info_t *tp) {
    tp->sampling_decision = k_sampling_decision_applied;
    tp->parent_remote = 0;
}

static __always_inline u8 wire_traceparent_parts_match(const tp_info_t *authority,
                                                       const unsigned char *wire_trace_id,
                                                       const unsigned char *wire_span_id,
                                                       u8 wire_flags) {
    return authority && wire_trace_id && wire_span_id &&
           __builtin_memcmp(authority->trace_id, wire_trace_id, sizeof(authority->trace_id)) == 0 &&
           __builtin_memcmp(authority->span_id, wire_span_id, sizeof(authority->span_id)) == 0 &&
           authority->flags == wire_flags;
}

static __always_inline u8 wire_traceparent_matches_authority(const tp_info_t *authority,
                                                             const tp_info_t *wire) {
    return wire &&
           wire_traceparent_parts_match(authority, wire->trace_id, wire->span_id, wire->flags);
}

enum outbound_trace_state : u8 {
    k_outbound_trace_pending = 0,
    k_outbound_trace_written = 1,
};

static __always_inline u8 outbound_traceparent_matches(const tp_info_pid_t *candidate,
                                                       u32 pid,
                                                       u8 request_type,
                                                       u8 written) {
    return candidate && written <= k_outbound_trace_written && candidate->valid == 1 &&
           candidate->written == written && candidate->pid == pid &&
           candidate->req_type == request_type &&
           (*((u64 *)candidate->tp.trace_id) || *((u64 *)(candidate->tp.trace_id + sizeof(u64))));
}

static __always_inline u8 adopt_outbound_traceparent(tp_info_t *tp,
                                                     const tp_info_pid_t *candidate,
                                                     u32 pid,
                                                     u8 request_type) {
    if (!outbound_traceparent_matches(candidate, pid, request_type, k_outbound_trace_written)) {
        return 0;
    }

    __builtin_memcpy(tp->trace_id, candidate->tp.trace_id, TRACE_ID_SIZE_BYTES);
    __builtin_memcpy(tp->span_id, candidate->tp.span_id, SPAN_ID_SIZE_BYTES);
    __builtin_memcpy(tp->parent_id, candidate->tp.parent_id, SPAN_ID_SIZE_BYTES);
    tp->flags = candidate->tp.flags;
    tp->sampling_decision = candidate->tp.sampling_decision;
    tp->parent_remote = candidate->tp.parent_remote;
    return 1;
}

static __always_inline void restore_outbound_traceparent_flags(tp_info_t *tp, u8 flags) {
    tp->flags = flags & k_flag_mask;
    commit_outbound_traceparent(tp);
}

static __always_inline void
restore_outbound_traceparent(tp_info_t *tp, const unsigned char *span_id, u8 flags) {
    __builtin_memcpy(tp->span_id, span_id, SPAN_ID_SIZE_BYTES);
    __builtin_memset(tp->parent_id, 0, SPAN_ID_SIZE_BYTES);
    tp->flags = flags & k_flag_mask;
    preserve_outbound_traceparent(tp);
}

static __always_inline bool is_traceparent_name(const unsigned char *p) {
    enum { k_ascii_lowercase_bit = 0x20 };

    if (((p[0] | k_ascii_lowercase_bit) == 't') && ((p[1] | k_ascii_lowercase_bit) == 'r') &&
        ((p[2] | k_ascii_lowercase_bit) == 'a') && ((p[3] | k_ascii_lowercase_bit) == 'c') &&
        ((p[4] | k_ascii_lowercase_bit) == 'e') && ((p[5] | k_ascii_lowercase_bit) == 'p') &&
        ((p[6] | k_ascii_lowercase_bit) == 'a') && ((p[7] | k_ascii_lowercase_bit) == 'r') &&
        ((p[8] | k_ascii_lowercase_bit) == 'e') && ((p[9] | k_ascii_lowercase_bit) == 'n') &&
        ((p[10] | k_ascii_lowercase_bit) == 't') && p[11] == ':') {
        return true;
    }

    return false;
}

static __always_inline bool is_traceparent(const unsigned char *p) {
    return is_traceparent_name(p) && p[12] == ' ';
}

enum : u8 {
    k_http_traceparent_value_offset_unknown = 0xff,
    k_http_traceparent_ows_scan = 8,
};

// The caller must make the header name and OWS scan window addressable.
static __always_inline u8 http_traceparent_value_offset(const unsigned char *p) {
    if (!is_traceparent_name(p)) {
        return 0;
    }

    u8 offset = 12;
#pragma unroll
    for (u8 i = 0; i < k_http_traceparent_ows_scan; i++) {
        if (p[offset] != ' ' && p[offset] != '\t') {
            return offset;
        }
        offset++;
    }
    return p[offset] == ' ' || p[offset] == '\t' ? k_http_traceparent_value_offset_unknown : offset;
}

static __always_inline bool is_eoh(const unsigned char *p) {
    return p[0] == '\r' && p[1] == '\n' && p[2] == '\r' && p[3] == '\n';
}

enum http1_traceparent_scan_result : u8 {
    k_http1_traceparent_scan_unknown = 0,
    k_http1_traceparent_scan_absent = 1,
    k_http1_traceparent_scan_found = 2,
    k_http1_traceparent_scan_present = 3,
};

enum {
    k_http1_traceparent_name_field_len = 12,
    k_http1_traceparent_value_len = 55,
};

static __always_inline u8 http1_server_requires_root(enum http1_traceparent_scan_result result) {
    return result == k_http1_traceparent_scan_unknown || result == k_http1_traceparent_scan_present;
}

typedef struct http1_traceparent_scan {
    unsigned char *buf;
    u32 field_pos;
    u16 buf_len;
    u8 line_start;
    u8 present;
    u8 ambiguous;
    u8 complete;
    u8 _pad[6];
} http1_traceparent_scan_t;

static int http1_traceparent_match(u32 index, void *data) {
    enum {
        k_http1_line_end_pos_max = TRACE_BUF_SIZE - 2,
        k_http1_eoh_pos_max = TRACE_BUF_SIZE - 4,
        k_http1_name_pos_max = TRACE_BUF_SIZE - k_http1_traceparent_name_field_len,
    };

    if (index >= TRACE_BUF_SIZE) {
        return 1;
    }
    bpf_clamp_umax(index, TRACE_BUF_SIZE - 1);

    http1_traceparent_scan_t *scan = data;
    u16 buf_len = scan->buf_len;
    bpf_clamp_umax(buf_len, TRACE_BUF_SIZE);
    if (index >= buf_len) {
        return 1;
    }

    unsigned char *field = scan->buf + index;
    const u16 remaining = buf_len - index;
    if (scan->line_start && remaining >= 2 && index <= k_http1_line_end_pos_max) {
        u32 line_end_pos = index;
        bpf_clamp_umax(line_end_pos, k_http1_line_end_pos_max);
        const unsigned char *line_end = scan->buf + line_end_pos;
        if (line_end[0] == '\r' && line_end[1] == '\n') {
            scan->complete = 1;
            return 1;
        }
    }
    if (remaining >= 4 && index <= k_http1_eoh_pos_max) {
        u32 eoh_pos = index;
        bpf_clamp_umax(eoh_pos, k_http1_eoh_pos_max);
        if (is_eoh(scan->buf + eoh_pos)) {
            scan->complete = 1;
            return 1;
        }
    }

    if (scan->line_start && remaining >= k_http1_traceparent_name_field_len &&
        index <= k_http1_name_pos_max) {
        u32 name_pos = index;
        bpf_clamp_umax(name_pos, k_http1_name_pos_max);
        const unsigned char *name = scan->buf + name_pos;
        if (!is_traceparent_name(name)) {
            goto done;
        }
        if (scan->present) {
            scan->ambiguous = 1;
            return 1;
        }

        scan->present = 1;
        scan->field_pos = index;
    }

done:
    scan->line_start = *field == '\n';
    return 0;
}

static __noinline u8 decode_http1_traceparent_at(
    unsigned char *buf, u16 buf_len, u32 field_pos, tp_info_t *tp, u8 is_client) {
    enum {
        k_http1_ows_pos_max =
            TRACE_BUF_SIZE - k_http1_traceparent_name_field_len - k_http_traceparent_ows_scan - 1,
        k_http1_value_pos_max = TRACE_BUF_SIZE - k_http1_traceparent_value_len - 1,
    };

    if (!buf) {
        return 0;
    }
    bpf_clamp_umax(buf_len, TRACE_BUF_SIZE);
    if (field_pos > k_http1_ows_pos_max || field_pos >= buf_len) {
        return 0;
    }
    bpf_clamp_umax(field_pos, k_http1_ows_pos_max);

    const u16 remaining = buf_len - field_pos;
    if (remaining <= k_http1_traceparent_name_field_len + k_http_traceparent_ows_scan) {
        return 0;
    }

    const u8 value_offset = http_traceparent_value_offset(buf + field_pos);
    if (!value_offset || value_offset == k_http_traceparent_value_offset_unknown ||
        remaining <= value_offset + k_http1_traceparent_value_len) {
        return 0;
    }

    u32 value_pos = field_pos + value_offset;
    if (value_pos > k_http1_value_pos_max) {
        return 0;
    }
    bpf_clamp_umax(value_pos, k_http1_value_pos_max);
    unsigned char value[k_http1_traceparent_value_len + 1] = {};
    if (bpf_probe_read(value, sizeof(value), buf + value_pos)) {
        return 0;
    }
    const unsigned char next = value[k_http1_traceparent_value_len];
    if (!valid_http_traceparent_value(value, next)) {
        return 0;
    }
    if (next == '\r') {
        u32 newline_pos = value_pos + k_http1_traceparent_value_len + 1;
        if (remaining <= value_offset + k_http1_traceparent_value_len + 1 ||
            newline_pos >= TRACE_BUF_SIZE) {
            return 0;
        }
        bpf_clamp_umax(newline_pos, TRACE_BUF_SIZE - 1);
        if (buf[newline_pos] != '\n') {
            return 0;
        }
    }

    if (tp) {
        enum {
            k_traceparent_trace_id_offset = 3,
            k_traceparent_trace_id_len = TRACE_ID_SIZE_BYTES * 2,
            k_traceparent_span_id_offset =
                k_traceparent_trace_id_offset + k_traceparent_trace_id_len + 1,
            k_traceparent_span_id_len = SPAN_ID_SIZE_BYTES * 2,
            k_traceparent_flags_offset =
                k_traceparent_span_id_offset + k_traceparent_span_id_len + 1,
            k_traceparent_flags_len = 2,
        };
        decode_hex(tp->trace_id, value + k_traceparent_trace_id_offset, k_traceparent_trace_id_len);
        decode_hex(is_client ? tp->span_id : tp->parent_id,
                   value + k_traceparent_span_id_offset,
                   k_traceparent_span_id_len);
        decode_hex(&tp->flags, value + k_traceparent_flags_offset, k_traceparent_flags_len);
        tp->flags = traceparent_flags_for_version(value, tp->flags);
        if (is_client) {
            __builtin_memset(tp->parent_id, 0, sizeof(tp->parent_id));
        }
    }
    return 1;
}

static __always_inline enum http1_traceparent_scan_result
http1_traceparent_scan_result(const http1_traceparent_scan_t *scan, u32 *field_pos) {
    if (!scan->present) {
        return scan->complete ? k_http1_traceparent_scan_absent : k_http1_traceparent_scan_unknown;
    }
    if (scan->ambiguous || !scan->complete ||
        !decode_http1_traceparent_at(scan->buf, scan->buf_len, scan->field_pos, NULL, 0)) {
        return k_http1_traceparent_scan_present;
    }

    if (field_pos) {
        *field_pos = scan->field_pos;
    }
    return k_http1_traceparent_scan_found;
}

static __always_inline enum http1_traceparent_scan_result
scan_http1_traceparent(unsigned char *buf, u16 buf_len, u32 *field_pos) {
    if (!buf || !buf_len) {
        return k_http1_traceparent_scan_unknown;
    }

    http1_traceparent_scan_t scan = {
        .buf = buf,
        .field_pos = k_tp_pos_not_found,
        .buf_len = buf_len,
        .line_start = 1,
    };
    bpf_loop(min((u32)buf_len, (u32)TRACE_BUF_SIZE), http1_traceparent_match, &scan, 0);
    return http1_traceparent_scan_result(&scan, field_pos);
}

static __always_inline enum http1_traceparent_scan_result
scan_http1_traceparent_legacy(unsigned char *buf, u16 buf_len, u32 *field_pos) {
    if (!buf || !buf_len) {
        return k_http1_traceparent_scan_unknown;
    }

    http1_traceparent_scan_t scan = {
        .buf = buf,
        .field_pos = k_tp_pos_not_found,
        .buf_len = buf_len,
        .line_start = 1,
    };
    const u16 nr_loops = min(buf_len, (u16)k_http1_legacy_scan_loops);

#pragma clang loop unroll(disable)
    for (u16 i = 0; i < k_http1_legacy_scan_loops; i++) {
        if (i >= nr_loops || http1_traceparent_match(i, &scan)) {
            break;
        }
    }

    return http1_traceparent_scan_result(&scan, field_pos);
}

static int tp_match(u32 index, void *data) {
    if (index >= (TRACE_BUF_SIZE - TRACE_PARENT_HEADER_LEN)) {
        return 1;
    }

    struct callback_ctx *ctx = data;
    unsigned char *s = &(ctx->buf[index]);

    if (is_eoh(s)) {
        return 1;
    }

    if ((index == 0 || ctx->buf[index - 1] == '\n') && is_traceparent_name(s)) {
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
    u8 line_start = 1;

    for (u16 i = 0; i < k_besteffort_max_loops; i++) {
        // buf is null terminated
        if (*buf == '\0') {
            return NULL;
        }

        if (is_eoh(buf)) {
            return NULL;
        }

        if (line_start && is_traceparent_name(buf)) {
            return buf;
        }

        line_start = *buf == '\n';
        ++buf;
    }

    return NULL;
}
