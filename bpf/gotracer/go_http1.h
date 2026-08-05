// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/http_types.h>
#include <common/trace_util.h>

enum {
    k_go_http1_traceparent_name_field_len = 12,
    k_go_http1_traceparent_prefix_len = 13,
    k_go_http1_traceparent_value_len = 55,
    k_go_http1_traceparent_min_field_len =
        k_go_http1_traceparent_name_field_len + k_go_http1_traceparent_value_len,
    k_go_http1_traceparent_field_len =
        k_go_http1_traceparent_prefix_len + k_go_http1_traceparent_value_len + 2,
    k_go_http1_legacy_scan_loops = 350,
};

enum go_http1_traceparent_scan_result : u8 {
    k_go_http1_traceparent_scan_unknown = 0,
    k_go_http1_traceparent_scan_absent = 1,
    k_go_http1_traceparent_scan_found = 2,
    k_go_http1_traceparent_scan_present = 3,
};

static __always_inline u8 go_http1_server_force_root(u8 state) {
    return state == k_go_http1_traceparent_scan_unknown ||
           state == k_go_http1_traceparent_scan_present;
}

static __always_inline u8 go_http1_server_can_publish_context(u8 state, u8 state_stored) {
    return state_stored && state == k_go_http1_traceparent_scan_found;
}

static __always_inline u8 go_http1_server_can_observe_inbound_headers(u8 invocation_present,
                                                                      u64 start_monotime_ns) {
    return !invocation_present || start_monotime_ns == 0;
}

typedef struct go_http1_traceparent {
    tp_info_t tp;
    u8 authoritative;
    u8 _pad[7];
} go_http1_traceparent_t;

typedef struct go_http1_traceparent_scan {
    unsigned char *buf;
    u32 field_pos;
    u16 buf_len;
    u8 line_start;
    u8 present;
    u8 ambiguous;
    u8 _pad[7];
} go_http1_traceparent_scan_t;

static __always_inline u8 go_http1_header_map_is_definitively_empty(u8 header_map_empty,
                                                                    s64 entry_n,
                                                                    s64 return_n) {
    return header_map_empty && entry_n >= 0 && return_n == entry_n;
}

static __always_inline u8 go_http1_should_suppress_fallback(u8 header_map_empty) {
    return !header_map_empty;
}

static __always_inline u8 go_http1_capture_region(
    s64 entry_n, s64 return_n, s64 writer_size, u32 capture_capacity, u32 *region) {
    if (!region || !capture_capacity || entry_n < 0 || return_n <= entry_n ||
        return_n > writer_size) {
        return 0;
    }

    const u64 capture_len = (u64)(return_n - entry_n);
    if (capture_len >= capture_capacity) {
        return 0;
    }

    *region = (u32)capture_len;
    return 1;
}

static __always_inline u8 go_http1_reader_capture_region(u64 reader_r,
                                                         u64 reader_w,
                                                         u64 buf_len,
                                                         u32 capture_capacity,
                                                         u64 *region_start,
                                                         u16 *region_len) {
    if (!region_start || !region_len || !capture_capacity || capture_capacity > 0xffff ||
        reader_r > reader_w || reader_w > buf_len || reader_r == reader_w) {
        return 0;
    }

    *region_start = reader_r;
    *region_len = (u16)min(reader_w - reader_r, (u64)capture_capacity);
    return 1;
}

static __always_inline u8 go_http1_can_append_traceparent(s64 writer_n, s64 writer_size) {
    return writer_n >= 0 && writer_n <= writer_size &&
           writer_size - writer_n >= k_go_http1_traceparent_field_len;
}

static __always_inline u8 go_http1_has_serialized_traceparent_end(const unsigned char *field,
                                                                  u64 available,
                                                                  u64 value_end) {
    if (available <= value_end) {
        return 0;
    }

    if (field[value_end] == '\r') {
        return available > value_end + 1 && field[value_end + 1] == '\n';
    }
    if (field[value_end] != '-') {
        return 0;
    }

    const u16 scan_len = (u16)min(available, (u64)TRACE_BUF_SIZE);
#pragma clang loop unroll(disable)
    for (u16 i = (u16)(value_end + 1); i < TRACE_BUF_SIZE - 1; i++) {
        if (i + 1 >= scan_len) {
            break;
        }
        if (field[i] == '\r') {
            return field[i + 1] == '\n';
        }
        if (field[i] == '\n') {
            return 0;
        }
    }
    return 0;
}

static __always_inline u8 go_http1_decode_traceparent_field(const unsigned char *field,
                                                            u64 available,
                                                            u8 require_serialized_end,
                                                            go_http1_traceparent_t *marker) {
    if (!field || !marker || available < k_go_http1_traceparent_min_field_len) {
        return 0;
    }

    const u8 value_offset = http_traceparent_value_offset(field);
    if (!value_offset || value_offset == k_http_traceparent_value_offset_unknown ||
        available < value_offset + k_go_http1_traceparent_value_len) {
        return 0;
    }

    const unsigned char *value = field + value_offset;
    const u64 value_end = value_offset + k_go_http1_traceparent_value_len;
    if (require_serialized_end && available == value_end) {
        return 0;
    }
    const unsigned char next =
        available > value_end ? value[k_go_http1_traceparent_value_len] : '\r';
    if (!valid_http_traceparent_value(value, next) ||
        (require_serialized_end &&
         !go_http1_has_serialized_traceparent_end(field, available, value_end)) ||
        (!require_serialized_end && available > value_end && next == '\r' &&
         (available <= value_end + 1 || value[k_go_http1_traceparent_value_len + 1] != '\n'))) {
        return 0;
    }

    go_http1_traceparent_t decoded = {};
    decode_hex(decoded.tp.trace_id, value + 3, TRACE_ID_CHAR_LEN);
    decode_hex(decoded.tp.span_id, value + 36, SPAN_ID_CHAR_LEN);
    decode_hex(&decoded.tp.flags, value + 53, FLAGS_CHAR_LEN);
    decoded.tp.flags = traceparent_flags_for_version(value, decoded.tp.flags);
    preserve_outbound_traceparent(&decoded.tp);
    decoded.authoritative = 1;
    *marker = decoded;
    return 1;
}

static __always_inline u8 go_http1_decode_traceparent(const unsigned char *field,
                                                      u64 available,
                                                      go_http1_traceparent_t *marker) {
    return go_http1_decode_traceparent_field(field, available, 1, marker);
}

static __always_inline u8 go_http1_decode_traceparent_value_only(const unsigned char *field,
                                                                 u64 available,
                                                                 go_http1_traceparent_t *marker) {
    return go_http1_decode_traceparent_field(field, available, 0, marker);
}

static __noinline u8 go_http1_has_serialized_traceparent_end_at(const unsigned char *buf,
                                                                u16 buf_len,
                                                                u32 value_pos,
                                                                unsigned char next) {
    const u32 extension_pos = value_pos + k_go_http1_traceparent_value_len + 1;
    if (next == '\r') {
        if (extension_pos >= buf_len || extension_pos >= TRACE_BUF_SIZE) {
            return 0;
        }
        u32 newline_pos = extension_pos;
        bpf_clamp_umax(newline_pos, TRACE_BUF_SIZE - 1);
        return buf[newline_pos] == '\n';
    }
    if (next != '-') {
        return 0;
    }

#pragma clang loop unroll(disable)
    for (u32 pos = extension_pos; pos < TRACE_BUF_SIZE - 1; pos++) {
        if (pos + 1 >= buf_len) {
            break;
        }
        u32 scan_pos = pos;
        bpf_clamp_umax(scan_pos, TRACE_BUF_SIZE - 2);
        if (buf[scan_pos] == '\r') {
            return buf[scan_pos + 1] == '\n';
        }
        if (buf[scan_pos] == '\n') {
            return 0;
        }
    }
    return 0;
}

static __always_inline u8 go_http1_decode_traceparent_at(unsigned char *buf,
                                                         u16 buf_len,
                                                         u32 field_pos,
                                                         go_http1_traceparent_t *marker) {
    enum {
        k_go_http1_ows_pos_max = TRACE_BUF_SIZE - k_go_http1_traceparent_name_field_len -
                                 k_http_traceparent_ows_scan - 1,
        k_go_http1_value_pos_max = TRACE_BUF_SIZE - k_go_http1_traceparent_value_len - 1,
    };

    if (!buf || !marker) {
        return 0;
    }
    bpf_clamp_umax(buf_len, TRACE_BUF_SIZE);
    if (field_pos > k_go_http1_ows_pos_max || field_pos >= buf_len) {
        return 0;
    }
    bpf_clamp_umax(field_pos, k_go_http1_ows_pos_max);

    const u16 available = buf_len - field_pos;
    if (available < k_go_http1_traceparent_min_field_len) {
        return 0;
    }

    const unsigned char *field = buf + field_pos;
    const u8 value_offset = http_traceparent_value_offset(field);
    if (!value_offset || value_offset == k_http_traceparent_value_offset_unknown ||
        available <= value_offset + k_go_http1_traceparent_value_len) {
        return 0;
    }

    u32 value_pos = field_pos + value_offset;
    if (value_pos > k_go_http1_value_pos_max) {
        return 0;
    }
    bpf_clamp_umax(value_pos, k_go_http1_value_pos_max);
    const unsigned char *value = buf + value_pos;
    const unsigned char next = value[k_go_http1_traceparent_value_len];
    if (!valid_http_traceparent_value(value, next) ||
        !go_http1_has_serialized_traceparent_end_at(buf, buf_len, value_pos, next)) {
        return 0;
    }

    go_http1_traceparent_t decoded = {};
    decode_hex(decoded.tp.trace_id, value + 3, TRACE_ID_CHAR_LEN);
    decode_hex(decoded.tp.span_id, value + 36, SPAN_ID_CHAR_LEN);
    decode_hex(&decoded.tp.flags, value + 53, FLAGS_CHAR_LEN);
    decoded.tp.flags = traceparent_flags_for_version(value, decoded.tp.flags);
    preserve_outbound_traceparent(&decoded.tp);
    decoded.authoritative = 1;
    *marker = decoded;
    return 1;
}

static int go_http1_traceparent_match(u32 index, void *data) {
    if (index > TRACE_BUF_SIZE - k_go_http1_traceparent_name_field_len) {
        return 1;
    }
    bpf_clamp_umax(index, TRACE_BUF_SIZE - k_go_http1_traceparent_name_field_len);

    go_http1_traceparent_scan_t *scan = data;
    u16 buf_len = scan->buf_len;
    bpf_clamp_umax(buf_len, TRACE_BUF_SIZE);
    if (index >= buf_len || buf_len - index < k_go_http1_traceparent_name_field_len) {
        return 1;
    }

    const unsigned char *field = scan->buf + index;
    if (scan->line_start && is_traceparent_name(field)) {
        if (scan->present) {
            scan->ambiguous = 1;
            return 1;
        }
        scan->present = 1;
        scan->field_pos = index;
    }

    scan->line_start = *field == '\n';
    return 0;
}

static __always_inline enum go_http1_traceparent_scan_result
go_http1_traceparent_scan_result(const go_http1_traceparent_scan_t *scan,
                                 u8 complete,
                                 u8 relax_field_pos,
                                 go_http1_traceparent_t *traceparent) {
    if (!scan->present) {
        return complete ? k_go_http1_traceparent_scan_absent : k_go_http1_traceparent_scan_unknown;
    }

    // Make the verifier validate one bounded decoder path instead of replaying
    // it for every possible field position retained from the legacy loop.
    u32 field_pos = scan->field_pos;
    if (scan->ambiguous || !complete ||
        (relax_field_pos &&
         bpf_probe_read_kernel(&field_pos, sizeof(field_pos), &scan->field_pos)) ||
        !go_http1_decode_traceparent_at(scan->buf, scan->buf_len, field_pos, traceparent)) {
        return k_go_http1_traceparent_scan_present;
    }

    return k_go_http1_traceparent_scan_found;
}

static __noinline enum go_http1_traceparent_scan_result
go_http1_inbound_scan_result(enum http1_traceparent_scan_result result,
                             unsigned char *buf,
                             u16 buf_len,
                             u32 field_pos,
                             go_http1_traceparent_t *traceparent) {
    if (result == k_http1_traceparent_scan_absent) {
        return k_go_http1_traceparent_scan_absent;
    }
    if (result == k_http1_traceparent_scan_unknown) {
        return k_go_http1_traceparent_scan_unknown;
    }
    if (result != k_http1_traceparent_scan_found ||
        !go_http1_decode_traceparent_at(buf, buf_len, field_pos, traceparent)) {
        return k_go_http1_traceparent_scan_present;
    }
    __builtin_memcpy(
        traceparent->tp.parent_id, traceparent->tp.span_id, sizeof(traceparent->tp.parent_id));
    traceparent->tp.parent_remote = 1;
    return k_go_http1_traceparent_scan_found;
}

static __always_inline enum go_http1_traceparent_scan_result go_http1_scan_inbound_traceparent(
    unsigned char *buf, u16 buf_len, go_http1_traceparent_t *traceparent) {
    u32 field_pos = k_tp_pos_not_found;
    const enum http1_traceparent_scan_result result =
        scan_http1_traceparent(buf, buf_len, &field_pos);
    return go_http1_inbound_scan_result(result, buf, buf_len, field_pos, traceparent);
}

static __always_inline enum go_http1_traceparent_scan_result
go_http1_scan_inbound_traceparent_legacy(unsigned char *buf,
                                         u16 buf_len,
                                         go_http1_traceparent_t *traceparent) {
    u32 field_pos = k_tp_pos_not_found;
    const enum http1_traceparent_scan_result result =
        scan_http1_traceparent_legacy(buf, buf_len, &field_pos);
    return go_http1_inbound_scan_result(result, buf, buf_len, field_pos, traceparent);
}

static __always_inline void go_http1_observe_inbound_traceparent(tp_info_t *tp,
                                                                 u8 *state,
                                                                 const unsigned char *field,
                                                                 u64 available) {
    if (!tp || !state || !field) {
        return;
    }

    if (*state != k_go_http1_traceparent_scan_absent) {
        __builtin_memset(tp, 0, sizeof(*tp));
        *state = k_go_http1_traceparent_scan_present;
        return;
    }

    go_http1_traceparent_t traceparent = {};
    if (!go_http1_decode_traceparent_value_only(field, available, &traceparent)) {
        __builtin_memset(tp, 0, sizeof(*tp));
        *state = k_go_http1_traceparent_scan_present;
        return;
    }

    __builtin_memcpy(
        traceparent.tp.parent_id, traceparent.tp.span_id, sizeof(traceparent.tp.parent_id));
    traceparent.tp.parent_remote = 1;
    *tp = traceparent.tp;
    *state = k_go_http1_traceparent_scan_found;
}

static __always_inline u8 go_http1_observe_server_traceparent(u8 invocation_present,
                                                              u64 start_monotime_ns,
                                                              tp_info_t *tp,
                                                              u8 *state,
                                                              const unsigned char *field,
                                                              u64 available) {
    if (!go_http1_server_can_observe_inbound_headers(invocation_present, start_monotime_ns)) {
        return 0;
    }

    go_http1_observe_inbound_traceparent(tp, state, field, available);
    return 1;
}

static __always_inline enum go_http1_traceparent_scan_result
go_http1_scan_traceparent(unsigned char *buf, u16 buf_len, go_http1_traceparent_t *traceparent) {
    if (!buf || !traceparent || buf_len < k_go_http1_traceparent_name_field_len) {
        return k_go_http1_traceparent_scan_absent;
    }

    go_http1_traceparent_scan_t scan = {
        .buf = buf,
        .buf_len = buf_len,
        .line_start = 1,
    };
    const u32 nr_loops = (u32)buf_len - k_go_http1_traceparent_name_field_len + 1;
    bpf_loop(nr_loops, go_http1_traceparent_match, &scan, 0);
    return go_http1_traceparent_scan_result(&scan, 1, 0, traceparent);
}

static __noinline __attribute__((unused)) enum go_http1_traceparent_scan_result
go_http1_scan_traceparent_legacy(unsigned char *buf,
                                 u16 buf_len,
                                 go_http1_traceparent_t *traceparent) {
    if (!buf || !traceparent || buf_len < k_go_http1_traceparent_name_field_len) {
        return k_go_http1_traceparent_scan_absent;
    }

    const u16 nr_positions = buf_len - k_go_http1_traceparent_name_field_len + 1;
    const u16 nr_loops = min(nr_positions, (u16)k_go_http1_legacy_scan_loops);
    go_http1_traceparent_scan_t scan = {
        .buf = buf,
        .buf_len = buf_len,
        .line_start = 1,
    };

#pragma clang loop unroll(disable)
    for (u16 i = 0; i < k_go_http1_legacy_scan_loops; i++) {
        if (i >= nr_loops) {
            break;
        }

        unsigned char *field = buf + i;
        if (scan.line_start && is_traceparent_name(field)) {
            if (scan.present) {
                scan.ambiguous = 1;
                break;
            }
            scan.present = 1;
            scan.field_pos = i;
        }
        scan.line_start = *field == '\n';
    }

    return go_http1_traceparent_scan_result(&scan, nr_positions <= nr_loops, 1, traceparent);
}

static __always_inline void go_http1_adopt_traceparent(tp_info_t *tp,
                                                       const go_http1_traceparent_t *marker) {
    if (!tp || !marker || !marker->authoritative) {
        return;
    }

    __builtin_memcpy(tp->trace_id, marker->tp.trace_id, sizeof(tp->trace_id));
    __builtin_memcpy(tp->span_id, marker->tp.span_id, sizeof(tp->span_id));
    __builtin_memset(tp->parent_id, 0, sizeof(tp->parent_id));
    tp->flags = marker->tp.flags;
    tp->sampling_decision = marker->tp.sampling_decision;
    tp->parent_remote = marker->tp.parent_remote;
}
