// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/event_defs.h>
#include <common/http_types.h>
#include <common/protocol_defs.h>
#include <common/sampling_decision.h>
#include <common/trace_util.h>

enum http1_split_traceparent_role : u8 {
    k_http1_split_traceparent_none,
    k_http1_split_traceparent_server,
    k_http1_split_traceparent_client,
};

enum {
    k_http1_split_traceparent_min_len =
        k_http1_traceparent_name_field_len + k_http1_traceparent_value_len + 2,
    k_http1_split_traceparent_max_len = k_http1_traceparent_name_field_len +
                                        k_http_traceparent_ows_scan +
                                        k_http1_traceparent_value_len + 2,
};

static __always_inline u8 http1_can_adopt_client_handoff(u8 request_type) {
    return request_type == EVENT_HTTP_CLIENT;
}

static __always_inline u8 http1_expect_split_traceparent(enum http1_traceparent_scan_result result,
                                                         u8 scan_completed) {
    return scan_completed && result == k_http1_traceparent_scan_unknown;
}

static __always_inline u8 http1_scan_fully_observed(const unsigned char *buf,
                                                    u16 buf_len,
                                                    u32 bytes_len,
                                                    u8 full_scanner) {
    if (!buf || !buf_len || buf[buf_len - 1] != '\n') {
        return 0;
    }
    if (full_scanner) {
        return bytes_len < TRACE_BUF_SIZE;
    }
    return bytes_len <= k_http1_legacy_scan_loops;
}

static __always_inline enum http1_split_traceparent_role
http1_split_traceparent_role(u8 request_type, u8 direction, u8 awaiting, int bytes_len) {
    if (!awaiting || bytes_len < k_http1_split_traceparent_min_len) {
        return k_http1_split_traceparent_none;
    }
    if (request_type == EVENT_HTTP_REQUEST && direction == TCP_RECV) {
        return k_http1_split_traceparent_server;
    }
    if (request_type == EVENT_HTTP_CLIENT && direction == TCP_SEND) {
        return k_http1_split_traceparent_client;
    }
    return k_http1_split_traceparent_none;
}

static __always_inline const unsigned char *
http1_split_traceparent_value(const unsigned char *header, u32 header_len) {
    if (!header || header_len < k_http1_split_traceparent_min_len || !is_traceparent_name(header)) {
        return NULL;
    }

    const u8 value_offset = http_traceparent_value_offset(header);
    if (!value_offset || value_offset == k_http_traceparent_value_offset_unknown ||
        header_len < (u16)value_offset + k_http1_traceparent_value_len + 2) {
        return NULL;
    }

    const unsigned char *value = header + value_offset;
    if (!valid_http_traceparent_value(value, value[k_http1_traceparent_value_len]) ||
        value[k_http1_traceparent_value_len] != '\r' ||
        value[k_http1_traceparent_value_len + 1] != '\n') {
        return NULL;
    }
    return value;
}

static __always_inline void http1_prepare_adopted_traceparent(tp_info_t *tp, u8 is_client) {
    if (!tp) {
        return;
    }
    if (is_client) {
        preserve_outbound_traceparent(tp);
    } else {
        reset_sampling_decision(tp);
    }
}

static __always_inline u8 http1_adopt_split_server_traceparent(tp_info_t *tp,
                                                               const unsigned char *header,
                                                               u32 header_len) {
    enum {
        k_traceparent_trace_id_offset = 3,
        k_traceparent_span_id_offset = k_traceparent_trace_id_offset + TRACE_ID_CHAR_LEN + 1,
        k_traceparent_flags_offset = k_traceparent_span_id_offset + SPAN_ID_CHAR_LEN + 1,
    };

    const unsigned char *value = http1_split_traceparent_value(header, header_len);
    if (!tp || !value) {
        return 0;
    }

    decode_hex(tp->trace_id, value + k_traceparent_trace_id_offset, TRACE_ID_CHAR_LEN);
    decode_hex(tp->parent_id, value + k_traceparent_span_id_offset, SPAN_ID_CHAR_LEN);
    decode_hex((unsigned char *)&tp->flags, value + k_traceparent_flags_offset, FLAGS_CHAR_LEN);
    tp->flags = traceparent_flags_for_version(value, tp->flags);
    http1_prepare_adopted_traceparent(tp, 0);
    return 1;
}

static __always_inline u8 http1_adopt_split_client_traceparent(tp_info_t *tp,
                                                               const unsigned char *header,
                                                               u32 header_len) {
    enum {
        k_traceparent_trace_id_offset = 3,
        k_traceparent_span_id_offset = k_traceparent_trace_id_offset + TRACE_ID_CHAR_LEN + 1,
        k_traceparent_flags_offset = k_traceparent_span_id_offset + SPAN_ID_CHAR_LEN + 1,
    };

    const unsigned char *value = http1_split_traceparent_value(header, header_len);
    if (!tp || !value) {
        return 0;
    }

    decode_hex(tp->trace_id, value + k_traceparent_trace_id_offset, TRACE_ID_CHAR_LEN);
    decode_hex(tp->span_id, value + k_traceparent_span_id_offset, SPAN_ID_CHAR_LEN);
    decode_hex((unsigned char *)&tp->flags, value + k_traceparent_flags_offset, FLAGS_CHAR_LEN);
    tp->flags = traceparent_flags_for_version(value, tp->flags);
    __builtin_memset(tp->parent_id, 0, sizeof(tp->parent_id));
    http1_prepare_adopted_traceparent(tp, 1);
    return 1;
}
