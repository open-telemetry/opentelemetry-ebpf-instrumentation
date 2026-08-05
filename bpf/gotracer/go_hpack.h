// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/http_types.h>
#include <common/trace_util.h>

enum {
    k_go_hpack_traceparent_name_len = 11,
    k_go_hpack_traceparent_value_len = 55,
    k_go_hpack_method_name_len = 7,
    k_go_hpack_authority_name_len = 10,
    k_go_hpack_status_name_len = 7,
};

enum go_hpack_block_state : u8 {
    k_go_hpack_block_none,
    k_go_hpack_block_request_candidate,
    k_go_hpack_block_request,
    k_go_hpack_block_non_request,
};

enum go_hpack_block_transition : u8 {
    k_go_hpack_block_unchanged,
    k_go_hpack_block_store,
    k_go_hpack_block_clear,
};

enum go_hpack_traceparent_class : u8 {
    k_go_hpack_traceparent_unknown,
    k_go_hpack_traceparent_absent,
    k_go_hpack_traceparent_authoritative,
    k_go_hpack_traceparent_non_authoritative,
};

typedef struct go_hpack_block {
    tp_info_t tp;
    u8 state;
    u8 has_traceparent;
    u8 authoritative;
    u8 _pad[5];
} go_hpack_block_t;

static const unsigned char go_hpack_traceparent_name[k_go_hpack_traceparent_name_len] =
    "traceparent";
static const unsigned char go_hpack_method_name[k_go_hpack_method_name_len] = ":method";
static const unsigned char go_hpack_authority_name[k_go_hpack_authority_name_len] = ":authority";
static const unsigned char go_hpack_status_name[k_go_hpack_status_name_len] = ":status";

static __always_inline u8 go_hpack_starts_header_block(const unsigned char *name, u64 name_len) {
    return name && name_len && name[0] == ':';
}

static __always_inline u8 go_hpack_name_matches(const unsigned char *name,
                                                u64 name_len,
                                                const unsigned char *expected,
                                                u64 expected_len) {
    return name && expected && name_len == expected_len &&
           __builtin_memcmp(name, expected, expected_len) == 0;
}

static __always_inline void go_hpack_clear_block(go_hpack_block_t *block) {
    if (block) {
        __builtin_memset(block, 0, sizeof(*block));
    }
}

static __always_inline u8 go_hpack_observe_pseudo_header(go_hpack_block_t *block,
                                                         const unsigned char *name,
                                                         u64 name_len) {
    if (!block || !go_hpack_starts_header_block(name, name_len)) {
        return k_go_hpack_block_unchanged;
    }

    if (go_hpack_name_matches(name, name_len, go_hpack_method_name, k_go_hpack_method_name_len)) {
        go_hpack_clear_block(block);
        block->state = k_go_hpack_block_request;
        return k_go_hpack_block_store;
    }

    if (go_hpack_name_matches(name, name_len, go_hpack_status_name, k_go_hpack_status_name_len)) {
        go_hpack_clear_block(block);
        return k_go_hpack_block_clear;
    }

    if (go_hpack_name_matches(
            name, name_len, go_hpack_authority_name, k_go_hpack_authority_name_len) &&
        block->state != k_go_hpack_block_request) {
        go_hpack_clear_block(block);
        block->state = k_go_hpack_block_request_candidate;
        return k_go_hpack_block_store;
    }

    return k_go_hpack_block_unchanged;
}

static __always_inline u8 go_hpack_is_traceparent_name(const unsigned char *name, u64 name_len) {
    return go_hpack_name_matches(
        name, name_len, go_hpack_traceparent_name, k_go_hpack_traceparent_name_len);
}

static __always_inline u8 go_hpack_decode_traceparent(const unsigned char *name,
                                                      u64 name_len,
                                                      const unsigned char *value,
                                                      u64 value_len,
                                                      go_hpack_block_t *block) {
    if (!name || !value || !block || !go_hpack_is_traceparent_name(name, name_len) ||
        !valid_traceparent_value_length(value, value_len)) {
        return 0;
    }

    go_hpack_block_t decoded = {};
    decode_hex(decoded.tp.trace_id, value + 3, TRACE_ID_CHAR_LEN);
    decode_hex(decoded.tp.span_id, value + 36, SPAN_ID_CHAR_LEN);
    decoded.tp.flags = 0;
    decode_hex(&decoded.tp.flags, value + 53, FLAGS_CHAR_LEN);
    decoded.tp.flags = traceparent_flags_for_version(value, decoded.tp.flags);
    preserve_outbound_traceparent(&decoded.tp);
    decoded.state = k_go_hpack_block_request;
    decoded.has_traceparent = 1;
    decoded.authoritative = 1;
    *block = decoded;
    return 1;
}

static __always_inline u8 go_hpack_traceparent_class(const go_hpack_block_t *block) {
    if (!block) {
        return k_go_hpack_traceparent_unknown;
    }
    if (!block->has_traceparent) {
        return block->state == k_go_hpack_block_request ? k_go_hpack_traceparent_absent
                                                        : k_go_hpack_traceparent_unknown;
    }
    return block->state == k_go_hpack_block_request && block->authoritative
               ? k_go_hpack_traceparent_authoritative
               : k_go_hpack_traceparent_non_authoritative;
}

static __always_inline u8 go_hpack_can_inject_traceparent(u8 classification) {
    return classification == k_go_hpack_traceparent_absent;
}

static __always_inline u8 go_hpack_capture_traceparent(go_hpack_block_t *block,
                                                       const unsigned char *name,
                                                       u64 name_len,
                                                       const unsigned char *value,
                                                       u64 value_len) {
    if (!block) {
        return k_go_hpack_traceparent_unknown;
    }

    if (!go_hpack_is_traceparent_name(name, name_len)) {
        return k_go_hpack_traceparent_unknown;
    }

    if (block->has_traceparent) {
        block->authoritative = 0;
        return go_hpack_traceparent_class(block);
    }

    const u8 authoritative = block->state == k_go_hpack_block_request;
    block->has_traceparent = 1;
    block->authoritative = 0;
    go_hpack_block_t decoded = {};
    if (!go_hpack_decode_traceparent(name, name_len, value, value_len, &decoded)) {
        return go_hpack_traceparent_class(block);
    }

    decoded.state = authoritative ? k_go_hpack_block_request : k_go_hpack_block_non_request;
    *block = decoded;
    return go_hpack_traceparent_class(block);
}

static __always_inline void go_hpack_adopt_traceparent(tp_info_t *tp,
                                                       const go_hpack_block_t *block) {
    if (!tp || !block || block->state != k_go_hpack_block_request || !block->has_traceparent ||
        !block->authoritative) {
        return;
    }

    __builtin_memcpy(tp->trace_id, block->tp.trace_id, sizeof(tp->trace_id));
    __builtin_memcpy(tp->span_id, block->tp.span_id, sizeof(tp->span_id));
    __builtin_memset(tp->parent_id, 0, sizeof(tp->parent_id));
    tp->flags = block->tp.flags;
    tp->sampling_decision = block->tp.sampling_decision;
    tp->parent_remote = block->tp.parent_remote;
}
