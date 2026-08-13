// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/go_h2_stream_state.h>
#include <common/h2_defs.h>

typedef enum h2_socket_transaction_outcome {
    k_h2_socket_transaction_committed,
    k_h2_socket_transaction_rollback_verified,
    k_h2_socket_transaction_rollback_uncertain,
} h2_socket_transaction_outcome_t;

static __always_inline u8 h2_socket_transaction_next_state(h2_socket_transaction_outcome_t outcome,
                                                           u8 current_state) {
    if (outcome == k_h2_socket_transaction_rollback_uncertain) {
        return k_go_h2_state_skip;
    }
    if (current_state != k_go_h2_state_obi_pending) {
        return current_state;
    }
    if (outcome == k_h2_socket_transaction_committed) {
        return k_go_h2_state_obi_written;
    }
    return current_state;
}

static __always_inline int h2_socket_transaction_verdict(h2_socket_transaction_outcome_t outcome) {
    return outcome == k_h2_socket_transaction_rollback_uncertain ? SK_DROP : SK_PASS;
}

static __always_inline bool h2_write_frame_len(struct sk_msg_md *msg, u32 frame_offset, u32 len) {
    enum { k_h2_frame_len_field = 3 };

    if (frame_offset > msg->size || msg->size - frame_offset < k_h2_frame_len_field) {
        return false;
    }
    if (bpf_msg_pull_data(msg, frame_offset, frame_offset + k_h2_frame_len_field, 0) != 0) {
        return false;
    }

    unsigned char *data = msg->data;
    if (!data || (void *)data + k_h2_frame_len_field > msg->data_end) {
        return false;
    }

    data[0] = (len >> 16) & 0xFF;
    data[1] = (len >> 8) & 0xFF;
    data[2] = len & 0xFF;

    return true;
}

static __always_inline bool h2_frame_len_is(struct sk_msg_md *msg, u32 frame_offset, u32 expected) {
    if (frame_offset > msg->size || msg->size - frame_offset < 3) {
        return false;
    }
    if (bpf_msg_pull_data(msg, frame_offset, frame_offset + 3, 0) != 0) {
        return false;
    }
    const unsigned char *data = msg->data;
    if (!data || (void *)data + 3 > msg->data_end) {
        return false;
    }
    const u32 actual = ((u32)data[0] << 16) | ((u32)data[1] << 8) | data[2];
    return actual == expected;
}

static __always_inline bool
h2_write_frame_flags(struct sk_msg_md *msg, u32 frame_offset, u8 flags) {
    const u32 flags_offset = frame_offset + 4;
    if (frame_offset > msg->size || msg->size - frame_offset < 5) {
        return false;
    }
    if (bpf_msg_pull_data(msg, flags_offset, flags_offset + 1, 0) != 0) {
        return false;
    }
    unsigned char *data = msg->data;
    if (!data || (void *)data + 1 > msg->data_end) {
        return false;
    }
    data[0] = flags;
    return true;
}

static __always_inline bool
h2_frame_flags_are(struct sk_msg_md *msg, u32 frame_offset, u8 expected) {
    const u32 flags_offset = frame_offset + 4;
    if (frame_offset > msg->size || msg->size - frame_offset < 5) {
        return false;
    }
    if (bpf_msg_pull_data(msg, flags_offset, flags_offset + 1, 0) != 0) {
        return false;
    }
    const unsigned char *data = msg->data;
    return data && (void *)data + 1 <= msg->data_end && data[0] == expected;
}

static __always_inline bool
h2_read_frame_flags(struct sk_msg_md *msg, u32 frame_offset, u8 *flags) {
    const u32 flags_offset = frame_offset + 4;
    if (!flags || frame_offset > msg->size || msg->size - frame_offset < 5 ||
        bpf_msg_pull_data(msg, flags_offset, flags_offset + 1, 0) != 0) {
        return false;
    }
    const unsigned char *data = msg->data;
    if (!data || (void *)data + 1 > msg->data_end) {
        return false;
    }
    *flags = data[0];
    return true;
}

static __always_inline bool rollback_h2_socket_write(
    struct sk_msg_md *msg, u32 inject_offset, u32 frame_offset, u32 payload_len, bool pushed) {
    if (pushed && bpf_msg_pop_data(msg, inject_offset, k_h2_tp_hpack_size, 0) != 0) {
        return false;
    }
    if (!h2_write_frame_len(msg, frame_offset, payload_len)) {
        return false;
    }
    return h2_frame_len_is(msg, frame_offset, payload_len);
}

static __always_inline bool rollback_h2_socket_continuation(
    struct sk_msg_md *msg, u32 append_offset, u32 frame_offset, u8 original_flags, bool pushed) {
    const bool popped =
        !pushed || bpf_msg_pop_data(msg, append_offset, k_h2_tp_continuation_size, 0) == 0;
    const bool restored = h2_write_frame_flags(msg, frame_offset, original_flags) &&
                          h2_frame_flags_are(msg, frame_offset, original_flags);
    return popped && restored;
}
