// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>

#include <common/h2_defs.h>

typedef enum h2_socket_transaction_outcome {
    k_h2_socket_transaction_no_mutation,
    k_h2_socket_transaction_committed,
    k_h2_socket_transaction_rollback_verified,
    k_h2_socket_transaction_rollback_uncertain,
} h2_socket_transaction_outcome_t;

static __always_inline bool h2_frame_len_bytes_are(const unsigned char *data, u32 expected) {
    return data[0] == ((expected >> 16) & 0xff) && data[1] == ((expected >> 8) & 0xff) &&
           data[2] == (expected & 0xff);
}

static __always_inline void h2_store_frame_len(unsigned char *data, u32 len) {
    data[0] = (len >> 16) & 0xff;
    data[1] = (len >> 8) & 0xff;
    data[2] = len & 0xff;
}

static __always_inline bool h2_restore_socket_message(struct sk_msg_md *msg,
                                                      u32 original_size,
                                                      u32 frame_offset,
                                                      u32 payload_len,
                                                      u32 inject_offset) {
    bool popped = bpf_msg_pop_data(msg, inject_offset, k_h2_tp_hpack_size, 0) == 0;
    if (!popped) {
        popped = bpf_msg_pop_data(msg, inject_offset, k_h2_tp_hpack_size, 0) == 0;
    }
    if (!popped) {
        return false;
    }
    if (msg->size != original_size) {
        return false;
    }

    bool pulled = bpf_msg_pull_data(msg, frame_offset, frame_offset + 3, 0) == 0;
    if (!pulled) {
        pulled = bpf_msg_pull_data(msg, frame_offset, frame_offset + 3, 0) == 0;
    }
    if (!pulled) {
        return false;
    }

    unsigned char *data = msg->data;
    if (!data || (void *)data + 3 > msg->data_end) {
        return false;
    }

    h2_store_frame_len(data, payload_len);
    return h2_frame_len_bytes_are(data, payload_len);
}

// Inserts one complete HPACK field. The frame-length store is the socket-message commit point:
// every fallible socket helper runs before it.
static __always_inline h2_socket_transaction_outcome_t
h2_write_socket_transaction(struct sk_msg_md *msg,
                            u32 frame_offset,
                            u32 payload_len,
                            u32 inject_offset,
                            const unsigned char *expected) {
    const u32 original_size = msg->size;
    if (!expected || payload_len > k_h2_default_max_frame_size - k_h2_tp_hpack_size ||
        frame_offset > original_size || original_size - frame_offset < k_h2_frame_header_len ||
        payload_len > original_size - frame_offset - k_h2_frame_header_len ||
        inject_offset < frame_offset + k_h2_frame_header_len ||
        inject_offset > frame_offset + k_h2_frame_header_len + payload_len ||
        original_size > (u32)-1 - k_h2_tp_hpack_size) {
        return k_h2_socket_transaction_no_mutation;
    }

    if (bpf_msg_pull_data(msg, frame_offset, frame_offset + 3, 0) != 0) {
        return k_h2_socket_transaction_no_mutation;
    }
    const unsigned char *frame = msg->data;
    if (!frame || (void *)frame + 3 > msg->data_end ||
        !h2_frame_len_bytes_are(frame, payload_len)) {
        return k_h2_socket_transaction_no_mutation;
    }

    if (bpf_msg_push_data(msg, inject_offset, k_h2_tp_hpack_size, 0) != 0) {
        return k_h2_socket_transaction_no_mutation;
    }

    if (bpf_msg_pull_data(msg, inject_offset, inject_offset + k_h2_tp_hpack_size, 0) != 0) {
        return h2_restore_socket_message(
                   msg, original_size, frame_offset, payload_len, inject_offset)
                   ? k_h2_socket_transaction_rollback_verified
                   : k_h2_socket_transaction_rollback_uncertain;
    }

    unsigned char *data = msg->data;
    if (!data || (void *)data + k_h2_tp_hpack_size > msg->data_end) {
        return h2_restore_socket_message(
                   msg, original_size, frame_offset, payload_len, inject_offset)
                   ? k_h2_socket_transaction_rollback_verified
                   : k_h2_socket_transaction_rollback_uncertain;
    }

    __builtin_memcpy(data, expected, k_h2_tp_hpack_size);

    if (bpf_msg_pull_data(msg, frame_offset, frame_offset + 3, 0) != 0) {
        return h2_restore_socket_message(
                   msg, original_size, frame_offset, payload_len, inject_offset)
                   ? k_h2_socket_transaction_rollback_verified
                   : k_h2_socket_transaction_rollback_uncertain;
    }

    data = msg->data;
    if (!data || (void *)data + 3 > msg->data_end) {
        return h2_restore_socket_message(
                   msg, original_size, frame_offset, payload_len, inject_offset)
                   ? k_h2_socket_transaction_rollback_verified
                   : k_h2_socket_transaction_rollback_uncertain;
    }

    h2_store_frame_len(data, payload_len + k_h2_tp_hpack_size);
    return k_h2_socket_transaction_committed;
}
