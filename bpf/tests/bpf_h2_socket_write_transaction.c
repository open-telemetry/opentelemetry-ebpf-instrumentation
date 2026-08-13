// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

struct sk_msg_md {
    void *data;
    void *data_end;
    u32 size;
};

enum sk_action {
    SK_DROP = 0,
    SK_PASS = 1,
};

static unsigned char message[256];
static unsigned int message_len;
static unsigned int pull_calls;
static unsigned int failed_pulls;
static bool fail_pop;

static long
test_msg_pull_data(struct sk_msg_md *msg, u32 start, u32 end, unsigned long long flags) {
    (void)start;
    (void)flags;
    pull_calls++;
    if ((failed_pulls & (1U << pull_calls)) || end > message_len) {
        return -1;
    }
    msg->data = message + start;
    msg->data_end = message + end;
    return 0;
}

static long test_msg_pop_data(struct sk_msg_md *msg, u32 start, u32 len, unsigned long long flags) {
    (void)flags;
    if (fail_pop || start > message_len || len > message_len - start) {
        return -1;
    }
    memmove(message + start, message + start + len, message_len - start - len);
    message_len -= len;
    msg->size = message_len;
    msg->data = message;
    msg->data_end = message + message_len;
    return 0;
}

#define bpf_msg_pull_data test_msg_pull_data
#define bpf_msg_pop_data test_msg_pop_data
#include <tpinjector/h2_write_transaction.h>
#undef bpf_msg_pull_data
#undef bpf_msg_pop_data

static void expect(bool condition, const char *message_text) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message_text);
        exit(1);
    }
}

static struct sk_msg_md reset_message(bool pushed) {
    const u32 payload_len = 8;
    memset(message, 0, sizeof(message));
    message[2] = payload_len + k_h2_tp_hpack_size;
    message[3] = k_h2_frame_headers;
    message[4] = k_h2_flag_end_headers;
    message[8] = 1;
    message_len = k_h2_frame_header_len + payload_len;
    if (pushed) {
        memset(message + message_len, 0xab, k_h2_tp_hpack_size);
        message_len += k_h2_tp_hpack_size;
    }
    pull_calls = 0;
    failed_pulls = 0;
    fail_pop = false;
    return (struct sk_msg_md){
        .data = message,
        .data_end = message + message_len,
        .size = message_len,
    };
}

static struct sk_msg_md reset_continuation_message(void) {
    const u32 payload_len = 8;
    memset(message, 0, sizeof(message));
    message[2] = payload_len;
    message[3] = k_h2_frame_headers;
    message[4] = 0;
    message[8] = 1;
    message_len = k_h2_frame_header_len + payload_len;
    memset(message + message_len, 0xcd, k_h2_tp_continuation_size);
    message_len += k_h2_tp_continuation_size;
    pull_calls = 0;
    failed_pulls = 0;
    fail_pop = false;
    return (struct sk_msg_md){
        .data = message,
        .data_end = message + message_len,
        .size = message_len,
    };
}

static struct sk_msg_md shift_message(u32 prefix_len) {
    memmove(message + prefix_len, message, message_len);
    memset(message, 0xee, prefix_len);
    message_len += prefix_len;
    return (struct sk_msg_md){
        .data = message,
        .data_end = message + message_len,
        .size = message_len,
    };
}

int main(void) {
    const u32 payload_len = 8;
    const u32 inject_offset = k_h2_frame_header_len + payload_len;

    struct sk_msg_md msg = reset_message(true);
    expect(rollback_h2_socket_write(&msg, inject_offset, 0, payload_len, true),
           "verified socket rollback succeeds");
    expect(message_len == inject_offset, "socket rollback removes pushed bytes");
    expect(message[0] == 0 && message[1] == 0 && message[2] == payload_len,
           "socket rollback restores the frame length");

    msg = reset_message(true);
    const u32 frame_offset = 5;
    msg = shift_message(frame_offset);
    expect(rollback_h2_socket_write(
               &msg, frame_offset + inject_offset, frame_offset, payload_len, true),
           "socket rollback supports a batched frame offset");
    expect(message[0] == 0xee && message[frame_offset + 2] == payload_len,
           "socket rollback preserves the prefix and restores the selected frame");

    msg = reset_message(true);
    fail_pop = true;
    expect(!rollback_h2_socket_write(&msg, inject_offset, 0, payload_len, true),
           "failed pop makes rollback unverified");
    expect(message_len == inject_offset + k_h2_tp_hpack_size,
           "failed pop retains the uncertain mutation for the caller to drop");

    msg = reset_message(false);
    failed_pulls = 1U << 1;
    expect(!rollback_h2_socket_write(&msg, inject_offset, 0, payload_len, false),
           "failed length restoration makes rollback unverified");

    msg = reset_message(false);
    failed_pulls = 1U << 2;
    expect(!rollback_h2_socket_write(&msg, inject_offset, 0, payload_len, false),
           "failed length readback makes rollback unverified");
    expect(message[2] == payload_len,
           "readback failure can restore bytes but remains unverified and must drop");

    const u32 continuation_offset = k_h2_frame_header_len + payload_len;
    msg = reset_continuation_message();
    expect(
        rollback_h2_socket_continuation(&msg, continuation_offset, 0, k_h2_flag_end_headers, true),
        "verified continuation rollback succeeds");
    expect(message_len == continuation_offset, "continuation rollback removes the pushed frame");
    expect(message[4] == k_h2_flag_end_headers, "continuation rollback restores END_HEADERS");

    msg = reset_continuation_message();
    fail_pop = true;
    expect(
        !rollback_h2_socket_continuation(&msg, continuation_offset, 0, k_h2_flag_end_headers, true),
        "failed continuation pop makes rollback unverified");

    msg = reset_continuation_message();
    failed_pulls = 1U << 1;
    expect(
        !rollback_h2_socket_continuation(&msg, continuation_offset, 0, k_h2_flag_end_headers, true),
        "failed END_HEADERS restoration makes rollback unverified");

    msg = reset_continuation_message();
    failed_pulls = 1U << 2;
    expect(
        !rollback_h2_socket_continuation(&msg, continuation_offset, 0, k_h2_flag_end_headers, true),
        "failed END_HEADERS readback makes rollback unverified");
    expect(message[4] == k_h2_flag_end_headers,
           "readback failure restores END_HEADERS but remains unverified");

    expect(h2_socket_transaction_next_state(k_h2_socket_transaction_committed,
                                            k_go_h2_state_obi_pending) == k_go_h2_state_obi_written,
           "successful socket commit transitions PENDING to WRITTEN");
    expect(h2_socket_transaction_verdict(k_h2_socket_transaction_committed) == SK_PASS,
           "successful socket commit passes the message");
    expect(h2_socket_transaction_next_state(k_h2_socket_transaction_rollback_verified,
                                            k_go_h2_state_obi_pending) == k_go_h2_state_obi_pending,
           "verified rollback leaves the stream PENDING for fallback");
    expect(h2_socket_transaction_verdict(k_h2_socket_transaction_rollback_verified) == SK_PASS,
           "verified rollback passes the pristine message");
    expect(h2_socket_transaction_next_state(k_h2_socket_transaction_rollback_uncertain,
                                            k_go_h2_state_obi_pending) == k_go_h2_state_skip,
           "unverified rollback transitions PENDING to SKIP");
    expect(h2_socket_transaction_next_state(k_h2_socket_transaction_rollback_uncertain,
                                            k_go_h2_state_obi_written) == k_go_h2_state_skip,
           "unverified rollback makes every prior state fail closed");
    expect(h2_socket_transaction_verdict(k_h2_socket_transaction_rollback_uncertain) == SK_DROP,
           "unverified rollback drops the uncertain message");

    printf("OK: %s\n", __FILE__);
    return 0;
}
