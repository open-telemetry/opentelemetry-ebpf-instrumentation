// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_builtins.h>

#include <common/h2_defs.h>

struct sk_msg_md {
    void *data;
    void *data_end;
    u32 size;
};

static long test_msg_pull_data(struct sk_msg_md *msg, u32 start, u32 end, u64 flags);
static long test_msg_push_data(struct sk_msg_md *msg, u32 start, u32 len, u64 flags);
static long test_msg_pop_data(struct sk_msg_md *msg, u32 start, u32 len, u64 flags);

#define bpf_msg_pull_data test_msg_pull_data
#define bpf_msg_push_data test_msg_push_data
#define bpf_msg_pop_data test_msg_pop_data
#include <tpinjector/h2_write_transaction.h>
#undef bpf_msg_pop_data
#undef bpf_msg_push_data
#undef bpf_msg_pull_data

static unsigned char message[256];
static unsigned char original[256];
static unsigned char expected[k_h2_tp_hpack_size];
static u32 message_len;
static u32 pull_calls;
static u64 failed_pull_calls;
static bool force_push_failure;
static u32 forced_pop_failures;

enum {
    k_preflight_pull_call = 1,
    k_write_pull_call,
    k_frame_pull_call,
    k_rollback_pull_after_write_failure_call = k_frame_pull_call,
};

static long test_msg_pull_data(struct sk_msg_md *msg, u32 start, u32 end, u64 flags) {
    (void)flags;
    pull_calls++;
    if (failed_pull_calls & (1ULL << pull_calls)) {
        return -1;
    }
    if (start > message_len || end < start || end > message_len) {
        return -1;
    }
    msg->data = message + start;
    msg->data_end = message + end;
    return 0;
}

static long test_msg_push_data(struct sk_msg_md *msg, u32 start, u32 len, u64 flags) {
    (void)flags;
    if (force_push_failure || start > message_len || len > sizeof(message) - message_len) {
        return -1;
    }
    memmove(message + start + len, message + start, message_len - start);
    memset(message + start, 0, len);
    message_len += len;
    msg->size = message_len;
    msg->data = message;
    msg->data_end = message + message_len;
    return 0;
}

static long test_msg_pop_data(struct sk_msg_md *msg, u32 start, u32 len, u64 flags) {
    (void)flags;
    if (forced_pop_failures) {
        forced_pop_failures--;
        return -1;
    }
    if (start > message_len || len > message_len - start) {
        return -1;
    }
    memmove(message + start, message + start + len, message_len - start - len);
    message_len -= len;
    msg->size = message_len;
    msg->data = message;
    msg->data_end = message + message_len;
    return 0;
}

static void expect(bool condition, const char *description) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", description);
        exit(1);
    }
}

static struct sk_msg_md reset_message(void) {
    enum { k_payload_len = 8 };

    for (u32 i = 0; i < sizeof(message); i++) {
        message[i] = (unsigned char)i;
        expected[i % sizeof(expected)] = (unsigned char)(0xa0 + i);
    }
    message[0] = 0;
    message[1] = 0;
    message[2] = k_payload_len;
    message_len = k_h2_frame_header_len + k_payload_len;
    memcpy(original, message, message_len);
    pull_calls = 0;
    failed_pull_calls = 0;
    force_push_failure = false;
    forced_pop_failures = 0;

    return (struct sk_msg_md){
        .data = message,
        .data_end = message + message_len,
        .size = message_len,
    };
}

static h2_socket_transaction_outcome_t run_transaction(struct sk_msg_md *msg) {
    enum { k_payload_len = 8 };
    return h2_write_socket_transaction(
        msg, 0, k_payload_len, k_h2_frame_header_len + k_payload_len, expected);
}

static void expect_original(const char *description) {
    expect(message_len == k_h2_frame_header_len + 8, description);
    expect(memcmp(message, original, message_len) == 0, description);
}

static void test_commit(void) {
    struct sk_msg_md msg = reset_message();
    expect(run_transaction(&msg) == k_h2_socket_transaction_committed,
           "successful transaction commits");
    expect(message_len == k_h2_frame_header_len + 8 + k_h2_tp_hpack_size,
           "commit grows the message once");
    expect(h2_frame_len_bytes_are(message, 8 + k_h2_tp_hpack_size),
           "commit publishes the new frame length");
    expect(memcmp(message + k_h2_frame_header_len + 8, expected, sizeof(expected)) == 0,
           "commit writes the expected HPACK field");
}

static void test_preflight_pull_failure(void) {
    struct sk_msg_md msg = reset_message();
    failed_pull_calls = 1ULL << k_preflight_pull_call;
    expect(run_transaction(&msg) == k_h2_socket_transaction_no_mutation,
           "preflight pull failure does not mutate");
    expect_original("preflight pull failure does not mutate");
}

static void test_push_failure(void) {
    struct sk_msg_md msg = reset_message();
    force_push_failure = true;
    expect(run_transaction(&msg) == k_h2_socket_transaction_no_mutation,
           "push failure does not mutate");
    expect_original("push failure does not mutate");
}

static void test_verified_rollback_pull_failure(u32 failed_pull_call, const char *description) {
    struct sk_msg_md msg = reset_message();
    failed_pull_calls = 1ULL << failed_pull_call;
    expect(run_transaction(&msg) == k_h2_socket_transaction_rollback_verified, description);
    expect_original(description);
}

static void test_retried_rollback_pop(void) {
    struct sk_msg_md msg = reset_message();
    failed_pull_calls = 1ULL << k_write_pull_call;
    forced_pop_failures = 1;
    expect(run_transaction(&msg) == k_h2_socket_transaction_rollback_verified,
           "transient pop failure is retried and verified");
    expect_original("transient pop failure is retried and verified");
}

static void test_retried_rollback_pull(void) {
    struct sk_msg_md msg = reset_message();
    failed_pull_calls =
        (1ULL << k_write_pull_call) | (1ULL << k_rollback_pull_after_write_failure_call);
    expect(run_transaction(&msg) == k_h2_socket_transaction_rollback_verified,
           "transient rollback pull failure is retried and verified");
    expect_original("transient rollback pull failure is retried and verified");
}

int main(void) {
    test_commit();

    test_preflight_pull_failure();
    test_push_failure();

    test_verified_rollback_pull_failure(k_write_pull_call, "post-push pull failure rolls back");
    test_verified_rollback_pull_failure(k_frame_pull_call, "frame pull failure rolls back");

    test_retried_rollback_pop();
    test_retried_rollback_pull();

    struct sk_msg_md msg = reset_message();
    failed_pull_calls = 1ULL << k_write_pull_call;
    forced_pop_failures = 2;
    expect(run_transaction(&msg) == k_h2_socket_transaction_rollback_uncertain,
           "two failed pop attempts keep rollback uncertain");

    puts("OK: bpf_h2_socket_write_transaction.c");
    return 0;
}
