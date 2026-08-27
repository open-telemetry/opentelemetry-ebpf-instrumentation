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

static unsigned char message[256];
static unsigned char original[256];
static unsigned char expected[k_h2_tp_hpack_size];
static u32 message_len;
static u64 fault_mask;
static u32 forced_pop_failures;

static bool transaction_fault(unsigned int boundary) {
    return fault_mask & (1ULL << boundary);
}

static long test_msg_pull_data(struct sk_msg_md *msg, u32 start, u32 end, u64 flags) {
    (void)flags;
    if (start > message_len || end < start || end > message_len) {
        return -1;
    }
    msg->data = message + start;
    msg->data_end = message + end;
    return 0;
}

static long test_msg_push_data(struct sk_msg_md *msg, u32 start, u32 len, u64 flags) {
    (void)flags;
    if (start > message_len || len > sizeof(message) - message_len) {
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

#define bpf_msg_pull_data test_msg_pull_data
#define bpf_msg_push_data test_msg_push_data
#define bpf_msg_pop_data test_msg_pop_data
#define H2_SOCKET_TRANSACTION_FAULT(boundary) transaction_fault(boundary)
#include <tpinjector/h2_write_transaction.h>
#undef H2_SOCKET_TRANSACTION_FAULT
#undef bpf_msg_pop_data
#undef bpf_msg_push_data
#undef bpf_msg_pull_data

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
    fault_mask = 0;
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

static void test_no_mutation_boundary(h2_socket_transaction_boundary_t boundary,
                                      const char *description) {
    struct sk_msg_md msg = reset_message();
    fault_mask = 1ULL << boundary;
    expect(run_transaction(&msg) == k_h2_socket_transaction_no_mutation, description);
    expect_original(description);
}

static void test_verified_rollback_boundary(h2_socket_transaction_boundary_t boundary,
                                            const char *description) {
    struct sk_msg_md msg = reset_message();
    fault_mask = 1ULL << boundary;
    expect(run_transaction(&msg) == k_h2_socket_transaction_rollback_verified, description);
    expect_original(description);
}

static void test_retried_rollback_boundary(h2_socket_transaction_boundary_t boundary,
                                           const char *description) {
    struct sk_msg_md msg = reset_message();
    fault_mask = (1ULL << k_h2_socket_boundary_write_pull) | (1ULL << boundary);
    expect(run_transaction(&msg) == k_h2_socket_transaction_rollback_verified, description);
    expect_original(description);
}

int main(void) {
    test_commit();

    test_no_mutation_boundary(k_h2_socket_boundary_preflight_pull,
                              "preflight pull failure does not mutate");
    test_no_mutation_boundary(k_h2_socket_boundary_push, "push failure does not mutate");

    test_verified_rollback_boundary(k_h2_socket_boundary_write_pull,
                                    "post-push pull failure rolls back");
    test_verified_rollback_boundary(k_h2_socket_boundary_frame_pull,
                                    "frame pull failure rolls back");

    test_retried_rollback_boundary(k_h2_socket_boundary_rollback_pop,
                                   "transient pop failure is retried and verified");
    test_retried_rollback_boundary(k_h2_socket_boundary_rollback_pull,
                                   "transient rollback pull failure is retried and verified");

    struct sk_msg_md msg = reset_message();
    fault_mask = 1ULL << k_h2_socket_boundary_write_pull;
    forced_pop_failures = 2;
    expect(run_transaction(&msg) == k_h2_socket_transaction_rollback_uncertain,
           "two failed pop attempts keep rollback uncertain");

    msg = reset_message();
    fault_mask = (1ULL << k_h2_socket_boundary_write_pull) |
                 (1ULL << k_h2_socket_boundary_rollback_readback);
    expect(run_transaction(&msg) == k_h2_socket_transaction_rollback_uncertain,
           "failed rollback verification keeps rollback uncertain");

    puts("OK: bpf_h2_socket_write_transaction.c");
    return 0;
}
