// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run from repo root:
//   make -C bpf/tests test_black_box_correlation && bpf/tests/test_black_box_correlation

#include <stdbool.h>
#include <stdio.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

static inline u32 bpf_get_prandom_u32(void) {
    return 0;
}

static inline long bpf_loop(u32 nr_loops, void *cb, void *ctx, u64 flags) {
    return 0;
}

#include <common/tracing.h>

static const u64 k_boundary_ns = 444205ULL * NANOSECONDS_PER_EPOCH;
static const u64 k_client_before_boundary_ns = 381000;
static const u64 k_server_after_boundary_ns = 183000;

static unsigned int failed_assertions;

static void assert_true(bool condition, const char *message) {
    if (condition) {
        printf("PASS: %s\n", message);
        return;
    }

    failed_assertions++;
    printf("FAIL: %s\n", message);
}

static tp_info_pid_t client_at(u64 ts) {
    tp_info_pid_t client = {};
    client.tp.ts = ts;

    return client;
}

static tp_info_t server_at(u64 ts) {
    tp_info_t server = {};
    server.ts = ts;

    return server;
}

static void test_close_pair_across_a_boundary_is_correlated(void) {
    const tp_info_pid_t client = client_at(k_boundary_ns - k_client_before_boundary_ns);
    const tp_info_t server = server_at(k_boundary_ns + k_server_after_boundary_ns);

    assert_true(correlated_requests(&server, &client),
                "a server request 564us after its client is correlated across a boundary");
}

static void test_close_pair_inside_a_window_is_correlated(void) {
    const u64 middle_ns = k_boundary_ns + NANOSECONDS_PER_EPOCH / 2;
    const tp_info_pid_t client = client_at(middle_ns);
    const tp_info_t server = server_at(middle_ns + k_client_before_boundary_ns);

    assert_true(correlated_requests(&server, &client),
                "a server request 381us after its client is correlated");
}

static void test_stale_client_is_rejected(void) {
    const tp_info_pid_t client = client_at(k_boundary_ns);
    const tp_info_t at_limit = server_at(k_boundary_ns + NANOSECONDS_PER_EPOCH);
    const tp_info_t past_limit = server_at(k_boundary_ns + NANOSECONDS_PER_EPOCH + 1);

    assert_true(!correlated_requests(&at_limit, &client),
                "a client exactly NANOSECONDS_PER_EPOCH old is rejected");
    assert_true(!correlated_requests(&past_limit, &client),
                "a client older than NANOSECONDS_PER_EPOCH is rejected");
}

static void test_client_after_server_is_rejected(void) {
    const tp_info_pid_t client = client_at(k_boundary_ns + 1);
    const tp_info_t server = server_at(k_boundary_ns);

    assert_true(!correlated_requests(&server, &client),
                "a client observed after the server request is rejected");
    assert_true(!correlated_requests(&server, NULL), "a missing client is rejected");
}

static void test_go_server_close_to_its_client_is_correlated_across_a_boundary(void) {
    tp_info_pid_t client = client_at(k_boundary_ns - k_client_before_boundary_ns);

    bpf_ktime_ns_value = k_boundary_ns + k_server_after_boundary_ns;
    assert_true(correlated_request_with_current(&client),
                "a Go server request 564us after its client is correlated across a boundary");

    bpf_ktime_ns_value = k_boundary_ns - k_client_before_boundary_ns + NANOSECONDS_PER_EPOCH;
    assert_true(!correlated_request_with_current(&client),
                "a Go server request NANOSECONDS_PER_EPOCH after its client is rejected");
}

int main(void) {
    test_close_pair_across_a_boundary_is_correlated();
    test_close_pair_inside_a_window_is_correlated();
    test_stale_client_is_rejected();
    test_client_after_server_is_rejected();
    test_go_server_close_to_its_client_is_correlated_across_a_boundary();

    if (failed_assertions != 0) {
        printf("%u failed assertions\n", failed_assertions);
        return 1;
    }

    return 0;
}