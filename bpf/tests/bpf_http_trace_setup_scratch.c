// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include <generictracer/maps/http_trace_setup_mem.h>

static unsigned int failures;

static void assert_bool(int want, int got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %d, got %d\n", message, want, got);
    failures++;
}

static pid_connection_info_t test_connection(void) {
    pid_connection_info_t pid_conn = {
        .conn =
            {
                .s_port = 50000,
                .d_port = 443,
            },
        .pid = 1234,
    };
    pid_conn.conn.s_addr[IP_V6_ADDR_LEN - 1] = 2;
    pid_conn.conn.d_addr[IP_V6_ADDR_LEN - 1] = 1;
    return pid_conn;
}

static outgoing_trace_token_t test_token(void) {
    return (outgoing_trace_token_t){
        .map_epoch = 11,
        .sequence = 22,
        .process_start_time = 33,
        .cpu = 4,
    };
}

static void test_expected_handoff_preserves_exact_identity(void) {
    const pid_connection_info_t pid_conn = test_connection();
    const outgoing_trace_token_t token = test_token();
    const egress_key_t want_egress = make_egress_key(&pid_conn.conn, pid_conn.pid, 0);
    http_trace_setup_scratch_t scratch = {};

    prepare_http_trace_setup_scratch(&scratch, &pid_conn, &token, 1);

    assert_bool(1,
                memcmp(&want_egress, &scratch.egress, sizeof(want_egress)) == 0,
                "scratch keeps the canonical HTTP/1 egress key");
    assert_bool(1,
                memcmp(&token, &scratch.handoff_token, sizeof(token)) == 0,
                "scratch keeps the explicit handoff generation");
}

static void test_locator_path_clears_stale_token(void) {
    const pid_connection_info_t pid_conn = test_connection();
    const outgoing_trace_token_t token = test_token();
    const outgoing_trace_token_t zero_token = {};
    http_trace_setup_scratch_t scratch;
    memset(&scratch, 0xff, sizeof(scratch));

    prepare_http_trace_setup_scratch(&scratch, &pid_conn, &token, 0);

    assert_bool(1,
                memcmp(&zero_token, &scratch.handoff_token, sizeof(zero_token)) == 0,
                "locator lookup never inherits a prior per-CPU token");
}

int main(void) {
    test_expected_handoff_preserves_exact_identity();
    test_locator_path_clears_stale_token();
    return failures ? 1 : 0;
}
