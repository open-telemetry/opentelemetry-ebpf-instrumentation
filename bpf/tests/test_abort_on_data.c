// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run from repo root:
//   make -C bpf/tests test_abort_on_data && bpf/tests/test_abort_on_data
// Run from bpf/tests:
//   make test_abort_on_data && ./test_abort_on_data

#include <stdbool.h>
#include <stdio.h>

#include <statsolly/abort_on_data.h>

static unsigned int failed_assertions;

static void assert_true(bool condition, const char *message) {
    if (condition) {
        printf("PASS: %s\n", message);
        return;
    }

    failed_assertions++;
    printf("FAIL: %s\n", message);
}

static const u8 seg_without_rst = 0;
static const u8 seg_with_rst = 1;

// Data reaching a socket that shut down reading makes tcp_rcv_state_process()
// call tcp_reset() itself, for a segment that carries no RST.
static void test_data_after_read_shutdown_is_a_local_abort(void) {
    assert_true(received_reset_is_local_abort(TCP_FIN_WAIT1, &seg_without_rst),
                "data in FIN_WAIT1 is a local abort");
    assert_true(received_reset_is_local_abort(TCP_FIN_WAIT2, &seg_without_rst),
                "data in FIN_WAIT2 is a local abort");
    assert_true(received_reset_is_local_abort(TCP_CLOSE_WAIT, &seg_without_rst),
                "data past the peer's FIN in CLOSE_WAIT is a local abort");
    assert_true(received_reset_is_local_abort(TCP_CLOSING, &seg_without_rst),
                "data past the peer's FIN in CLOSING is a local abort");
    assert_true(received_reset_is_local_abort(TCP_LAST_ACK, &seg_without_rst),
                "data past the peer's FIN in LAST_ACK is a local abort");
}

static void test_rst_from_the_peer_is_received(void) {
    assert_true(!received_reset_is_local_abort(TCP_FIN_WAIT2, &seg_with_rst),
                "an RST in FIN_WAIT2 is received");
    assert_true(!received_reset_is_local_abort(TCP_CLOSE_WAIT, &seg_with_rst),
                "an RST in CLOSE_WAIT is received");
}

// ESTABLISHED segments skip tcp_rcv_state_process(), so only an RST resets them.
static void test_rst_in_established_is_received(void) {
    assert_true(!received_reset_is_local_abort(TCP_ESTABLISHED, &seg_without_rst),
                "a reset in ESTABLISHED is received even with a stale entry");
    assert_true(!received_reset_is_local_abort(TCP_ESTABLISHED, NULL),
                "a reset in ESTABLISHED is received");
}

static void test_missing_entry_is_received(void) {
    assert_true(!received_reset_is_local_abort(TCP_FIN_WAIT2, NULL),
                "a reset with no recorded segment is counted as received");
}

enum {
    k_seq = 1000,
    k_seq_after_fin = k_seq + 1,
    k_seq_after_data = k_seq + 100,
};

// end_seq counts SYN, FIN and payload, so only a pure ACK has end_seq == seq
static void test_only_rst_fin_or_data_can_reset(void) {
    assert_true(!segment_can_reset(TCPHDR_ACK, k_seq, k_seq), "a pure ACK cannot reset");
    assert_true(segment_can_reset(TCPHDR_RST, k_seq, k_seq), "an RST can reset");
    assert_true(segment_can_reset(TCPHDR_ACK, k_seq, k_seq_after_data), "data can abort");
    assert_true(segment_can_reset(TCPHDR_FIN | TCPHDR_ACK, k_seq, k_seq_after_fin),
                "an out-of-order FIN can abort");
}

int main(void) {
    test_data_after_read_shutdown_is_a_local_abort();
    test_rst_from_the_peer_is_received();
    test_rst_in_established_is_received();
    test_missing_entry_is_received();
    test_only_rst_fin_or_data_can_reset();

    if (failed_assertions != 0) {
        printf("%u failed assertions\n", failed_assertions);
        return 1;
    }

    return 0;
}
