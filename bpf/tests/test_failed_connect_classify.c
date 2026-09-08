// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run from repo root:
//   make -C bpf/tests test_failed_connect_classify && bpf/tests/test_failed_connect_classify
// Run from bpf/tests:
//   make test_failed_connect_classify && ./test_failed_connect_classify

#include <stdbool.h>
#include <stdio.h>

#include <common/sockaddr.h>

static unsigned int failed_assertions;

static void assert_true(bool condition, const char *message) {
    if (condition) {
        printf("PASS: %s\n", message);
        return;
    }

    failed_assertions++;
    printf("FAIL: %s\n", message);
}

// An established socket that carried no application bytes is what a client
// connection pool leaves behind when it reaps an idle connection, and what a
// racing pool checkout leaves behind when the connection it started arrives
// after the request it was started for has been served elsewhere.
static void test_established_socket_without_traffic_is_connected(void) {
    assert_true(!tcp_never_connected(TCP_ESTABLISHED, 1),
                "an established socket that carried no bytes is connected");
    assert_true(!tcp_never_connected(TCP_CLOSE_WAIT, 1),
                "a socket whose peer closed first is connected");
    assert_true(!tcp_never_connected(TCP_FIN_WAIT1, 1),
                "a socket closing after a completed handshake is connected");
}

static void test_socket_dying_in_the_handshake_never_connected(void) {
    assert_true(tcp_never_connected(TCP_SYN_SENT, 0), "a socket still in SYN_SENT never connected");
    assert_true(tcp_never_connected(TCP_SYN_RECV, 0), "a socket still in SYN_RECV never connected");
}

// tcp_done() moves a refused, reset or timed out connect to TCP_CLOSE, the same
// state a socket reaches once a normal close completes.
static void test_closed_socket_is_told_apart_by_the_acknowledged_syn(void) {
    assert_true(tcp_never_connected(TCP_CLOSE, 0),
                "a closed socket whose SYN was never acknowledged never connected");
    assert_true(!tcp_never_connected(TCP_CLOSE, 1),
                "a closed socket whose SYN was acknowledged is connected");
}

static void test_listening_socket_is_not_a_failed_connect(void) {
    assert_true(!tcp_never_connected(TCP_LISTEN, 0),
                "a listening socket never attempted a connect");
}

int main(void) {
    test_established_socket_without_traffic_is_connected();
    test_socket_dying_in_the_handshake_never_connected();
    test_closed_socket_is_told_apart_by_the_acknowledged_syn();
    test_listening_socket_is_not_a_failed_connect();

    if (failed_assertions != 0) {
        printf("%u failed assertions\n", failed_assertions);
        return 1;
    }

    return 0;
}
