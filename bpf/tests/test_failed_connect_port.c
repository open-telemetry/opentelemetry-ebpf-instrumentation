// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run from repo root:
//   make -C bpf/tests test_failed_connect_port && bpf/tests/test_failed_connect_port
// Run from bpf/tests:
//   make test_failed_connect_port && ./test_failed_connect_port

#include <stdbool.h>
#include <stdio.h>

#include <statsolly/failed_conn_port.h>

static unsigned int failed_assertions;

static void assert_true(bool condition, const char *message) {
    if (condition) {
        printf("PASS: %s\n", message);
        return;
    }

    failed_assertions++;
    printf("FAIL: %s\n", message);
}

// connect(AF_UNSPEC) leaves inet_sport holding the previous connection's port,
// and a reconnect that finds no free local port fails before sending its SYN.
static void test_connect_failing_before_the_syn_does_not_own_inet_sport(void) {
    assert_true(!failed_connect_owns_inet_sport(TCP_SYN_SENT, 0),
                "a connect that sent no SYN keeps the zeroed port");
}

static void test_connect_failing_after_the_syn_owns_inet_sport(void) {
    assert_true(failed_connect_owns_inet_sport(TCP_SYN_SENT, 1),
                "a refused or timed out connect reports the port its SYN used");
}

// An accepted child that failed before sending anything was created with the
// listener's port, so its inet_sport is valid even with no segment sent.
static void test_sockets_past_syn_sent_own_inet_sport(void) {
    assert_true(failed_connect_owns_inet_sport(TCP_SYN_RECV, 0),
                "an accepted child that sent nothing reports its port");
    assert_true(failed_connect_owns_inet_sport(TCP_ESTABLISHED, 0),
                "an established socket reports its port");
    assert_true(failed_connect_owns_inet_sport(TCP_FIN_WAIT1, 1),
                "a closing socket reports its port");
}

int main(void) {
    test_connect_failing_before_the_syn_does_not_own_inet_sport();
    test_connect_failing_after_the_syn_owns_inet_sport();
    test_sockets_past_syn_sent_own_inet_sport();

    if (failed_assertions != 0) {
        printf("%u failed assertions\n", failed_assertions);
        return 1;
    }

    return 0;
}
