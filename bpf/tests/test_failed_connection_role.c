// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run from repo root:
//   make -C bpf/tests test_failed_connection_role && bpf/tests/test_failed_connection_role
// Run from bpf/tests:
//   make test_failed_connection_role && ./test_failed_connection_role

#include <stdbool.h>
#include <stdio.h>

#include <statsolly/handshake_role.h>

static unsigned int failed_assertions;

static void assert_true(bool condition, const char *message) {
    if (condition) {
        printf("PASS: %s\n", message);
        return;
    }

    failed_assertions++;
    printf("FAIL: %s\n", message);
}

// sock_role keeps an entry until the socket is freed, so a socket reused with connect(AF_UNSPEC)
// can still hold the role of its previous connection when the next handshake fails.
static void test_handshake_states_ignore_a_stored_role(void) {
    assert_true(failed_connection_role(TCP_SYN_SENT, role_server) == role_client,
                "a failed connect is a client, whatever the previous connection was");
    assert_true(failed_connection_role(TCP_SYN_RECV, role_client) == role_server,
                "a failed accepted child is a server, whatever the previous connection was");
}

static void test_established_states_use_the_stored_role(void) {
    assert_true(failed_connection_role(TCP_ESTABLISHED, role_client) == role_client,
                "a reset client connection keeps its role");
    assert_true(failed_connection_role(TCP_CLOSE_WAIT, role_server) == role_server,
                "a reset server connection keeps its role");
    assert_true(failed_connection_role(TCP_ESTABLISHED, role_unknown) == role_unknown,
                "a connection established before OBI started has no role");
}

int main(void) {
    test_handshake_states_ignore_a_stored_role();
    test_established_states_use_the_stored_role();

    if (failed_assertions != 0) {
        printf("%u failed assertions\n", failed_assertions);
        return 1;
    }

    return 0;
}
