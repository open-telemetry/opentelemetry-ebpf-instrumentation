// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run from repo root:
//   make -C bpf/tests test_resolve_local_port && bpf/tests/test_resolve_local_port
// Run from bpf/tests:
//   make test_resolve_local_port && ./test_resolve_local_port

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

// inet_sport is in network byte order, skc_num in host byte order.
static void test_released_port_is_resolved_in_host_order(void) {
    assert_true(resolve_local_port(0, bpf_htons(9000)) == 9000,
                "a released port is resolved from inet_sport in host byte order");
}

static void test_bound_port_is_kept(void) {
    assert_true(resolve_local_port(8080, bpf_htons(9000)) == 8080,
                "a socket that still holds its port keeps it");
}

static void test_never_bound_socket_stays_zero(void) {
    assert_true(resolve_local_port(0, 0) == 0, "a socket that never had a port reports 0");
}

int main(void) {
    test_released_port_is_resolved_in_host_order();
    test_bound_port_is_kept();
    test_never_bound_socket_stays_zero();

    if (failed_assertions != 0) {
        printf("%u failed assertions\n", failed_assertions);
        return 1;
    }

    return 0;
}
