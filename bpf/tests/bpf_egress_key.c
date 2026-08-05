// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <string.h>

#include <common/connection_info.h>

static unsigned int failures;

static void assert_bool(int want, int got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %d, got %d\n", message, want, got);
    failures++;
}

static connection_info_t
connection(unsigned char source, unsigned char destination, u16 source_port, u16 destination_port) {
    connection_info_t conn = {
        .s_port = source_port,
        .d_port = destination_port,
    };
    conn.s_addr[IP_V6_ADDR_LEN - 1] = source;
    conn.d_addr[IP_V6_ADDR_LEN - 1] = destination;
    return conn;
}

static connection_info_t reversed(connection_info_t conn) {
    swap_connection_info_order(&conn);
    return conn;
}

static void test_reversed_endpoints_share_key(void) {
    const connection_info_t forward = connection(1, 2, 50000, 443);
    const connection_info_t reverse = reversed(forward);
    const egress_key_t forward_key = make_egress_key(&forward, 42, 7);
    const egress_key_t reverse_key = make_egress_key(&reverse, 42, 7);

    assert_bool(
        1, memcmp(&forward_key, &reverse_key, sizeof(forward_key)) == 0, "reverse endpoint key");
}

static void test_equal_ports_use_address_tiebreaker(void) {
    const connection_info_t forward = connection(1, 2, 8080, 8080);
    const connection_info_t reverse = reversed(forward);
    const egress_key_t forward_key = make_egress_key(&forward, 42, 7);
    const egress_key_t reverse_key = make_egress_key(&reverse, 42, 7);

    assert_bool(1, memcmp(&forward_key, &reverse_key, sizeof(forward_key)) == 0, "equal-port key");
}

static void test_key_isolates_connection_pid_and_stream(void) {
    const connection_info_t first = connection(1, 2, 50000, 443);
    const connection_info_t second = connection(3, 4, 50000, 443);
    const egress_key_t first_key = make_egress_key(&first, 42, 7);
    const egress_key_t connection_key = make_egress_key(&second, 42, 7);
    const egress_key_t pid_key = make_egress_key(&first, 43, 7);
    const egress_key_t stream_key = make_egress_key(&first, 42, 9);

    assert_bool(1,
                memcmp(&first_key, &connection_key, sizeof(first_key)) != 0,
                "connection identity separates equal ports");
    assert_bool(1, memcmp(&first_key, &pid_key, sizeof(first_key)) != 0, "PID separates key");
    assert_bool(1, memcmp(&first_key, &stream_key, sizeof(first_key)) != 0, "stream separates key");
}

int main(void) {
    test_reversed_endpoints_share_key();
    test_equal_ports_use_address_tiebreaker();
    test_key_isolates_connection_pid_and_stream();
    return failures ? 1 : 0;
}
