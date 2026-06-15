// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Run from repo root:
//   make -C bpf/tests test_failed_connect_event && bpf/tests/test_failed_connect_event
// Run from bpf/tests:
//   make test_failed_connect_event && ./test_failed_connect_event

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <generictracer/failed_connect.h>

static unsigned int failed_assertions;

static void assert_true(bool condition, const char *message) {
    if (condition) {
        printf("PASS: %s\n", message);
        return;
    }

    failed_assertions++;
    printf("FAIL: %s\n", message);
}

static void assert_tcp_req_equal(const tcp_req_t *actual, const tcp_req_t *expected) {
    const unsigned char *actual_bytes = (const unsigned char *)actual;
    const unsigned char *expected_bytes = (const unsigned char *)expected;

    for (size_t i = 0; i < sizeof(*actual); i++) {
        if (actual_bytes[i] == expected_bytes[i]) {
            continue;
        }

        printf("FAIL: tcp_req_t byte %zu: got 0x%02x, want 0x%02x\n",
               i,
               actual_bytes[i],
               expected_bytes[i]);
        failed_assertions++;
        return;
    }

    printf("PASS: tcp_req_t contains only expected bytes\n");
}

static connection_info_t test_connection_info(void) {
    connection_info_t conn = {
        .s_port = 40100,
        .d_port = 443,
    };

    for (size_t i = 0; i < sizeof(conn.s_addr); i++) {
        conn.s_addr[i] = (unsigned char)(i + 1);
        conn.d_addr[i] = (unsigned char)(0x80 + i);
    }

    return conn;
}

static void test_failed_connect_record_is_fully_initialized(void) {
    const u16 orig_dport = 443;
    const u64 connect_ts = 123456789;
    const u64 end_ts = 123456999;
    const u64 trace_ts = 123457111;
    const u64 extra_id = 0xaabbccddeeff0011;

    const pid_info pid = {
        .host_pid = 1001,
        .user_pid = 2002,
        .ns = 3003,
    };
    const pid_connection_info_t pid_conn = {
        .conn = test_connection_info(),
        .pid = pid.host_pid,
    };

    tcp_req_t actual;
    __builtin_memset(&actual, 0xff, sizeof(actual));
    init_failed_connect_tcp_req(
        &actual, &pid_conn, orig_dport, connect_ts, end_ts, trace_ts, extra_id, &pid);

    tcp_req_t expected = {};
    expected.flags = EVENT_FAILED_CONNECT;
    expected.conn_info = pid_conn.conn;
    fixup_connection_info(&expected.conn_info, TCP_SEND, orig_dport);
    expected.direction = TCP_SEND;
    expected.start_monotime_ns = connect_ts;
    expected.end_monotime_ns = end_ts;
    expected.extra_id = extra_id;
    expected.pid = pid;
    expected.tp.ts = trace_ts;

    assert_tcp_req_equal(&actual, &expected);
    assert_true(actual.buf[0] == '\0', "request buffer is empty");
    assert_true(actual.rbuf[0] == '\0', "response buffer is empty");
    assert_true(actual.tp.flags == 0, "trace flags do not retain stale bytes");
}

int main(void) {
    test_failed_connect_record_is_fully_initialized();

    if (failed_assertions != 0) {
        printf("%u failed assertions\n", failed_assertions);
        return 1;
    }

    return 0;
}
