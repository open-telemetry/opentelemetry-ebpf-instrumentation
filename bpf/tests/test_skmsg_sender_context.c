// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#include <tpinjector/sender_context.h>

int main(void) {
    const u64 id = ((u64)41 << 32) | 42;
    pid_connection_info_t conn = {.pid = 41};
    conn.conn.s_port = 12345;
    conn.conn.d_port = 8080;
    skmsg_sender_context_t sender = {.p_conn = conn, .id = id, .started_ns = 100};
    assert(skmsg_sender_matches(&sender, &conn, id, 101, 100));
    assert(!skmsg_sender_matches(NULL, &conn, id, 101, 100));
    assert(!skmsg_sender_matches(&sender, &conn, id + 1, 101, 100));
    assert(!skmsg_sender_matches(&sender, &conn, id, 99, 100));
    assert(!skmsg_sender_matches(&sender, &conn, id, 201, 100));
    assert(skmsg_sender_matches(&sender, &conn, id, 200, 100));
    conn.conn.s_port++;
    assert(!skmsg_sender_matches(&sender, &conn, id, 101, 100));
    conn = sender.p_conn;
    conn.conn.d_ip[3] = 1;
    assert(!skmsg_sender_matches(&sender, &conn, id, 101, 100));
    conn = sender.p_conn;
    conn.pid++;
    assert(!skmsg_sender_matches(&sender, &conn, id, 101, 100));
    puts("PASS: SK_MSG context rejects a different sender, socket, process, or stale lifetime");
}
