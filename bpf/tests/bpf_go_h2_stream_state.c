// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/go_h2_stream_state.h>

static void expect(bool condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

int main(void) {
    expect(go_h2_state_can_inject(k_go_h2_state_obi_pending), "pending is injectable");
    expect(!go_h2_state_can_inject(k_go_h2_state_app), "application-owned is not injectable");
    expect(go_h2_state_suppresses_injection(k_go_h2_state_app), "application-owned suppresses");
    expect(go_h2_state_suppresses_injection(k_go_h2_state_obi_written), "written suppresses");
    expect(go_h2_state_suppresses_injection(k_go_h2_state_skip), "skip suppresses");
    expect(!go_h2_state_suppresses_injection(k_go_h2_state_obi_pending),
           "pending does not suppress");

    expect(go_h2_timestamp_is_fresh(100, 100), "same timestamp is fresh");
    expect(go_h2_timestamp_is_fresh(100, 100 + k_go_h2_state_fresh_ns),
           "freshness boundary is accepted");
    expect(!go_h2_timestamp_is_fresh(100, 101 + k_go_h2_state_fresh_ns),
           "stale timestamp is rejected");
    expect(!go_h2_timestamp_is_fresh(0, 100), "zero timestamp is rejected");
    expect(!go_h2_timestamp_is_fresh(101, 100), "future timestamp is rejected");

    go_h2_stream_key_t stream = {
        .p_conn =
            {
                .conn =
                    {
                        .s_port = 40000,
                        .d_port = 50051,
                    },
                .pid = 2769,
            },
        .stream_id = 1,
    };
    memset(stream.p_conn.conn.s_addr, 0x11, sizeof(stream.p_conn.conn.s_addr));
    memset(stream.p_conn.conn.d_addr, 0x22, sizeof(stream.p_conn.conn.d_addr));
    sort_connection_info(&stream.p_conn.conn);
    expect(stream.p_conn.conn.s_port == 50051 && stream.p_conn.conn.d_port == 40000,
           "generic high-port tuple is sorted");
    go_h2_restore_client_direction(&stream, 50051);
    expect(stream.p_conn.conn.s_port == 40000 && stream.p_conn.conn.d_port == 50051,
           "exact Go key restores client port direction");
    expect(stream.p_conn.conn.s_addr[0] == 0x11 && stream.p_conn.conn.d_addr[0] == 0x22,
           "exact Go key restores client address direction");

    printf("OK: %s\n", __FILE__);
    return 0;
}
