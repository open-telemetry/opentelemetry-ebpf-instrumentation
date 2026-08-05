// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags);

#define BPF_ANY 0
#define bpf_map_update_elem test_map_update

#include <generictracer/protocol_tcp_persistence.h>

#undef bpf_map_update_elem
#undef BPF_ANY

static int request_map;
static pid_connection_info_t stored_key;
static tcp_req_t stored_request;
static unsigned int update_count;
static unsigned int failures;

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    (void)flags;
    if (map != &request_map) {
        return -1;
    }
    stored_key = *(const pid_connection_info_t *)key;
    stored_request = *(const tcp_req_t *)value;
    update_count++;
    return 0;
}

static void reset_map(void) {
    memset(&stored_key, 0, sizeof(stored_key));
    memset(&stored_request, 0, sizeof(stored_request));
    update_count = 0;
}

static void assert_bool(int want, int got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %d, got %d\n", message, want, got);
    failures++;
}

static void assert_u32(uint32_t want, uint32_t got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %u, got %u\n", message, want, got);
    failures++;
}

static void capture_large_request(tcp_req_t *req, uint32_t bytes) {
    req->lb_req_bytes += bytes;
    req->has_large_buffers = 1;
}

static pid_connection_info_t test_key(void) {
    return (pid_connection_info_t){
        .conn =
            {
                .s_port = 41000,
                .d_port = 443,
            },
        .pid = 123,
    };
}

static void test_handoff_replaces_early_snapshot_after_unknown_capture(void) {
    reset_map();
    const pid_connection_info_t key = test_key();
    tcp_req_t req = {
        .direction = TCP_SEND,
        .protocol_type = k_protocol_type_unknown,
        .handoff_expected = 1,
    };
    req.handoff_token.map_epoch = 7;
    req.handoff_token.sequence = 11;
    req.handoff_token.process_start_time = 13;

    test_map_update(&request_map, &key, &req, 0);
    capture_large_request(&req, 37);

    assert_bool(
        1,
        tcp_persist_post_capture_request(&request_map, &key, &req, k_tcp_trace_setup_handoff),
        "handoff setup persists post-capture state");
    assert_u32(2, update_count, "handoff performs early and post-capture writes");
    assert_bool(1,
                memcmp(&key, &stored_key, sizeof(key)) == 0,
                "post-capture replacement keeps the exact connection key");
    assert_u32(37, stored_request.lb_req_bytes, "handoff retains captured byte count");
    assert_bool(1, stored_request.has_large_buffers, "handoff retains large-buffer flag");
    assert_u32(
        11, (uint32_t)stored_request.handoff_token.sequence, "handoff retains its exact token");
}

static void test_normal_one_write_persists_captured_state(void) {
    reset_map();
    const pid_connection_info_t key = test_key();
    tcp_req_t req = {
        .direction = TCP_SEND,
        .protocol_type = k_protocol_type_unknown,
        .req_len = 21,
    };
    capture_large_request(&req, 21);

    assert_bool(
        1,
        tcp_persist_post_capture_request(&request_map, &key, &req, k_tcp_trace_setup_normal),
        "normal setup persists one-write capture");
    assert_u32(1, update_count, "normal setup needs one post-capture write");
    assert_u32(21, stored_request.req_len, "one-write request length is durable");
    assert_u32(21, stored_request.lb_req_bytes, "one-write capture count is durable");
}

static void test_handoff_fragment_append_starts_from_post_capture_state(void) {
    reset_map();
    const pid_connection_info_t key = test_key();
    tcp_req_t req = {
        .direction = TCP_SEND,
        .protocol_type = k_protocol_type_mssql,
        .handoff_expected = 1,
        .req_len = 4,
        .len = 4,
    };

    test_map_update(&request_map, &key, &req, 0);
    capture_large_request(&req, 4);
    tcp_persist_post_capture_request(&request_map, &key, &req, k_tcp_trace_setup_handoff);

    stored_request.len += 8;
    stored_request.req_len = stored_request.len;
    capture_large_request(&stored_request, 8);

    assert_u32(12, stored_request.len, "fragment append retains the first request fragment");
    assert_u32(12, stored_request.req_len, "fragment append updates total request length");
    assert_u32(12,
               stored_request.lb_req_bytes,
               "stateful large-buffer append retains the first capture count");
    assert_bool(1,
                stored_request.has_large_buffers,
                "stateful fragmented request retains its capture flag");
}

static void test_fail_closed_setup_does_not_persist(void) {
    reset_map();
    const pid_connection_info_t key = test_key();
    const tcp_req_t req = {};

    assert_bool(
        0,
        tcp_persist_post_capture_request(&request_map, &key, &req, k_tcp_trace_setup_fail_closed),
        "fail-closed setup cannot publish request state");
    assert_u32(0, update_count, "fail-closed setup does not write the request map");
}

static void assert_response_cleanup_gates_replacement(u8 direction, const char *role) {
    const u64 end_monotime_ns = 12345;
    tcp_req_t ongoing = {
        .direction = direction,
    };
    tcp_req_t event = ongoing;
    event.end_monotime_ns = end_monotime_ns;
    event.resp_len = 17;

    assert_bool(0,
                tcp_request_ready_for_replacement(&ongoing, direction),
                "ongoing request is not replaceable while cleanup is pending");
    assert_bool(1,
                tcp_request_ready_for_replacement(&event, direction),
                "response event carries its completion before cleanup");
    assert_bool(0,
                tcp_publish_response_completion(&ongoing, end_monotime_ns, 17, 0),
                "failed cleanup cannot expose the replacement marker");
    assert_bool(0,
                tcp_request_ready_for_replacement(&ongoing, direction),
                "request remains protected after failed cleanup");

    assert_bool(1,
                tcp_publish_response_completion(&ongoing, end_monotime_ns, 17, 1),
                "successful cleanup publishes the replacement marker");
    assert_bool(1,
                tcp_request_ready_for_replacement(&ongoing, direction),
                "request becomes replaceable only after cleanup");
    assert_u32(17, ongoing.resp_len, role);
}

static void test_response_cleanup_precedes_sequential_replacement(void) {
    assert_response_cleanup_gates_replacement(TCP_SEND, "client response length is published");
    assert_response_cleanup_gates_replacement(TCP_RECV, "server response length is published");
}

int main(void) {
    test_handoff_replaces_early_snapshot_after_unknown_capture();
    test_normal_one_write_persists_captured_state();
    test_handoff_fragment_append_starts_from_post_capture_state();
    test_fail_closed_setup_does_not_persist();
    test_response_cleanup_precedes_sequential_replacement();
    return failures ? 1 : 0;
}
