// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/common.h>
#include <common/connection_info.h>

enum tcp_trace_setup : u8 {
    k_tcp_trace_setup_normal,
    k_tcp_trace_setup_handoff,
    k_tcp_trace_setup_fail_closed,
};

static __always_inline u8 tcp_request_ready_for_replacement(const tcp_req_t *req, u8 direction) {
    return req && req->direction == direction && req->end_monotime_ns != 0;
}

// The completion marker is also the replacement gate. Publish it only after
// the connection-scoped trace state for this request has been cleaned so a
// sequential request cannot become replaceable while the old cleanup can
// still delete the new request's publications.
static __always_inline u8 tcp_publish_response_completion(tcp_req_t *req,
                                                          u64 end_monotime_ns,
                                                          u32 resp_len,
                                                          u8 trace_cleanup_complete) {
    if (!req || !end_monotime_ns || !trace_cleanup_complete) {
        return 0;
    }
    req->resp_len = resp_len;
    req->end_monotime_ns = end_monotime_ns;
    return 1;
}

// Handoff setup publishes an early durable copy before connection trace setup.
// Capture mutates the scratch request afterwards, so every successful setup
// must replace that early copy with the post-capture state.
static __always_inline u8 tcp_persist_post_capture_request(void *requests,
                                                           const pid_connection_info_t *pid_conn,
                                                           const tcp_req_t *req,
                                                           u8 trace_setup) {
    return requests && pid_conn && req && trace_setup != k_tcp_trace_setup_fail_closed &&
           bpf_map_update_elem(requests, pid_conn, req, BPF_ANY) == 0;
}
