// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>
#include <common/event_source.h>
#include <common/tp_info.h>

#define FULL_BUF_SIZE 256

// How much of the response instrumentation saw, on a request finished at socket
// teardown. The value decides whether the record's duration is a measurement.
enum http_response_observation : u8 {
    // Response parsed, or request still in flight.
    http_response_parsed = 0,
    // Bytes arrived, no probe parsed them.
    http_response_received = 1,
    // Nothing arrived, the local process closed.
    http_response_silent = 2,
};

// A FIN advances bytes_received by one, so ignore that byte.
#define HTTP_RESPONSE_BYTES_FIN_TOLERANCE 1

// Reports whether the peer sent payload since the request was recorded.
static __always_inline bool http_response_bytes_advanced(u64 at_request, u64 at_close) {
    if (at_close <= at_request) {
        return false;
    }

    return (at_close - at_request) > HTTP_RESPONSE_BYTES_FIN_TOLERANCE;
}

static __always_inline u8 http_response_observation_at_close(u64 at_request, u64 at_close) {
    return http_response_bytes_advanced(at_request, at_close) ? http_response_received
                                                              : http_response_silent;
}

// Here we keep the information that is sent on the ring buffer
typedef struct http_info {
    u8 flags; // Must be first, we use it to tell what kind of packet we have on the ring buffer
    u8 type;
    u8 ssl;
    u8 delayed;
    connection_info_t conn_info;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u64 req_monotime_ns;
    u64 extra_id;
    // The byte counter when the request was recorded: received bytes for a
    // client, sent bytes for a server. Zero when the recording path held no
    // socket (TLS uprobes, unix sockets).
    u64 response_bytes_at_request;
    tp_info_t tp;
    pid_info pid;
    u32 len;
    u32 resp_len;
    u32 task_tid;
    u32 lb_req_bytes;
    u32 lb_res_bytes;
    u16 status;
    unsigned char buf[FULL_BUF_SIZE];
    u8 has_large_buffers;
    u8 direction;
    u8 submitted;
    enum parent_status parent_status;
    enum event_source_type event_source;
    u8 response_observation;
} http_info_t;

static __always_inline bool still_responding(const http_info_t *info) {
    return info->status != 0;
}

static __always_inline bool still_reading(const http_info_t *info) {
    return info->status == 0 && info->response_observation == http_response_parsed &&
           info->start_monotime_ns != 0;
}

static __always_inline u8 http_info_complete(const http_info_t *info) {
    return (info->start_monotime_ns != 0 && info->status != 0 && info->pid.host_pid != 0);
}

static __always_inline u8 http_info_emittable(const http_info_t *info) {
    if (http_info_complete(info)) {
        return 1;
    }

    return (info->response_observation != http_response_parsed && info->start_monotime_ns != 0 &&
            info->pid.host_pid != 0);
}
