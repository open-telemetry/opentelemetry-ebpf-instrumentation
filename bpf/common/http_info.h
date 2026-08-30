// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>
#include <common/event_defs.h>
#include <common/event_source.h>
#include <common/protocol_defs.h>
#include <common/tp_info.h>

#define FULL_BUF_SIZE 256

// How much of the response instrumentation saw. The value decides whether the record
// carries a status and whether its duration is a measurement.
enum http_response_observation : u8 {
    // Response parsed, or request still in flight.
    http_response_parsed = 0,
    // No probe parsed the response, and the record was ended by something other than
    // the response itself: the socket tearing down, or the next request taking over the
    // connection. Its duration overstates the request.
    http_response_received = 1,
    // Nothing arrived, the local process closed. The close ended the request, so the
    // duration is a measurement.
    http_response_silent = 2,
    // Bytes arrived in the response direction while the request was in flight and no
    // probe could parse them. The record ends when the last of them arrived, so the
    // duration is a measurement.
    http_response_unread = 3,
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

// Reports whether the request's response arrived without being parsed. The record is
// finished, and only the status is missing from it.
static __always_inline bool response_unread(const http_info_t *info) {
    return info->status == 0 && info->response_observation == http_response_unread;
}

// Reports whether a buffer traveling in this direction carries the response to this
// record's request: inbound for a call this process made, outbound for one it served.
static __always_inline bool http_response_direction(const http_info_t *info, u8 direction) {
    if (info->type == EVENT_HTTP_CLIENT) {
        return direction == TCP_RECV;
    }

    return direction == TCP_SEND;
}

// Reports whether a buffer that no parser recognized carries this record's response: it
// travels in the response direction, and the record is one whose status is still missing.
static __always_inline bool unparsed_response_buffer(const http_info_t *info, u8 direction) {
    if (still_responding(info)) {
        return false;
    }

    if (!still_reading(info) && !response_unread(info)) {
        return false;
    }

    return http_response_direction(info, direction);
}

// Records a response that arrived unparsed, ending the record when the bytes arrived.
// Called for every such buffer, so the end advances to the last one seen.
static __always_inline void note_unread_response(http_info_t *info, u64 at) {
    info->response_observation = http_response_unread;
    info->end_monotime_ns = at;
}

// Records that the next request took over the connection while this one was still in
// flight. The response cannot be observed after this point, so the record is reported
// for what it is: a call that was made, with no status, ended at a time it cannot vouch
// for. Reporting nothing loses one call for every request a connection carries.
static __always_inline void note_displaced_by_next_request(http_info_t *info, u64 at) {
    if (!still_reading(info)) {
        return;
    }

    info->resp_len = 0;
    info->end_monotime_ns = at;
    info->response_observation = http_response_received;
}

static __always_inline u8 http_info_complete(const http_info_t *info) {
    return (info->start_monotime_ns != 0 && info->status != 0 && info->pid.host_pid != 0);
}

// Reports whether an unfinished record on this connection is the client call that an
// incoming request is about to reference itself through. A process that calls itself
// reuses the connection tuple, so the server leg would otherwise overwrite the client
// record and lose the parent it carried.
//
// incoming_type is what the arriving request is, from request_type_by_direction. Only a
// server request can self-reference: a client request on this connection is the next
// call on it, and adopting the previous call's parent would hang it off the wrong
// request. That distinction matters once a record whose response went unparsed stays
// here to be reported rather than being destroyed by the request that follows it.
static __always_inline bool self_reference_candidate(const http_info_t *old_info,
                                                     u8 incoming_type) {
    return incoming_type == EVENT_HTTP_REQUEST && !http_info_complete(old_info) &&
           old_info->type == EVENT_HTTP_CLIENT;
}

static __always_inline u8 http_info_emittable(const http_info_t *info) {
    if (http_info_complete(info)) {
        return 1;
    }

    return (info->response_observation != http_response_parsed && info->start_monotime_ns != 0 &&
            info->pid.host_pid != 0);
}
