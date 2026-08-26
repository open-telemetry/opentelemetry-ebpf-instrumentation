// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The following code is copied from bpf/generictracer/protocol_aerospike.h and
 * adapted to run as a host unit test. The function under test is:
 *
 *   static __always_inline int aerospike_send_large_buffer(tcp_req_t *req,
 *       pid_connection_info_t *pid_conn, const void *u_buf, u32 bytes_len,
 *       u8 packet_type, u8 direction, enum large_buf_action action);
 *
 * together with aerospike_emit_chunks and aerospike_body_len. The BPF-only
 * helpers, the aerospike_state map, and the large buffer emission are mocked
 * below; the mock for large_buf_emit_chunks records what would reach the ring
 * buffer so the tests can assert on it.
 *
 * These tests pin down the split-read reassembly contract: -1 while the first
 * response frame is incomplete (the span event must wait), 0 when it is
 * complete or on any bail-out path, state map entries created/updated/deleted
 * at the right moments, and capture-cap accounting that counts full wire bytes
 * even when emission is truncated.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;

// Mocks for the BPF runtime pieces used by aerospike_send_large_buffer.

#ifndef __always_inline
#define __always_inline inline
#endif
#define BPF_ANY 0
#define PACKET_TYPE_REQUEST 1
#define PACKET_TYPE_RESPONSE 2
#define TCP_SEND 1
#define EVENT_TCP_LARGE_BUFFER 12

#define bpf_dbg_printk(...) ((void)0)
#define bpf_clamp_umax(v, max)                                                                     \
    do {                                                                                           \
        if ((v) > (max)) {                                                                         \
            (v) = (max);                                                                           \
        }                                                                                          \
    } while (0)

static inline u32 min(u32 a, u32 b) {
    return a < b ? a : b;
}

static int bpf_probe_read(void *dst, u32 size, const void *src) {
    memcpy(dst, src, size);
    return 0;
}

typedef struct connection_info {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
} connection_info_t;

typedef struct pid_connection_info {
    connection_info_t conn;
    u32 pid;
} pid_connection_info_t;

// Reduced tcp_req_t: only the fields the function under test touches.
typedef struct tcp_req {
    u64 end_monotime_ns;
    u32 lb_req_bytes;
    u32 lb_res_bytes;
    bool has_large_buffers;
    int tp;
} tcp_req_t;

enum large_buf_action {
    k_large_buf_action_init = 0,
    k_large_buf_action_append = 1,
};

enum {
    k_large_buf_layer_wire = 0,
    k_large_buf_layer_app = 1,
    k_large_buf_read_kernel = 0,
    k_large_buffer_source_kprobes = 0,
};

typedef struct tcp_large_buffer {
    u8 type;
    u8 packet_type;
    u8 action;
    u8 kind;
    u8 direction;
    u8 source;
    connection_info_t conn_info;
    int tp;
} tcp_large_buffer_t;

static tcp_large_buffer_t scratch_lb;

static void *tcp_large_buffers_mem(void) {
    return &scratch_lb;
}

// Records what large_buf_emit_chunks would have shipped to the ring buffer.
static struct {
    u32 calls;
    u32 total_bytes;
    u8 last_packet_type;
    u8 last_action;
    u8 last_kind;
} emit_log;

static u32 large_buf_emit_chunks(tcp_large_buffer_t *lb, const void *buf, u32 len, int mode) {
    (void)buf;
    (void)mode;
    emit_log.calls++;
    emit_log.total_bytes += len;
    emit_log.last_packet_type = lb->packet_type;
    emit_log.last_action = lb->action;
    emit_log.last_kind = lb->kind;
    return len;
}

// In protocol_aerospike.h this is `volatile const`, set from userspace; the
// tests flip it per case.
static u32 aerospike_max_captured_bytes = 0;

enum {
    k_aerospike_proto_header_len = 8,
    k_aerospike_proto_version = 2,
    k_large_buf_max_aerospike_captured_bytes = 1 << 16,
    MAX_ENTRIES = 20,
};

// Array-backed simulation of the aerospike_state LRU map.
typedef struct aerospike_state_data {
    s64 response_bytes_remaining;
} aerospike_state_data_t;

typedef struct aerospike_state_entry {
    connection_info_t key;
    aerospike_state_data_t value;
    int used;
} aerospike_state_entry_t;

static aerospike_state_entry_t aerospike_state[MAX_ENTRIES];

static void *bpf_map_lookup_elem(void *map, const void *key) {
    (void)map;
    for (int i = 0; i < MAX_ENTRIES; i++) {
        if (aerospike_state[i].used &&
            memcmp(&aerospike_state[i].key, key, sizeof(connection_info_t)) == 0) {
            return &aerospike_state[i].value;
        }
    }
    return NULL;
}

static long bpf_map_update_elem(void *map, const void *key, const void *value, u64 flags) {
    (void)map;
    (void)flags;
    for (int i = 0; i < MAX_ENTRIES; i++) {
        if (aerospike_state[i].used &&
            memcmp(&aerospike_state[i].key, key, sizeof(connection_info_t)) == 0) {
            memcpy(&aerospike_state[i].value, value, sizeof(aerospike_state_data_t));
            return 0;
        }
    }
    for (int i = 0; i < MAX_ENTRIES; i++) {
        if (!aerospike_state[i].used) {
            memcpy(&aerospike_state[i].key, key, sizeof(connection_info_t));
            memcpy(&aerospike_state[i].value, value, sizeof(aerospike_state_data_t));
            aerospike_state[i].used = 1;
            return 0;
        }
    }
    return -1;
}

static long bpf_map_delete_elem(void *map, const void *key) {
    (void)map;
    for (int i = 0; i < MAX_ENTRIES; i++) {
        if (aerospike_state[i].used &&
            memcmp(&aerospike_state[i].key, key, sizeof(connection_info_t)) == 0) {
            aerospike_state[i].used = 0;
            return 0;
        }
    }
    return -1;
}

// Code under test (copied from protocol_aerospike.h).

static __always_inline u64 aerospike_body_len(const unsigned char *hdr) {
    return ((u64)hdr[2] << 40) | ((u64)hdr[3] << 32) | ((u64)hdr[4] << 24) | ((u64)hdr[5] << 16) |
           ((u64)hdr[6] << 8) | (u64)hdr[7];
}

static __always_inline u32 aerospike_emit_chunks(tcp_req_t *req,
                                                 pid_connection_info_t *pid_conn,
                                                 const void *u_buf,
                                                 u32 bytes_len,
                                                 u8 packet_type,
                                                 u8 direction,
                                                 enum large_buf_action action,
                                                 u32 sent_bytes) {
    tcp_large_buffer_t *lb = (tcp_large_buffer_t *)tcp_large_buffers_mem();
    if (!lb) {
        bpf_dbg_printk("failed to reserve space for Aerospike large buffer");
        return 0;
    }

    lb->type = EVENT_TCP_LARGE_BUFFER;
    lb->packet_type = packet_type;
    lb->action = action;
    lb->kind = k_large_buf_layer_app;
    lb->direction = direction;
    lb->conn_info = pid_conn->conn;
    lb->tp = req->tp;
    lb->source = k_large_buffer_source_kprobes;

    u32 max_available_bytes = aerospike_max_captured_bytes - sent_bytes;
    bpf_clamp_umax(max_available_bytes, k_large_buf_max_aerospike_captured_bytes);

    const u32 available_bytes = min(bytes_len, max_available_bytes);
    return large_buf_emit_chunks(lb, u_buf, available_bytes, k_large_buf_read_kernel);
}

static __always_inline int aerospike_send_large_buffer(tcp_req_t *req,
                                                       pid_connection_info_t *pid_conn,
                                                       const void *u_buf,
                                                       u32 bytes_len,
                                                       u8 packet_type,
                                                       u8 direction,
                                                       enum large_buf_action action) {
    if (aerospike_max_captured_bytes == 0 || bytes_len == 0) {
        return 0;
    }

    if (packet_type == PACKET_TYPE_REQUEST) {
        if (req->lb_req_bytes >= aerospike_max_captured_bytes) {
            return 0;
        }
        const u32 consumed = aerospike_emit_chunks(
            req, pid_conn, u_buf, bytes_len, packet_type, direction, action, req->lb_req_bytes);
        req->lb_req_bytes += consumed;
        if (consumed > 0) {
            req->has_large_buffers = true;
        }
        return 0;
    }

    // Response side: reassemble the first frame so its result_code reaches
    // userspace even when the client reads the proto header and the body in
    // separate recv() calls (split read).
    if (req->end_monotime_ns != 0) {
        // The span event was already emitted: these are trailing frames of a
        // streamed scan/query/batch response.
        return 0;
    }

    const bool first_chunk = req->lb_res_bytes == 0;
    s64 remaining = 0;

    if (first_chunk) {
        if (bytes_len < k_aerospike_proto_header_len) {
            return 0;
        }
        unsigned char hdr[k_aerospike_proto_header_len] = {};
        if (bpf_probe_read(hdr, sizeof(hdr), u_buf) != 0) {
            return 0;
        }
        if (hdr[0] != k_aerospike_proto_version) {
            return 0;
        }
        remaining = (s64)(k_aerospike_proto_header_len + aerospike_body_len(hdr));
    } else {
        const aerospike_state_data_t *state =
            bpf_map_lookup_elem(&aerospike_state, &pid_conn->conn);
        if (!state) {
            // The state entry was LRU-evicted mid-capture: finalize with what
            // was captured (possibly truncated) rather than never completing.
            return 0;
        }
        remaining = state->response_bytes_remaining;
    }

    const u32 consumed = aerospike_emit_chunks(
        req, pid_conn, u_buf, bytes_len, packet_type, direction, action, req->lb_res_bytes);
    req->lb_res_bytes += consumed;
    if (consumed > 0) {
        req->has_large_buffers = true;
    }

    // remaining tracks wire bytes of the first frame, so the whole chunk counts
    // even when the capture cap truncated what was emitted.
    remaining -= (s64)bytes_len;

    if (remaining > 0 && req->lb_res_bytes < aerospike_max_captured_bytes) {
        const aerospike_state_data_t state = {.response_bytes_remaining = remaining};
        bpf_map_update_elem(&aerospike_state, &pid_conn->conn, &state, BPF_ANY);
        bpf_dbg_printk("aerospike response incomplete, remaining=%lld, waiting", remaining);
        return -1;
    }

    bpf_map_delete_elem(&aerospike_state, &pid_conn->conn);
    return 0;
}

// Test harness.

static int failures = 0;

static void check_int(const char *name, long long expected, long long actual) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %lld, got %lld\n", name, expected, actual);
        failures++;
    } else {
        printf("ok: %s\n", name);
    }
}

static void reset(void) {
    memset(aerospike_state, 0, sizeof(aerospike_state));
    memset(&emit_log, 0, sizeof(emit_log));
}

// Writes an 8-byte proto header: version 2, type 3, 48-bit big-endian body length.
static void put_header(unsigned char *buf, u64 body_len) {
    buf[0] = 2;
    buf[1] = 3;
    for (int i = 0; i < 6; i++) {
        buf[2 + i] = (unsigned char)(body_len >> (8 * (5 - i)));
    }
}

static s64 state_remaining(const connection_info_t *conn) {
    const aerospike_state_data_t *state = bpf_map_lookup_elem(NULL, conn);
    return state ? state->response_bytes_remaining : -999;
}

static const pid_connection_info_t test_conn = {.conn = {.src_port = 40000, .dst_port = 3000},
                                                .pid = 1};

// Java client: 8-byte header recv, then the 22-byte body recv. The span event
// must wait (-1) after the header and fire (0) after the body.
static void test_split_read_response(void) {
    reset();
    aerospike_max_captured_bytes = 1024;
    tcp_req_t req = {0};
    pid_connection_info_t conn = test_conn;

    unsigned char frame[30] = {0};
    put_header(frame, 22);

    check_int("split: header-only recv returns -1",
              -1,
              aerospike_send_large_buffer(
                  &req, &conn, frame, 8, PACKET_TYPE_RESPONSE, TCP_SEND, k_large_buf_action_init));
    check_int("split: state stores remaining=22", 22, state_remaining(&conn.conn));
    check_int("split: 8 bytes captured", 8, req.lb_res_bytes);

    check_int(
        "split: body recv returns 0",
        0,
        aerospike_send_large_buffer(
            &req, &conn, frame + 8, 22, PACKET_TYPE_RESPONSE, TCP_SEND, k_large_buf_action_append));
    check_int("split: state deleted after completion", -999, state_remaining(&conn.conn));
    check_int("split: 30 bytes captured", 30, req.lb_res_bytes);
    check_int("split: has_large_buffers set", 1, req.has_large_buffers);
    check_int("split: emitted app-layer chunks", k_large_buf_layer_app, emit_log.last_kind);
}

// A body split across three recvs: each middle chunk must update the state and
// keep returning -1 until the count is drained.
static void test_multi_chunk_body(void) {
    reset();
    aerospike_max_captured_bytes = 1024;
    tcp_req_t req = {0};
    pid_connection_info_t conn = test_conn;

    unsigned char frame[30] = {0};
    put_header(frame, 22);

    check_int("multi: header recv returns -1",
              -1,
              aerospike_send_large_buffer(
                  &req, &conn, frame, 8, PACKET_TYPE_RESPONSE, TCP_SEND, k_large_buf_action_init));
    check_int(
        "multi: first body part returns -1",
        -1,
        aerospike_send_large_buffer(
            &req, &conn, frame + 8, 10, PACKET_TYPE_RESPONSE, TCP_SEND, k_large_buf_action_append));
    check_int("multi: state updated to remaining=12", 12, state_remaining(&conn.conn));
    check_int("multi: last body part returns 0",
              0,
              aerospike_send_large_buffer(&req,
                                          &conn,
                                          frame + 18,
                                          12,
                                          PACKET_TYPE_RESPONSE,
                                          TCP_SEND,
                                          k_large_buf_action_append));
    check_int("multi: state deleted", -999, state_remaining(&conn.conn));
}

// Single-recv clients (e.g. Go) get the whole frame in one call: 0 immediately,
// no state entry ever created — behavior identical to before reassembly.
static void test_single_recv_response(void) {
    reset();
    aerospike_max_captured_bytes = 1024;
    tcp_req_t req = {0};
    pid_connection_info_t conn = test_conn;

    unsigned char frame[30] = {0};
    put_header(frame, 22);

    check_int("single: whole frame returns 0",
              0,
              aerospike_send_large_buffer(
                  &req, &conn, frame, 30, PACKET_TYPE_RESPONSE, TCP_SEND, k_large_buf_action_init));
    check_int("single: no state entry", -999, state_remaining(&conn.conn));
    check_int("single: 30 bytes captured", 30, req.lb_res_bytes);
}

// A recv bundling the first frame plus the start of the next one drives
// remaining negative: complete, never wait.
static void test_bundled_frames(void) {
    reset();
    aerospike_max_captured_bytes = 1024;
    tcp_req_t req = {0};
    pid_connection_info_t conn = test_conn;

    unsigned char buf[40] = {0};
    put_header(buf, 22); // first frame is 30 bytes; 10 extra bytes follow

    check_int("bundled: returns 0",
              0,
              aerospike_send_large_buffer(
                  &req, &conn, buf, 40, PACKET_TYPE_RESPONSE, TCP_SEND, k_large_buf_action_init));
    check_int("bundled: no state entry", -999, state_remaining(&conn.conn));
}

// Capture disabled: nothing emitted, nothing stored, always 0.
static void test_knob_disabled(void) {
    reset();
    aerospike_max_captured_bytes = 0;
    tcp_req_t req = {0};
    pid_connection_info_t conn = test_conn;

    unsigned char frame[30] = {0};
    put_header(frame, 22);

    check_int("knob=0: returns 0",
              0,
              aerospike_send_large_buffer(
                  &req, &conn, frame, 8, PACKET_TYPE_RESPONSE, TCP_SEND, k_large_buf_action_init));
    check_int("knob=0: nothing emitted", 0, emit_log.calls);
    check_int("knob=0: no state entry", -999, state_remaining(&conn.conn));
}

// Span already emitted: trailing frames of a streamed response are ignored.
static void test_trailing_stream_frames(void) {
    reset();
    aerospike_max_captured_bytes = 1024;
    tcp_req_t req = {.end_monotime_ns = 12345};
    pid_connection_info_t conn = test_conn;

    unsigned char frame[30] = {0};
    put_header(frame, 22);

    check_int("trailing: returns 0",
              0,
              aerospike_send_large_buffer(
                  &req, &conn, frame, 30, PACKET_TYPE_RESPONSE, TCP_SEND, k_large_buf_action_init));
    check_int("trailing: nothing emitted", 0, emit_log.calls);
}

// State evicted mid-capture (lb_res_bytes > 0 but no map entry): finalize with
// what was captured instead of waiting forever.
static void test_state_evicted_mid_capture(void) {
    reset();
    aerospike_max_captured_bytes = 1024;
    tcp_req_t req = {.lb_res_bytes = 8};
    pid_connection_info_t conn = test_conn;

    unsigned char body[22] = {0};

    check_int(
        "evicted: returns 0",
        0,
        aerospike_send_large_buffer(
            &req, &conn, body, 22, PACKET_TYPE_RESPONSE, TCP_SEND, k_large_buf_action_append));
    check_int("evicted: nothing emitted", 0, emit_log.calls);
}

// First response chunk shorter than the proto header or with a wrong version:
// no reassembly, today's behavior.
static void test_first_chunk_rejects(void) {
    reset();
    aerospike_max_captured_bytes = 1024;
    tcp_req_t req = {0};
    pid_connection_info_t conn = test_conn;

    unsigned char tiny[4] = {2, 3, 0, 0};
    check_int("short first chunk: returns 0",
              0,
              aerospike_send_large_buffer(
                  &req, &conn, tiny, 4, PACKET_TYPE_RESPONSE, TCP_SEND, k_large_buf_action_init));

    unsigned char wrong[30] = {0};
    put_header(wrong, 22);
    wrong[0] = 9; // not proto version 2
    check_int("wrong version: returns 0",
              0,
              aerospike_send_large_buffer(
                  &req, &conn, wrong, 30, PACKET_TYPE_RESPONSE, TCP_SEND, k_large_buf_action_init));
    check_int("rejects: nothing emitted", 0, emit_log.calls);
}

// Cap accounting: emission is truncated to the cap, but `remaining` counts the
// full wire bytes; hitting the cap mid-frame finalizes instead of waiting.
static void test_cap_truncation(void) {
    reset();
    aerospike_max_captured_bytes = 10;
    tcp_req_t req = {0};
    pid_connection_info_t conn = test_conn;

    unsigned char frame[30] = {0};
    put_header(frame, 22);

    check_int("cap: header recv returns -1",
              -1,
              aerospike_send_large_buffer(
                  &req, &conn, frame, 8, PACKET_TYPE_RESPONSE, TCP_SEND, k_large_buf_action_init));

    // 11 body bytes arrive, only 2 fit under the cap; frame still incomplete
    // (remaining 22-11=11 > 0) but the cap is reached -> finalize with 0.
    check_int(
        "cap: reaching the cap finalizes with 0",
        0,
        aerospike_send_large_buffer(
            &req, &conn, frame + 8, 11, PACKET_TYPE_RESPONSE, TCP_SEND, k_large_buf_action_append));
    check_int("cap: captured exactly the cap", 10, req.lb_res_bytes);
    check_int("cap: state deleted", -999, state_remaining(&conn.conn));
}

// Request side: plain capture, always 0, own byte accounting, stops at the cap.
static void test_request_capture(void) {
    reset();
    aerospike_max_captured_bytes = 100;
    tcp_req_t req = {0};
    pid_connection_info_t conn = test_conn;

    unsigned char chunk[60] = {0};

    check_int("request: first chunk returns 0",
              0,
              aerospike_send_large_buffer(
                  &req, &conn, chunk, 60, PACKET_TYPE_REQUEST, TCP_SEND, k_large_buf_action_init));
    check_int("request: 60 bytes captured", 60, req.lb_req_bytes);
    check_int("request: emitted as request", PACKET_TYPE_REQUEST, emit_log.last_packet_type);

    check_int(
        "request: second chunk returns 0",
        0,
        aerospike_send_large_buffer(
            &req, &conn, chunk, 60, PACKET_TYPE_REQUEST, TCP_SEND, k_large_buf_action_append));
    check_int("request: capped at 100", 100, req.lb_req_bytes);

    const u32 calls_before = emit_log.calls;
    check_int(
        "request: at cap, returns 0",
        0,
        aerospike_send_large_buffer(
            &req, &conn, chunk, 60, PACKET_TYPE_REQUEST, TCP_SEND, k_large_buf_action_append));
    check_int("request: at cap, nothing more emitted", calls_before, emit_log.calls);
    check_int("request: no response state touched", -999, state_remaining(&conn.conn));
}

int main(void) {
    test_split_read_response();
    test_multi_chunk_body();
    test_single_recv_response();
    test_bundled_frames();
    test_knob_disabled();
    test_trailing_stream_frames();
    test_state_evicted_mid_capture();
    test_first_chunk_rejects();
    test_cap_truncation();
    test_request_capture();

    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }

    printf("all aerospike large buffer tests passed\n");
    return 0;
}
