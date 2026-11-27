// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <common/ringbuf.h>
#include <common/tcp_multiplex.h>
#include <generictracer/tcp_multiplex_protocols.h>

enum {
    k_tcp_multiplex_max_operations = 1 + 32, // initial I/O and up to 32 appends
    k_tcp_multiplex_max_records = 1024,
};

typedef struct {
    tcp_req_t tcp;
    tcp_multiplex_header_t header;
    tcp_io_range_t operations[k_tcp_multiplex_max_operations];
} tcp_multiplex_record_t;

typedef struct {
    u64 start;
    u32 pid;
    connection_info_t conn;
} tcp_multiplex_key_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, tcp_multiplex_key_t);
    __type(value, tcp_multiplex_record_t);
    __uint(max_entries, k_tcp_multiplex_max_records);
    __uint(pinning, OBI_PIN_INTERNAL);
} tcp_multiplex_records SEC(".maps");

static __always_inline tcp_multiplex_key_t tcp_multiplex_key(const tcp_req_t *req) {
    return (tcp_multiplex_key_t){
        .start = req->start_monotime_ns, .pid = req->pid.host_pid, .conn = req->conn_info};
}

static __always_inline void tcp_multiplex_record_operation(tcp_req_t *req,
                                                           const call_protocol_args_t *args,
                                                           const tcp_io_range_t *op,
                                                           u64 previous_record) {
    const bool known_record_protocol = req->protocol_type != k_protocol_type_unknown;
    const bool known_operation_protocol = args->protocol_type != k_protocol_type_unknown;
    const bool has_bytes = op->inline_len || op->large_len;

    if (known_record_protocol || known_operation_protocol || !has_bytes) {
        return;
    }

    const bool multiplexed = req->flags == k_event_type_tcp_multiplex;
    if (!multiplexed) {
        const bool candidate = tcp_multiplex_candidate(args);
        if (!candidate) {
            return;
        }
    }

    const tcp_multiplex_key_t key = tcp_multiplex_key(req);
    if (req->flags == k_event_type_tcp_request) {
        static const tcp_multiplex_record_t empty = {};
        const long update_err = bpf_map_update_elem(&tcp_multiplex_records, &key, &empty, BPF_ANY);
        if (update_err != 0) {
            return;
        }
    }

    tcp_multiplex_record_t *record = bpf_map_lookup_elem(&tcp_multiplex_records, &key);
    if (!record) {
        return;
    }

    const u8 index = record->header.count;
    if (index >= k_tcp_multiplex_max_operations) {
        return;
    }

    if (!index) {
        record->header.previous_record = previous_record;
    }

    record->operations[index] = *op;
    if (!op->timestamp) {
        record->operations[index].timestamp = bpf_ktime_get_ns();
    }

    record->header.count = index + 1;
    req->flags = k_event_type_tcp_multiplex;
}

static __always_inline bool tcp_multiplex_emit(tcp_req_t *req, u32 response_len) {
    if (req->flags != k_event_type_tcp_multiplex) {
        return false;
    }

    const tcp_multiplex_key_t key = tcp_multiplex_key(req);
    tcp_multiplex_record_t *record = bpf_map_lookup_elem(&tcp_multiplex_records, &key);
    if (record) {
        __builtin_memcpy(&record->tcp, req, sizeof(*req));
        record->header.response_len = response_len;

        u32 size = offsetof(tcp_multiplex_record_t, operations) +
                   record->header.count * sizeof(record->operations[0]);
        bpf_clamp_umax(size, sizeof(*record));
        const long emit_err = events_ringbuf_output(record, size);
        bpf_map_delete_elem(&tcp_multiplex_records, &key);

        if (emit_err == 0) {
            return true;
        }
    }

    // Eviction or ring pressure can still leave room for the ordinary TCP event.
    req->flags = k_event_type_tcp_request;
    return false;
}

static __always_inline void
tcp_multiplex_emit_cont(const tcp_req_t *req, const call_protocol_args_t *args, u32 large_len) {
    tcp_multiplex_cont_t *cont = events_ringbuf_reserve(sizeof(*cont), 0);
    if (!cont) {
        return;
    }

    bpf_memset(cont, 0, sizeof(*cont));
    cont->flags = k_event_type_tcp_multiplex_cont;
    cont->direction = args->direction;
    cont->is_server = req->is_server;
    cont->event_source = req->event_source;
    cont->pid = req->pid;
    cont->conn_info = req->conn_info;
    cont->tp = req->tp;
    cont->record_start = req->start_monotime_ns;
    cont->observed = bpf_ktime_get_ns();
    cont->len = args->bytes_len;
    cont->large_len = large_len;

    u32 len = cont->len;
    bpf_clamp_umax(len, sizeof(cont->buf));

    const long read_err = bpf_probe_read(cont->buf, len, (const void *)args->u_buf);
    const bool missing_payload = read_err != 0 && !large_len;

    if (missing_payload) {
        bpf_ringbuf_discard(cont, 0);
        return;
    }

    bpf_ringbuf_submit(cont, get_flags());
}
