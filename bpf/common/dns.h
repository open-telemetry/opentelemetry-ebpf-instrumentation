// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>

#include <common/common.h>
#include <common/connection_info.h>
#include <common/http_types.h>
#include <common/ringbuf.h>
#include <common/trace_common.h>
#include <common/trace_util.h>

#include <generictracer/k_tracer_defs.h>
#include <generictracer/protocol_tcp.h>

#include <maps/sock_pids.h>

#include <pid/types/pid_info.h>

enum dns_qr_type : u8 { k_dns_qr_query = 0, k_dns_qr_resp = 1 };

// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
//
// 4.1.1. Header section format
//
// The header contains the following fields:
//
//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      ID                       |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   | <--- flags (1)
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    QDCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ANCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    NSCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ARCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

struct dnshdr {
    u16 id;

    u16 flags; // flags (1) in network byte order

    u16 qdcount; // number of question entries
    u16 ancount; // number of answer entries
    u16 nscount; // number of authority records
    u16 arcount; // number of additional records
};

static __always_inline u8 dns_qr(u16 f) {
    return (f >> 15) & 0x1;
}

static __always_inline u8 dns_opcode(u16 f) {
    return (f >> 11) & 0xF;
}

static __always_inline u8 dns_aa(u16 f) {
    return (f >> 10) & 0x1;
}

static __always_inline u8 dns_tc(u16 f) {
    return (f >> 9) & 0x1;
}

static __always_inline u8 dns_rd(u16 f) {
    return (f >> 8) & 0x1;
}

static __always_inline u8 dns_ra(u16 f) {
    return (f >> 7) & 0x1;
}

static __always_inline u8 dns_z(u16 f) {
    return (f >> 4) & 0x7;
}

static __always_inline u8 dns_rcode(u16 f) {
    return f & 0xF;
}

static __always_inline u8 is_dns_port(u16 port) {
    return port == 53 || port == 5353;
}

static __always_inline u8 is_dns(connection_info_t *conn) {
    return is_dns_port(conn->s_port) || is_dns_port(conn->d_port);
}

static __always_inline void populate_dns_record(dns_req_t *req,
                                                const pid_connection_info_t *p_conn,
                                                const u16 orig_dport,
                                                const u32 size,
                                                const u8 qr,
                                                const u16 id,
                                                const conn_pid_t *conn_pid) {
    __builtin_memcpy(&req->conn, &p_conn->conn, sizeof(connection_info_t));

    req->flags = EVENT_DNS_REQUEST;
    req->len = size;
    req->dns_q = qr;
    req->id = bpf_ntohs(id);
    req->tp.ts = bpf_ktime_get_ns();
    req->pid = conn_pid->p_info;

    trace_key_t t_key = {0};
    trace_key_from_pid_tid_with_p_key(&t_key, &conn_pid->p_key, conn_pid->id);

    const u8 found = find_trace_for_client_request_with_t_key(
        p_conn, orig_dport, &t_key, conn_pid->id, &req->tp);

    bpf_dbg_printk("handle_dns: looking up client trace info, found %d", found);
    if (found) {
        urand_bytes(req->tp.span_id, SPAN_ID_SIZE_BYTES);
    } else {
        init_new_trace(&req->tp);
    }
}

static __always_inline u8 handle_dns(struct __sk_buff *skb,
                                     connection_info_t *conn,
                                     protocol_info_t *p_info) {

    u16 dns_off = 0;
    u16 l4_off = p_info->ip_len;
    // Calculate the DNS offset in the packet
    struct tcphdr tcph;

    switch (p_info->l4_proto) {
    case IPPROTO_UDP:
        dns_off = l4_off + sizeof(struct udphdr);
        break;
    case IPPROTO_TCP:
        // This is best effort, since we don't reassemble TCP segments.
        if (bpf_skb_load_bytes(skb, l4_off, &tcph, sizeof tcph)) {
            return 0;
        }

        // The data offset field in the header is specified in 32-bit words. We
        // have to multiply this value by 4 to get the TCP header length in bytes.
        __u8 tcp_header_len = tcph.doff * 4;

        // DNS is after the TCP header and the 2 bytes of the length of the DNS packet
        const u16 size_bytes_len = 2;

        // Skip if we don't have any data to avoid handling control segments
        dns_off = l4_off + tcp_header_len + size_bytes_len;

        if (skb->len <= (dns_off + sizeof(struct dnshdr))) {
            return 0;
        }
        break;
    default:
        return 0;
    }

    struct dnshdr hdr;
    bpf_skb_load_bytes(skb, dns_off, &hdr, sizeof(hdr));

    const u16 flags = bpf_ntohs(hdr.flags);
    const u8 qr = dns_qr(flags);

    if (qr == k_dns_qr_query || qr == k_dns_qr_resp) {
        const u16 orig_dport = conn->d_port;
        sort_connection_info(conn);
        conn_pid_t *conn_pid = bpf_map_lookup_elem(&sock_pids, conn);

        if (!conn_pid) {
            bpf_d_printk("can't find connection info for dns call");
            return 0;
        }

        pid_connection_info_t p_conn = {
            .conn = *conn,
            .pid = conn_pid->p_info.host_pid,
        };

        dns_req_t *req = bpf_ringbuf_reserve(&events, sizeof(dns_req_t), 0);

        if (req) {
            u32 len = skb->len - dns_off;
            bpf_clamp_umax(len, 512);
            populate_dns_record(req, &p_conn, orig_dport, len, qr, hdr.id, conn_pid);

            read_skb_bytes(skb, dns_off, req->buf, len);
            bpf_d_printk("sending dns trace");
            bpf_ringbuf_submit(req, get_flags());
        }

        return 1;
    }

    return 0;
}

static __always_inline u8 handle_dns_buf(const unsigned char *buf,
                                         const int size,
                                         pid_connection_info_t *p_conn,
                                         u16 orig_dport) {

    if (size < sizeof(struct dnshdr)) {
        bpf_d_printk("dns packet too small");
        return 0;
    }

    struct dnshdr hdr;
    bpf_probe_read_user(&hdr, sizeof(struct dnshdr), buf);

    const u16 flags = bpf_ntohs(hdr.flags);
    const u8 qr = dns_qr(flags);

    bpf_d_printk("QR type: %d", qr);

    if (qr == k_dns_qr_query || qr == k_dns_qr_resp) {
        conn_pid_t *conn_pid = bpf_map_lookup_elem(&sock_pids, &p_conn->conn);
        if (!conn_pid) {
            bpf_d_printk("can't find connection info for dns call");
            return 0;
        }

        dns_req_t *req = bpf_ringbuf_reserve(&events, sizeof(dns_req_t), 0);
        if (req) {
            populate_dns_record(req, p_conn, orig_dport, size, qr, hdr.id, conn_pid);

            bpf_probe_read(req->buf, sizeof(req->buf), buf);
            bpf_d_printk("sending dns trace");
            bpf_ringbuf_submit(req, get_flags());
        }

        return 1;
    }

    return 0;
}
