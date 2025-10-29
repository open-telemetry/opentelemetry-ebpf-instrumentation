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
union dnsflags {
    struct {
        u8 qr : 1;     // 0=query; 1=response
        u8 opcode : 4; // kind of query
        u8 aa : 1;     // authoritative answer
        u8 tc : 1;     // truncation
        u8 rd : 1;     // recursion desired
        u8 ra : 1;     // recursion available
        u8 z : 3;      // reserved
        u8 rcode : 4;  // response code
    };
    u16 flags;
};

struct dnshdr {
    u16 id;

    union dnsflags flags;

    u16 qdcount; // number of question entries
    u16 ancount; // number of answer entries
    u16 nscount; // number of authority records
    u16 arcount; // number of additional records
};

static __always_inline u8 is_dns_port(u16 port) {
    return port == 53 || port == 5353;
}

static __always_inline u8 is_dns(connection_info_t *conn) {
    return is_dns_port(conn->s_port) || is_dns_port(conn->d_port);
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

        // Skip if we don't have any data to avoid handling control segments
        dns_off = l4_off + tcp_header_len;
        if (skb->len <= dns_off) {
            return 0;
        }

        // DNS is after the TCP header and the 2 bytes of the length of the DNS packet
        dns_off += 2;
        break;
    default:
        return 0;
    }

    union dnsflags flags;
    bpf_skb_load_bytes(skb, dns_off + offsetof(struct dnshdr, flags), &flags.flags, sizeof(u16));
    flags.flags = bpf_ntohs(flags.flags); // Convert from network to host byte order

    u8 qr = flags.qr;
    if (qr == k_dns_qr_query || qr == k_dns_qr_resp) {
        u16 id = 0;
        bpf_skb_load_bytes(skb, dns_off + offsetof(struct dnshdr, id), &id, sizeof(u16));
        u16 orig_dport = conn->d_port;
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
            __builtin_memcpy(&req->conn, conn, sizeof(connection_info_t));

            req->flags = EVENT_DNS_REQUEST;
            req->p_type = skb->pkt_type;
            req->len = skb->len;
            req->dns_q = qr;
            req->id = id;
            req->ts = bpf_ktime_get_ns();
            req->tp.ts = bpf_ktime_get_ns();
            __builtin_memcpy(&req->pid, &conn_pid->p_info, sizeof(pid_info));

            trace_key_t t_key = {0};
            trace_key_from_pid_tid_with_p_key(&t_key, &conn_pid->p_key, conn_pid->id);

            u8 found = find_trace_for_client_request_with_t_key(
                &p_conn, orig_dport, &t_key, conn_pid->id, &req->tp);
            bpf_dbg_printk("handle_dns: looking up client trace info, found %d", found);
            if (found) {
                urand_bytes(req->tp.span_id, SPAN_ID_SIZE_BYTES);
            } else {
                init_new_trace(&req->tp);
            }
            read_skb_bytes(skb, dns_off, req->buf, sizeof(req->buf));
            bpf_d_printk("sending dns trace");
            bpf_ringbuf_submit(req, get_flags());
        }

        return 1;
    }

    return 0;
}