// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>

#include <common/common.h>
#include <common/connection_info.h>
#include <common/http_types.h>
#include <common/lw_thread.h>
#include <common/protocol_defs.h>
#include <common/ringbuf.h>
#include <common/strings.h>
#include <common/trace_helpers.h>
#include <common/trace_parent.h>
#include <common/trace_util.h>

#include <generictracer/k_tracer_defs.h>

#include <maps/sock_pids.h>
#include <maps/unconn_dns_socks.h>

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

// RFC 1035 reserved three bits here, but RFC 2535 reassigned the lower two to
// AD and CD, which DNSSEC-aware resolvers set on ordinary traffic. Only bit 6
// is still required to be zero, so only bit 6 may be used to reject a message.
static __always_inline u8 dns_z(u16 f) {
    return (f >> 6) & 0x1;
}

static __always_inline u8 dns_ad(u16 f) {
    return (f >> 5) & 0x1;
}

static __always_inline u8 dns_cd(u16 f) {
    return (f >> 4) & 0x1;
}

static __always_inline u8 dns_rcode(u16 f) {
    return f & 0xF;
}

enum : u16 { k_dns_port = 53, k_mdns_port = 5353 };

static __always_inline u8 is_mdns_port(u16 port) {
    return port == k_mdns_port;
}

static __always_inline u8 is_dns_port(u16 port) {
    return port == k_dns_port || is_mdns_port(port);
}

static __always_inline u8 is_dns(const connection_info_t *conn) {
    return is_dns_port(conn->s_port) || is_dns_port(conn->d_port);
}

// Recovers the peer port from a kernel-resident msghdr->msg_name. An unconnected
// UDP socket has no peer in its 4-tuple (skc_dport==0), so the destination
// (sendmsg) or source (recvmsg) port lives only in msg_name.
static __always_inline u16 obi_msg_name_port(struct msghdr *msg) {
    if (!msg) {
        return 0;
    }
    void *name = NULL;
    int namelen = 0;
    BPF_CORE_READ_INTO(&name, msg, msg_name);
    BPF_CORE_READ_INTO(&namelen, msg, msg_namelen);
    if (!name || namelen < (int)sizeof(struct sockaddr_in)) {
        return 0;
    }
    struct sockaddr_in sa = {0};
    if (bpf_probe_read_kernel(&sa, sizeof(sa), name) != 0) {
        return 0;
    }
    if (sa.sin_family != AF_INET) {
        return 0; // IPv6 DNS transport not handled by this fallback
    }
    return bpf_ntohs(sa.sin_port);
}

// Whether the exchange is multicast DNS, which runs 5353 to 5353: a compliant
// querier sends from source port 5353 (RFC 6762 §5.2) to 224.0.0.251:5353, and
// a responder is bound to the same port. A one-shot querier uses an ephemeral
// source port and is explicitly not a compliant querier (§5.1), so it does not
// emit the forms this distinction exists to admit.
//
// Both ends are required because holding 5353 locally proves nothing: the port
// is unprivileged, so any process may bind it, and a site that widens
// ip_local_port_range down to 1024 lets the kernel hand it to an arbitrary
// client as an ephemeral source port.
static __always_inline u8 is_mdns_exchange(const connection_info_t *conn, struct msghdr *msg) {
    if (is_mdns_port(conn->s_port) && is_mdns_port(conn->d_port)) {
        return 1;
    }

    if (!is_mdns_port(conn->s_port) && !is_mdns_port(conn->d_port)) {
        return 0;
    }

    if (conn->d_port != 0) {
        return 0; // the tuple names the peer, and it is not the mDNS port
    }

    // an unconnected socket, so the peer lives only in msg_name
    return is_mdns_port(obi_msg_name_port(msg));
}

// Smallest encodings of a question and of a resource record: the root name
// (a single zero length octet), then the fixed fields of each.
enum : u32 {
    k_dns_min_question_bytes = 1 + 2 + 2,   // name, qtype, qclass
    k_dns_min_rr_bytes = 1 + 2 + 2 + 4 + 2, // name, type, class, ttl, rdlength
};

// Whether a datagram is structurally a DNS message. qr alone is one bit, so it
// says nothing: every payload of at least sizeof(struct dnshdr) has a valid qr,
// and the socket-identity tier hands this function payloads whose only other
// evidence is the socket they arrived on. These checks are what separates a DNS
// message from arbitrary bytes.
//
// Deliberately not checked: rcode, because NXDOMAIN and SERVFAIL are lookups
// worth reporting, and the AD and CD bits, which ordinary DNSSEC-aware
// resolvers set.
//
// mdns relaxes the counts a query may carry, because multicast DNS puts records
// in sections a unicast query leaves empty.
static __always_inline u8 dns_header_is_plausible(const struct dnshdr *hdr,
                                                  const u16 flags,
                                                  const u32 size,
                                                  const u8 mdns) {
    if (dns_opcode(flags) != 0) {
        return 0; // a lookup is a standard query; IQUERY, STATUS, NOTIFY and UPDATE are not
    }

    if (dns_z(flags) != 0) {
        return 0; // still reserved, so a set bit means this is not a DNS header
    }

    const u16 qdcount = bpf_ntohs(hdr->qdcount);
    const u16 ancount = bpf_ntohs(hdr->ancount);
    const u16 nscount = bpf_ntohs(hdr->nscount);
    const u16 arcount = bpf_ntohs(hdr->arcount);

    // A message describing no records at all carries no lookup, whichever
    // direction it travels in. An mDNS response may omit the question, so the
    // sections are counted together rather than separately.
    if (qdcount + ancount + nscount + arcount == 0) {
        return 0;
    }

    // A unicast query asks at least one question and answers none of them.
    // Multicast DNS is exempt on both halves: a query carries the answers it
    // already knows so that responders suppress them (RFC 6762 §7.1), and the
    // continuation packets holding the rest of that list have no question at
    // all (§7.2).
    if (dns_qr(flags) == k_dns_qr_query && !mdns && (qdcount == 0 || ancount != 0)) {
        return 0;
    }

    // A truncated message describes records that were never sent, so its counts
    // cannot be held against the bytes on hand.
    if (dns_tc(flags)) {
        return 1;
    }

    const u32 payload = size - sizeof(struct dnshdr);
    const u32 needed = ((u32)qdcount * k_dns_min_question_bytes) +
                       (((u32)ancount + nscount + arcount) * k_dns_min_rr_bytes);

    return needed <= payload;
}

// k_dns_msg_no is a positive answer, not an absence of evidence: the peer is
// known and it is not a DNS endpoint. Only k_dns_msg_unknown may fall through
// to the socket-identity tier.
enum dns_msg_class : u8 {
    k_dns_msg_unknown = 0,
    k_dns_msg_yes = 1,
    k_dns_msg_no = 2,
};

static __always_inline enum dns_msg_class classify_dns_msg(const connection_info_t *conn,
                                                           struct msghdr *msg) {
    if (is_dns(conn)) {
        return k_dns_msg_yes;
    }

    if (conn->d_port != 0) {
        return k_dns_msg_no; // the tuple names a non-DNS peer
    }

    const u16 peer_port = obi_msg_name_port(msg);

    if (peer_port == 0) {
        return k_dns_msg_unknown;
    }

    if (is_dns_port(peer_port)) {
        bpf_dbg_printk("UNCONN_DNS_MSGNAME: classified unconnected UDP DNS via msg_name port=%d",
                       peer_port);
        return k_dns_msg_yes;
    }

    return k_dns_msg_no;
}

static __always_inline u8 is_dns_msg(const connection_info_t *conn, struct msghdr *msg) {
    return classify_dns_msg(conn, msg) == k_dns_msg_yes;
}

// An answer is only expected for a short while after a query; a resolver that
// never sees its answer must not leave the socket classified forever. Answers
// arrive in milliseconds, so this is far longer than needed and still well
// inside the usual 5s resolver timeout.
enum : u64 { k_unconn_dns_answer_timeout_ns = 2ULL * 1000000000ULL };

static __always_inline u8 obi_same_local_addr(const unconn_dns_sock_t *state,
                                              const connection_info_t *conn) {
    return state->s_port == conn->s_port && obi_bpf_memcmp((const char *)state->s_addr,
                                                           (const char *)conn->s_addr,
                                                           sizeof(state->s_addr)) == 0;
}

static __always_inline void obi_forget_unconn_dns_sock(void *sk) {
    const u64 k = (u64)sk;
    bpf_map_delete_elem(&unconn_dns_socks, &k);
}

// Opens the window in which a nameless answer on sk may be classified as DNS.
//
// conn must be the unsorted tuple, so that s_addr/s_port name the local endpoint.
// The whole record is rewritten unconditionally: one map store, no
// read-modify-write, so concurrent sends on the same socket cannot lose state.
static __always_inline void obi_note_unconn_dns_query(void *sk, const connection_info_t *conn) {
    const u64 k = (u64)sk;

    unconn_dns_sock_t fresh = {
        .s_port = conn->s_port,
        .last_query_ns = bpf_ktime_get_ns(),
    };
    __builtin_memcpy(fresh.s_addr, conn->s_addr, sizeof(fresh.s_addr));

    bpf_map_update_elem(&unconn_dns_socks, &k, &fresh, BPF_ANY);
}

// Holds a parsed DNS query until udp_sendmsg returns. The payload has been
// recognised as DNS by this point, but the send may still fail, and a query
// that never left the host is owed no answer.
//
// conn must be the unsorted tuple.
static __always_inline void
obi_stage_unconn_dns_query(u64 pid_tid, void *sk, const connection_info_t *conn) {
    unconn_dns_pending_t pending = {
        .sk = (u64)sk,
        .s_port = conn->s_port,
    };
    __builtin_memcpy(pending.s_addr, conn->s_addr, sizeof(pending.s_addr));

    bpf_map_update_elem(&unconn_dns_pending, &pid_tid, &pending, BPF_ANY);
}

static __always_inline void obi_discard_unconn_dns_query(u64 pid_tid) {
    bpf_map_delete_elem(&unconn_dns_pending, &pid_tid);
}

// Opens the answer window for a query that was staged and has now been sent.
// The window is timed from here rather than from the entry probe, so it starts
// when the datagram actually went out.
static __always_inline void obi_commit_unconn_dns_query(u64 pid_tid) {
    const unconn_dns_pending_t *pending = bpf_map_lookup_elem(&unconn_dns_pending, &pid_tid);

    if (!pending) {
        return;
    }

    connection_info_t local_conn = {.s_port = pending->s_port};
    __builtin_memcpy(local_conn.s_addr, pending->s_addr, sizeof(local_conn.s_addr));

    obi_note_unconn_dns_query((void *)pending->sk, &local_conn);
    obi_discard_unconn_dns_query(pid_tid);
}

// Reports whether a nameless answer on sk may be attributed to DNS: the socket
// must still be the one that sent the query, and the query must be recent. This
// only decides eligibility; nothing is consumed, so several answers to queries
// issued in parallel are all classified. A stale or mismatched record is
// retired here so it cannot accumulate.
//
// conn must be the unsorted tuple.
static __always_inline u8 obi_unconn_dns_answer_expected(void *sk, const connection_info_t *conn) {
    const u64 k = (u64)sk;

    const unconn_dns_sock_t *state = bpf_map_lookup_elem(&unconn_dns_socks, &k);

    if (!state) {
        return 0;
    }

    // the struct sock * address has been recycled by an unrelated socket
    if (!obi_same_local_addr(state, conn)) {
        obi_forget_unconn_dns_sock(sk);
        return 0;
    }

    if (bpf_ktime_get_ns() - state->last_query_ns > k_unconn_dns_answer_timeout_ns) {
        obi_forget_unconn_dns_sock(sk);
        return 0;
    }

    return 1;
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
        p_conn, orig_dport, &t_key, conn_pid->id, k_lw_thread_none, &req->tp);
    req->parent_status = found;

    bpf_dbg_printk("looking up client trace info, found: %d", found);
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
    const u16 l4_off = p_info->ip_len;
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
        const u8 tcp_header_len = tcph.doff * 4;

        // DNS is after the TCP header and the 2 bytes of the length of the DNS packet
        const u16 size_bytes_len = 2;

        // Skip if we don't have any data to avoid handling control segments
        dns_off = l4_off + tcp_header_len + size_bytes_len;

        break;
    default:
        return 0;
    }

    if (skb->len < (dns_off + sizeof(struct dnshdr))) {
        return 0;
    }

    struct dnshdr hdr;
    if (bpf_skb_load_bytes(skb, dns_off, &hdr, sizeof(hdr)) != 0) {
        return 0;
    }

    const u16 flags = bpf_ntohs(hdr.flags);
    const u8 qr = dns_qr(flags);

    if (qr == k_dns_qr_query || qr == k_dns_qr_resp) {
        const u16 orig_dport = conn->d_port;
        sort_connection_info(conn);
        conn_pid_t *conn_pid = bpf_map_lookup_elem(&sock_pids, conn);

        if (!conn_pid) {
            //bpf_d_printk("can't find connection info for dns call [%s]", __FUNCTION__);
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
            bpf_d_printk("sending dns trace [%s]", __FUNCTION__);
            bpf_ringbuf_submit(req, get_flags());
        }

        return 1;
    }

    return 0;
}

static __always_inline u8 handle_dns_buf(const unsigned char *buf,
                                         const int size,
                                         pid_connection_info_t *p_conn,
                                         u16 orig_dport,
                                         struct msghdr *msg) {

    if (size < sizeof(struct dnshdr)) {
        bpf_d_printk("dns packet too small [%s]", __FUNCTION__);
        return 0;
    }

    // buf is scratch memory from iovec_memory(), so this is a kernel read; a
    // user read silently zeroes hdr, yielding id 0 and a bogus qr
    struct dnshdr hdr;
    if (bpf_probe_read_kernel(&hdr, sizeof(struct dnshdr), buf) != 0) {
        return 0;
    }

    const u16 flags = bpf_ntohs(hdr.flags);
    const u8 qr = dns_qr(flags);

    bpf_d_printk("QR type: %d [%s]", qr, __FUNCTION__);

    if (dns_header_is_plausible(&hdr, flags, size, is_mdns_exchange(&p_conn->conn, msg))) {
        conn_pid_t *conn_pid = bpf_map_lookup_elem(&sock_pids, &p_conn->conn);
        if (!conn_pid) {
            bpf_d_printk("can't find connection info for dns call [%s]", __FUNCTION__);
            return 0;
        }

        dns_req_t *req = bpf_ringbuf_reserve(&events, sizeof(dns_req_t), 0);
        if (req) {
            populate_dns_record(req, p_conn, orig_dport, size, qr, hdr.id, conn_pid);

            bpf_probe_read_kernel(req->buf, sizeof(req->buf), buf);
            bpf_d_printk("sending dns trace [%s]", __FUNCTION__);
            bpf_ringbuf_submit(req, get_flags());
        }

        return 1;
    }

    return 0;
}
