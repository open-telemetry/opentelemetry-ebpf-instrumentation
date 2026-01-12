// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>

#include <common/go_addr_key.h>
#include <logger/bpf_dbg.h>

#include <maps/go_ongoing_http.h>
#include <maps/go_ongoing_http_client_requests.h>
#include <maps/ongoing_http.h>
#include <maps/sock_dir.h>

#include <common/http_types.h>
#include <common/tc_act.h>
#include <common/tc_common.h>
#include <common/tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// these are uppercase to adhere to the IPPROTO_* defines
enum {
    IPPROTO_HOPOPTS = 0,   // IPv6 hop-by-hop options
    IPPROTO_ROUTING = 43,  // IPv6 routing header
    IPPROTO_FRAGMENT = 44, // IPv6 fragmentation header
    IPPROTO_DSTOPTS = 60,  // IPv6 destination options
};

enum { k_ip4_option_code = 0x88 };

// use an experimental option value defined by RFC-4727
// see https://www.rfc-editor.org/rfc/rfc4727.html#section-8
// and https://www.rfc-editor.org/rfc/rfc8200#section-4.1
// as each individual bit plays a role
enum : u8 { k_ip6_option_code = 0x1e };

typedef struct ipv4_opt_t {
    u8 type;
    u8 len;
    u8 trace_id[TRACE_ID_SIZE_BYTES];
    u8 pad[2];
} ipv4_opt;

_Static_assert(sizeof(ipv4_opt) == 20, "invalid IPv4 option len");

typedef struct ipv6_opt_data_t {
    u8 trace_id[TRACE_ID_SIZE_BYTES];
    u8 span_id[SPAN_ID_SIZE_BYTES];
    u32 pad;
} ipv6_opt_data;

typedef struct ipv6_opt_t {
    u8 nexthdr;
    u8 hdrlen;
    u8 opttype;
    u8 optlen;
    ipv6_opt_data data;
} ipv6_opt;

_Static_assert(sizeof(ipv6_opt) % 8 == 0, "ipv6_opt not 8-byte aligned");
_Static_assert(sizeof(ipv6_opt) == 32, "invalid IPv6 option len");

enum protocol { protocol_ip4, protocol_ip6, protocol_unknown };

static __always_inline u16 ip_header_off(struct __sk_buff *ctx) {
    void *data = ctx_data(ctx);
    void *data_end = ctx_data_end(ctx);

    struct ethhdr *eth = data;

    u16 off = sizeof(*eth);

    if (data + off > data_end) {
        return 0;
    }

    u16 h_proto = bpf_ntohs(eth->h_proto);

    for (u8 i = 0; i < 2; ++i) {
        if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
            if (data + off + sizeof(struct vlan_hdr) > data_end) {
                return 0;
            }

            struct vlan_hdr *vh = data + off;
            h_proto = bpf_ntohs(vh->h_vlan_encapsulated_proto);
            off += sizeof(*vh);
        }
    }

    if (h_proto != ETH_P_IP && h_proto != ETH_P_IPV6) {
        return 0;
    }

    return off;
}

static __always_inline void populate_span_id_from_seq_ack(tp_info_t *tp, u32 seq, u32 ack) {
    // We use a combination of the TCP sequence + TCP ack as a SpanID
    *((u32 *)(&tp->span_id[0])) = seq;
    *((u32 *)(&tp->span_id[4])) = ack;
}

static __always_inline bool conn_info_from_skb4(struct __sk_buff *skb, connection_info_t *conn) {
    const u16 ip4_off = ip_header_off(skb);

    if (ip4_off == 0) {
        return false;
    }

    const struct iphdr *iphdr = ctx_data(skb) + ip4_off;

    if ((const void *)(iphdr + 1) > ctx_data_end(skb)) {
        return false;
    }

    if (iphdr->version != 4) {
        return false;
    }

    __builtin_memcpy(conn->s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    __builtin_memcpy(conn->d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    __builtin_memcpy(conn->s_addr + sizeof(ip4ip6_prefix), &iphdr->saddr, sizeof(iphdr->saddr));
    __builtin_memcpy(conn->d_addr + sizeof(ip4ip6_prefix), &iphdr->daddr, sizeof(iphdr->daddr));

    if (iphdr->protocol != IPPROTO_TCP) {
        return false;
    }

    const u16 ihl_bytes = iphdr->ihl << 2;
    const struct tcphdr *tcp = (struct tcphdr *)((const void *)iphdr + ihl_bytes);

    if ((const void *)(tcp + 1) > ctx_data_end(skb)) {
        return false;
    }

    conn->s_port = bpf_ntohs(tcp->source);
    conn->d_port = bpf_ntohs(tcp->dest);

    return conn;
}

static __always_inline bool conn_info_from_skb6(struct __sk_buff *skb, connection_info_t *conn) {
    const u16 ip6_off = ip_header_off(skb);

    if (ip6_off == 0) {
        return false;
    }

    const struct ipv6hdr *iphdr = ctx_data(skb) + ip6_off;

    if ((const void *)(iphdr + 1) > ctx_data_end(skb)) {
        return false;
    }

    if (iphdr->version != 6) {
        return false;
    }

    __builtin_memcpy(conn->s_addr, &iphdr->saddr, sizeof(iphdr->saddr));
    __builtin_memcpy(conn->d_addr, &iphdr->daddr, sizeof(iphdr->daddr));

    const void *ptr = (const void *)(iphdr + 1);

    u8 curr_hdr = iphdr->nexthdr;

    // try to find the start of the TCP header
    // iterate at most 4 extension headers
    for (u8 i = 0; i < 4; ++i) {
        if (curr_hdr == IPPROTO_TCP) {
            break;
        }

        const struct ipv6_opt_hdr *opt_hdr = ptr;

        if ((const void *)(opt_hdr + 1) > ctx_data_end(skb)) {
            return conn;
        }

        switch (curr_hdr) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_DSTOPTS:
            ptr += (opt_hdr->hdrlen * 8) + 1;
            break;
        case IPPROTO_FRAGMENT:
            ptr += 8;
            break;
        default:
            // don't know how to parse, bail
            return false;
        }

        curr_hdr = opt_hdr->nexthdr;
    }

    if (curr_hdr != IPPROTO_TCP) {
        return false;
    }

    const struct tcphdr *tcp = (struct tcphdr *)ptr;

    if ((const void *)(tcp + 1) > ctx_data_end(skb)) {
        return false;
    }

    conn->s_port = bpf_ntohs(tcp->source);
    conn->d_port = bpf_ntohs(tcp->dest);

    return true;
}

static __always_inline bool conn_info_from_skb(struct __sk_buff *skb, connection_info_t *conn) {
    if (skb->protocol == bpf_htons(ETH_P_IP)) {
        return conn_info_from_skb4(skb, conn);
    }

    if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
        return conn_info_from_skb6(skb, conn);
    }

    return false;
}

static __always_inline void print_tp(const char *prefix, const tp_info_t *tp) {
    if (!g_bpf_debug) {
        return;
    }

    unsigned char tp_buf[TP_MAX_VAL_LENGTH + 1];
    tp_buf[TP_MAX_VAL_LENGTH] = '\0';

    make_tp_string(tp_buf, tp);
    bpf_dbg_printk("prefix=%s, tp=%s", prefix, tp_buf);
}

static __always_inline void update_outgoing_request_span_id(const connection_info_t *conn,
                                                            const egress_key_t *e_key,
                                                            const tp_info_pid_t *tp_p) {

    const pid_connection_info_t p_conn = {.conn = *conn, .pid = tp_p->pid};

    http_info_t *h_info = bpf_map_lookup_elem(&ongoing_http, &p_conn);

    if (h_info) {
        __builtin_memcpy(h_info->tp.span_id, tp_p->tp.span_id, SPAN_ID_SIZE_BYTES);

        print_tp("Found HTTP info, reset", &h_info->tp);
    }

    go_addr_key_t *g_key = bpf_map_lookup_elem(&go_ongoing_http, e_key);

    if (!g_key) {
        return;
    }

    http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&go_ongoing_http_client_requests, g_key);

    if (!invocation) {
        return;
    }

    __builtin_memcpy(invocation->tp.span_id, tp_p->tp.span_id, SPAN_ID_SIZE_BYTES);

    print_tp("Found Go HTTP invocation, reset", &tp_p->tp);
}

static __always_inline bool parse_ip_options_ipv4(struct __sk_buff *skb, connection_info_t *conn) {
    const u16 ip4_off = ip_header_off(skb);

    if (ip4_off == 0) {
        return 0;
    }

    const struct iphdr *iphdr = ctx_data(skb) + ip4_off;

    if ((const void *)(iphdr + 1) > ctx_data_end(skb)) {
        return false;
    }

    if (iphdr->version != 4) {
        return false;
    }

    if (iphdr->ihl < 5) {
        // no options present
        return false;
    }

    if (iphdr->protocol != IPPROTO_TCP) {
        return false;
    }

    const unsigned char *ptr = (const unsigned char *)(iphdr + 1);
    const unsigned char *end = ctx_data_end(skb);

    const u8 k_max_options = 10;

    for (u8 i = 0; i < k_max_options; ++i) {
        if (ptr + 2 > end) {
            return false;
        }

        if (*ptr == 0x0) {
            // end of option list
            return false;
        }

        if (*ptr == 0x1) {
            // NOP - single byte option
            ++ptr;
            continue;
        }

        if (*ptr != k_ip4_option_code) {
            // not our option - advance at least one byte
            const u8 opt_len = *(ptr + 1);
            const u8 advance_len = opt_len > 0 ? opt_len : 1;

            ptr += advance_len;
            continue;
        }

        // found our option, try to parse it
        const ipv4_opt *opt = (const ipv4_opt *)ptr;

        if ((const void *)(opt + 1) > (const void *)end) {
            return false;
        }

        // sanity check
        if (opt->len != sizeof(ipv4_opt)) {
            bpf_dbg_printk("wrong IPv4 option size, bailing...");
            return false;
        }

        const tp_info_pid_t *existing_tp =
            (tp_info_pid_t *)bpf_map_lookup_elem(&incoming_trace_map, conn);

        if (existing_tp) {
            bpf_dbg_printk("found existing TP - ignoring IPv4 options");
            return false;
        }

        const u16 ihl_bytes = iphdr->ihl << 2;

        const struct tcphdr *tcp = (struct tcphdr *)((const void *)iphdr + ihl_bytes);

        if ((const void *)(tcp + 1) > ctx_data_end(skb)) {
            return false;
        }

        tp_info_pid_t new_tp = {.pid = 0, .valid = 1};
        populate_span_id_from_seq_ack(&new_tp.tp, tcp->seq, tcp->ack_seq);

        _Static_assert(sizeof(new_tp.tp.trace_id) == sizeof(opt->trace_id),
                       "trace id size mismatch");

        __builtin_memcpy(new_tp.tp.trace_id, opt->trace_id, sizeof(opt->trace_id));

        print_tp("Found TP in IPv4 Options", &new_tp.tp);

        bpf_map_update_elem(&incoming_trace_map, conn, &new_tp, BPF_ANY);

        return true;
    }

    return false;
}

static __always_inline bool parse_ip_options_ipv6(struct __sk_buff *skb, connection_info_t *conn) {
    const tp_info_pid_t *existing_tp =
        (tp_info_pid_t *)bpf_map_lookup_elem(&incoming_trace_map, conn);

    if (existing_tp) {
        print_tp("ignoring existing tp", &existing_tp->tp);
        return false;
    }

    const u16 ip6_off = ip_header_off(skb);

    if (ip6_off == 0) {
        return false;
    }

    const struct ipv6hdr *iphdr = ctx_data(skb) + ip6_off;

    if ((const void *)(iphdr + 1) > ctx_data_end(skb)) {
        return false;
    }

    if (iphdr->version != 6) {
        return false;
    }

    if (iphdr->nexthdr != IPPROTO_DSTOPTS) {
        return false;
    }

    const ipv6_opt *opt = (ipv6_opt *)(iphdr + 1);

    if ((const void *)(opt + 1) > ctx_data_end(skb)) {
        return false;
    }

    if (opt->opttype != k_ip6_option_code) {
        return false;
    }

    if (opt->optlen != sizeof(ipv6_opt_data)) {
        return false;
    }

    const u8 expected_hdr_len = (sizeof(ipv6_opt) / 8) - 1;

    if (opt->hdrlen != expected_hdr_len) {
        return false;
    }

    tp_info_pid_t new_tp = {.pid = 0, .valid = 1};

    __builtin_memcpy(new_tp.tp.trace_id, opt->data.trace_id, TRACE_ID_SIZE_BYTES);
    __builtin_memcpy(new_tp.tp.span_id, opt->data.span_id, SPAN_ID_SIZE_BYTES);

    print_tp(__func__, &new_tp.tp);
    bpf_map_update_elem(&incoming_trace_map, conn, &new_tp, BPF_ANY);

    return true;
}

static __always_inline void inject_tc_ip_options_ipv4(struct __sk_buff *skb, tp_info_pid_t *tp) {
    const u16 ip4_off = ip_header_off(skb);

    if (ip4_off == 0) {
        return;
    }

    struct iphdr *iphdr = ctx_data(skb) + ip4_off;

    if ((void *)(iphdr + 1) > ctx_data_end(skb)) {
        return;
    }

    if (iphdr->version != 4) {
        return;
    }

    if (iphdr->protocol != IPPROTO_TCP) {
        return;
    }

    if (bpf_skb_adjust_room(skb, sizeof(ipv4_opt), BPF_ADJ_ROOM_NET, 0) != 0) {
        return;
    }

    // reload pointers
    iphdr = ctx_data(skb) + ip4_off;

    if ((void *)(iphdr + 1) > ctx_data_end(skb)) {
        return;
    }

    const u16 ihl_bytes = iphdr->ihl << 2;

    unsigned char *ptr = ((unsigned char *)iphdr) + ihl_bytes;
    unsigned char *ptr_b = ptr;

    if ((void *)ptr + sizeof(ipv4_opt) > ctx_data_end(skb)) {
        return;
    }

    *ptr++ = k_ip4_option_code;
    *ptr++ = sizeof(ipv4_opt);

    __builtin_memcpy(ptr, tp->tp.trace_id, TRACE_ID_SIZE_BYTES);

    ptr += TRACE_ID_SIZE_BYTES;
    *ptr++ = 0;
    *ptr++ = 0;

    // update IP header and checksum
    const u16 old_vihl_tos = *(u16 *)iphdr;

    iphdr->ihl += (sizeof(ipv4_opt) >> 2);

    const u16 new_vihl_tos = *(u16 *)iphdr;

    const u16 old_tot_len = iphdr->tot_len;

    iphdr->tot_len = bpf_htons(bpf_ntohs(iphdr->tot_len) + sizeof(ipv4_opt));

    const u16 new_tot_len = iphdr->tot_len;

    u32 sum = ~iphdr->check & 0xffff;

    iphdr->check = 0;

    const u32 opt_sum = bpf_csum_diff(NULL, 0, (__be32 *)ptr_b, ptr - ptr_b, 0);

    sum += opt_sum;
    sum += (~old_vihl_tos & 0xffff);
    sum += new_vihl_tos;
    sum += (~old_tot_len & 0xffff);
    sum += new_tot_len;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    const u16 new_check = ~sum;
    iphdr->check = new_check;

    const struct tcphdr *tcp = (struct tcphdr *)ptr;

    if ((const void *)(tcp + 1) > ctx_data_end(skb)) {
        return;
    }

    populate_span_id_from_seq_ack(&tp->tp, tcp->seq, tcp->ack_seq);

    print_tp("injected", &tp->tp);
}

static __always_inline void inject_tc_ip_options_ipv6(struct __sk_buff *skb,
                                                      const tp_info_pid_t *tp) {
    const u16 ip6_off = ip_header_off(skb);

    if (ip6_off == 0) {
        return;
    }

    struct ipv6hdr *iphdr = ctx_data(skb) + ip6_off;

    if ((void *)(iphdr + 1) > ctx_data_end(skb)) {
        return;
    }

    if (iphdr->version != 6) {
        return;
    }

    const u8 nexthdr = iphdr->nexthdr;

    // https://www.rfc-editor.org/rfc/rfc8200#section-4.1 defines the
    // constraints for header count and ordering. To keep things from
    // breaking, we only inject the options when dealing with TCP packets and
    // no other options are present
    if (nexthdr != IPPROTO_TCP) {
        return;
    }

    if (bpf_skb_adjust_room(skb, sizeof(ipv6_opt), BPF_ADJ_ROOM_NET, 0) != 0) {
        return;
    }

    // reload pointers
    iphdr = ctx_data(skb) + ip6_off;

    ipv6_opt *opt = (ipv6_opt *)(iphdr + 1);

    if ((void *)(opt + 1) > ctx_data_end(skb)) {
        return;
    }

    iphdr->nexthdr = IPPROTO_DSTOPTS;
    iphdr->payload_len = bpf_htons(bpf_ntohs(iphdr->payload_len) + sizeof(ipv6_opt));

    opt->nexthdr = nexthdr;
    opt->hdrlen = (sizeof(ipv6_opt) / 8) - 1;
    opt->opttype = k_ip6_option_code;
    opt->optlen = sizeof(ipv6_opt_data);

    __builtin_memcpy(opt->data.trace_id, tp->tp.trace_id, TRACE_ID_SIZE_BYTES);
    __builtin_memcpy(opt->data.span_id, tp->tp.span_id, SPAN_ID_SIZE_BYTES);

    opt->data.pad = 0;

    print_tp("injected", &tp->tp);
}

static __always_inline u8 is_sock_tracked(const connection_info_t *conn) {
    struct bpf_sock *sk = (struct bpf_sock *)bpf_map_lookup_elem(&sock_dir, conn);

    if (sk) {
        bpf_sk_release(sk);
        return 1;
    }

    return 0;
}

static __always_inline void track_sock(struct __sk_buff *skb, const connection_info_t *conn) {
    if (is_sock_tracked(conn)) {
        return;
    }

    struct bpf_sock_tuple tuple = {};

    u32 tuple_size = 0;

    if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
        __builtin_memcpy(tuple.ipv6.saddr, conn->s_addr, IP_V6_ADDR_LEN);
        __builtin_memcpy(tuple.ipv6.daddr, conn->d_addr, IP_V6_ADDR_LEN);

        tuple.ipv6.sport = bpf_htons(conn->s_port);
        tuple.ipv6.dport = bpf_htons(conn->d_port);

        tuple_size = sizeof(tuple.ipv6);
    } else if (skb->protocol == bpf_htons(ETH_P_IP)) {
        __builtin_memcpy(&tuple.ipv4.saddr, conn->s_addr + sizeof(ip4ip6_prefix), sizeof(u32));
        __builtin_memcpy(&tuple.ipv4.saddr, conn->s_addr + sizeof(ip4ip6_prefix), sizeof(u32));
        __builtin_memcpy(&tuple.ipv4.daddr, conn->d_addr + sizeof(ip4ip6_prefix), sizeof(u32));

        tuple.ipv4.sport = bpf_htons(conn->s_port);
        tuple.ipv4.dport = bpf_htons(conn->d_port);

        tuple_size = sizeof(tuple.ipv4);
    } else {
        return;
    }

    // this MUST be a signed 32-bit number
    const s32 BPF_F_CURRENT_NETNS = -1;

    struct bpf_sock *sk = bpf_sk_lookup_tcp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0);

    if (!sk) {
        return;
    }

    bpf_map_update_elem(&sock_dir, conn, sk, BPF_NOEXIST);

    bpf_sk_release(sk);
}

static __always_inline bool parse_ip_options(struct __sk_buff *skb, connection_info_t *conn) {
    if (skb->protocol == bpf_htons(ETH_P_IP)) {
        return parse_ip_options_ipv4(skb, conn);
    }

    if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
        return parse_ip_options_ipv6(skb, conn);
    }

    return false;
}

static __always_inline void inject_ip_options(struct __sk_buff *skb,
                                              const connection_info_t *conn) {
    const egress_key_t e_key = {
        .d_port = conn->d_port,
        .s_port = conn->s_port,
    };

    tp_info_pid_t *tp = bpf_map_lookup_elem(&outgoing_trace_map, &e_key);

    if (!tp) {
        return;
    }

    if (tp->written) {
        bpf_dbg_printk("tp already written by L7, not injecting IP options");
        bpf_map_delete_elem(&outgoing_trace_map, &e_key);
        return;
    }

    if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
        bpf_dbg_printk("Adding the trace_id in IPv6 Destination Options");

        inject_tc_ip_options_ipv6(skb, tp);

        bpf_map_delete_elem(&outgoing_trace_map, &e_key);
    } else if (skb->protocol == bpf_htons(ETH_P_IP)) {
        bpf_dbg_printk("Adding the trace_id in the IP Options");

        inject_tc_ip_options_ipv4(skb, tp);

        bpf_map_delete_elem(&outgoing_trace_map, &e_key);

        // We look up metadata setup by the Go uprobes or the kprobes on
        // a transaction we consider outgoing HTTP request. We will extend this in
        // the future for other protocols, e.g. gRPC/HTTP2.
        // The metadata always comes setup with the state field valid = 1, which
        // means we haven't seen this request yet.
        // If it's the first packet of a request:
        // We set the span information to match our TCP information. This
        // is done for L4 context propagation, where we use the SEQ/ACK
        // numbers for the Span ID. Since this is the first time we see
        // these SEQ,ACK ids, we update the random Span ID the metadata has
        // to match what we send over the wire.
        update_outgoing_request_span_id(conn, &e_key, tp);
    }
}

static __always_inline void process_ip_options(struct __sk_buff *skb) {
    connection_info_t conn = {};

    if (!conn_info_from_skb(skb, &conn)) {
        return;
    }

    track_sock(skb, &conn);

    sort_connection_info(&conn);

    if (parse_ip_options(skb, &conn)) {
        return;
    }

    inject_ip_options(skb, &conn);
}

SEC("tc_egress")
int obi_app_egress(struct __sk_buff *skb) {
    process_ip_options(skb);
    return TC_ACT_UNSPEC;
}

SEC("tc_ingress")
int obi_app_ingress(struct __sk_buff *skb) {
    process_ip_options(skb);
    return TC_ACT_UNSPEC;
}
