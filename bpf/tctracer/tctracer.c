// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/go_addr_key.h>
#include <logger/bpf_dbg.h>

#include <maps/go_ongoing_http.h>
#include <maps/go_ongoing_http_client_requests.h>
#include <maps/ongoing_http.h>
#include <maps/sock_dir.h>

#include <common/http_types.h>
#include <common/tcp_info.h>
#include <common/tc_act.h>
#include <common/tc_common.h>
#include <common/tracing.h>

// Do not change this into u64 const, the API doesn't work if
// we pass in anything other than -1 explicitly.
#define BPF_F_CURRENT_NETNS (-1)

enum {
    k_min_ip_len = 20,
    k_ip_option_len = 20,        // Stream ID option length (type + len + trace_id + padding)
    k_ip_option_header = 0x8814, // Combined type (0x88) + length (0x14) as u16
    k_max_ipv6_opts_len = 24
};

enum protocol { protocol_ip4, protocol_ip6, protocol_unknown };

char __license[] SEC("license") = "Dual MIT/GPL";

static __always_inline void populate_span_id_from_tcp_info(tp_info_t *tp, protocol_info_t *tcp) {
    // We use a combination of the TCP sequence + TCP ack as a SpanID
    *((u32 *)(&tp->span_id[0])) = tcp->seq;
    *((u32 *)(&tp->span_id[4])) = tcp->ack;
}

static __always_inline void print_tp(const char *prefix, tp_info_pid_t *new_tp) {
    if (!k_bpf_debug) {
        return;
    }

    unsigned char tp_buf[TP_MAX_VAL_LENGTH];

    make_tp_string(tp_buf, &new_tp->tp);
    bpf_dbg_printk("%s tp: %s", prefix, tp_buf);
}

static __always_inline u8 read_ihl(struct __sk_buff *skb) {
    u8 ihl_byte;
    bpf_skb_load_bytes(skb, ETH_HLEN, &ihl_byte, sizeof(ihl_byte));
    const u8 ihl = (ihl_byte & 0x0f) * 4; // IHL in bytes

    return ihl;
}

static __always_inline bool
parse_ip_options_ipv4(struct __sk_buff *skb, connection_info_t *conn, protocol_info_t *tcp) {
    dbg_print_http_connection_info(conn);

    const u8 ihl = read_ihl(skb);

    if (ihl <= k_min_ip_len) {
        // no options present
        return false;
    }

    // Walk through IP options looking for our Stream ID option
    const u32 opts_start = k_min_ip_len + ETH_HLEN;
    const u32 opts_end = ETH_HLEN + ihl;
    u32 offset = opts_start;

    // Prevent infinite loops - max 10 iterations
    for (u8 i = 0; i < 10; i++) {
        if (offset + 2 > opts_end) {
            break;
        }

        u16 opt_header = 0;
        bpf_skb_load_bytes(skb, offset, &opt_header, sizeof(opt_header));
        opt_header = bpf_ntohs(opt_header);

        bpf_dbg_printk("checking offset %d, opt_header %x", offset, opt_header);

        if (opt_header == k_ip_option_header) {
            // Found our Stream ID option
            const tp_info_pid_t *existing_tp =
                (tp_info_pid_t *)bpf_map_lookup_elem(&incoming_trace_map, conn);
            if (existing_tp) {
                bpf_dbg_printk("ignoring existing tp");
                break;
            }

            bpf_dbg_printk("Found tp context in opts at offset %d! ihl = %d", offset, ihl);
            tp_info_pid_t new_tp = {.pid = 0, .valid = 1};
            populate_span_id_from_tcp_info(&new_tp.tp, tcp);

            // Load TraceID from right after type and length bytes (2 bytes total)
            bpf_skb_load_bytes(skb, offset + 2, &new_tp.tp.trace_id[0], sizeof(new_tp.tp.trace_id));

            print_tp(__func__, &new_tp);

            bpf_map_update_elem(&incoming_trace_map, conn, &new_tp, BPF_ANY);

            return true;
        }

        // Parse option type and length to skip to next option
        const u8 opt_type = (opt_header >> 8) & 0xff;
        const u8 opt_len = opt_header & 0xff;

        // Handle special single-byte options
        if (opt_type == 0x00) {
            // End of Option List - stop parsing
            break;
        } else if (opt_type == 0x01) {
            // NOP - single byte option
            offset += 1;
        } else if (opt_len >= 2) {
            // Standard TLV option - skip by length
            offset += opt_len;
        } else {
            // Invalid length - skip by 1 to avoid infinite loop
            offset += 1;
        }
    }

    return false;
}

static __always_inline bool
parse_ip_options_ipv6(struct __sk_buff *skb, connection_info_t *conn, protocol_info_t *tcp) {
    bpf_dbg_printk("IPv6 ingress");
    dbg_print_http_connection_info(conn);

    // Check if we actually have a destination options header
    // tcp->ip_len points past the IPv6 header (and dest opts if present)
    const u32 ipv6_hdr_end = ETH_HLEN + sizeof(struct ipv6hdr);
    if (tcp->ip_len <= ipv6_hdr_end) {
        // No extension headers present
        return false;
    }

    const tp_info_pid_t *existing_tp =
        (tp_info_pid_t *)bpf_map_lookup_elem(&incoming_trace_map, conn);
    if (existing_tp) {
        bpf_dbg_printk("ignoring existing tp");
        return false;
    }

    // IPv6 Destination Options header format:
    // - Next Header (1 byte)
    // - Hdr Ext Len (1 byte) - in 8-byte units, not including first 8 bytes
    // - Options (variable)
    //
    // We injected: 09 14 <16 bytes trace_id> (24 bytes total, aligned to 8)
    // Option type 09 (unknown), length 14 (20 decimal)

    // Skip the first 4 bytes (next header + len + option type + option len)
    const u32 opts_start = ipv6_hdr_end + 4;
    const u32 opts_end = tcp->ip_len;

    // For now, assume our option is at the start (after the 4-byte header)
    // This matches our injection code which puts it right after the dest opts header
    if (opts_start + sizeof(((tp_info_t *)0)->trace_id) <= opts_end) {
        tp_info_pid_t new_tp = {.pid = 0, .valid = 1};
        populate_span_id_from_tcp_info(&new_tp.tp, tcp);

        // Load TraceID from the options area
        bpf_skb_load_bytes(skb, opts_start, &new_tp.tp.trace_id[0], sizeof(new_tp.tp.trace_id));

        print_tp(__func__, &new_tp);
        bpf_map_update_elem(&incoming_trace_map, conn, &new_tp, BPF_ANY);

        return true;
    }

    return false;
}

static __always_inline u8 inject_tc_ip_options_ipv4(struct __sk_buff *skb,
                                                    protocol_info_t *tcp,
                                                    tp_info_pid_t *tp) {
    // Verify no existing IP options before injection
    // This function should only be called when tcp->ip_len == k_min_ip_len (verified by caller)
    // but we double-check here for safety
    const u8 current_ihl = read_ihl(skb);

    if (current_ihl != k_min_ip_len) {
        bpf_dbg_printk("IP options already present (IHL=%d), not injecting", current_ihl);
        return 0;
    }

    print_tp(__func__, tp);

    if (!bpf_skb_adjust_room(
            skb, k_ip_option_len, BPF_ADJ_ROOM_NET, BPF_F_ADJ_ROOM_NO_CSUM_RESET)) {
        const u16 zero = 0;
        // Stream ID option: 1 byte type + 1 byte length + 16 bytes trace_id + 2 bytes padding = 20 bytes total
        // After bpf_skb_adjust_room with BPF_ADJ_ROOM_NET, space is inserted after the IP header
        // Write at the original IP header end (k_min_ip_len + ETH_HLEN)
        const u32 ip_off = k_min_ip_len + ETH_HLEN;
        const u16 opt_header = bpf_htons(k_ip_option_header);

        bpf_skb_store_bytes(skb, ip_off, &opt_header, sizeof(opt_header), 0);
        bpf_skb_store_bytes(
            skb, ip_off + sizeof(opt_header), &tp->tp.trace_id[0], sizeof(tp->tp.trace_id), 0);
        bpf_skb_store_bytes(
            skb, ip_off + sizeof(opt_header) + sizeof(tp->tp.trace_id), &zero, sizeof(zero), 0);
        const u32 offset_ip_tot_len = ETH_HLEN + offsetof(struct iphdr, tot_len);

        const u16 new_tot_len = bpf_htons(bpf_ntohs(tcp->tot_len) + k_ip_option_len);

        u8 hdr_len; // this 1 byte field is a composite of the IP version and the IHL
        bpf_skb_load_bytes(skb, ETH_HLEN, &hdr_len, sizeof(hdr_len));

        const u8 hdr_ver = hdr_len;
        u8 new_hdr_len = hdr_len;
        new_hdr_len &= 0x0f;
        new_hdr_len += (k_ip_option_len / 4); // IHL is a number of 32bit words
        new_hdr_len |= hdr_ver & 0xf0;

        bpf_dbg_printk(
            "prev h_len %d, new_h_len %d, new_tot_len %d", hdr_len, new_hdr_len, new_tot_len);

        bpf_skb_store_bytes(skb, offset_ip_tot_len, &new_tot_len, sizeof(u16), 0);
        bpf_skb_store_bytes(skb, ETH_HLEN, &new_hdr_len, sizeof(u8), 0);

        const u32 offset_ip_checksum = ETH_HLEN + offsetof(struct iphdr, check);

        // Update the IPv4 checksum for the change of the total packet length
        bpf_l3_csum_replace(skb, offset_ip_checksum, tcp->tot_len, new_tot_len, sizeof(u16));
        // Update the IPv4 checksum for the change of the IHL IP header field. We use replace of 2 bytes because
        // it's the minimum the API can do.
        bpf_l3_csum_replace(skb, offset_ip_checksum, hdr_len, new_hdr_len, sizeof(u16));
        // Update the IPv4 checksum for the addition of the option header (type 0x88 + length 20)
        bpf_l3_csum_replace(skb, offset_ip_checksum, 0, opt_header, sizeof(u16));
        // Update the IPv4 checksum for the TraceID value. The l3_csum_replace can only replace 2 or 4 byte values
        for (u8 i = 0; i < 4; i++) {
            bpf_l3_csum_replace(skb,
                                offset_ip_checksum,
                                0,
                                *((u32 *)&tp->tp.trace_id[i * sizeof(u32)]),
                                sizeof(u32));
        }

        return 1;
    }

    return 0;
}

static __always_inline u8 inject_tc_ip_options_ipv6(struct __sk_buff *skb,
                                                    protocol_info_t *tcp,
                                                    tp_info_pid_t *tp) {
    // Verify no existing IPv6 extension headers before injection
    // This function should only be called when tcp->ip_len == ETH_HLEN + sizeof(struct ipv6hdr)
    // but we double-check here for safety
    const u32 ipv6_hdr_end = ETH_HLEN + sizeof(struct ipv6hdr);
    if (tcp->ip_len != ipv6_hdr_end) {
        bpf_dbg_printk("IPv6 extension headers already present (ip_len=%d), not injecting",
                       tcp->ip_len);
        return 0;
    }

    if (!bpf_skb_adjust_room(skb,
                             k_max_ipv6_opts_len,
                             BPF_ADJ_ROOM_NET,
                             BPF_F_ADJ_ROOM_NO_CSUM_RESET)) { // Must be 8 byte aligned size
        const u8 next_hdr = IP_V6_DEST_OPTS;                  // 60 -> Destination options
        const u32 next_hdr_off = ETH_HLEN + offsetof(struct ipv6hdr, nexthdr);
        bpf_skb_store_bytes(skb, next_hdr_off, &next_hdr, sizeof(next_hdr), 0);

        const u32 next_hdr_start = tcp->ip_len;
        bpf_skb_store_bytes(skb,
                            next_hdr_start,
                            &tcp->l4_proto,
                            sizeof(tcp->l4_proto),
                            0); // The next header now has the L4 protocol info

        const u32 offset_ip_tot_len = ETH_HLEN + offsetof(struct ipv6hdr, payload_len);
        const u16 new_tot_len = bpf_htons(bpf_ntohs(tcp->tot_len) + k_max_ipv6_opts_len);
        bpf_skb_store_bytes(skb, offset_ip_tot_len, &new_tot_len, sizeof(u16), 0);

        const u8 hdr_len =
            (k_max_ipv6_opts_len - 8) / 8; // this value is expressed as multiples of 8
        bpf_skb_store_bytes(skb,
                            next_hdr_start + sizeof(next_hdr),
                            &hdr_len,
                            sizeof(hdr_len),
                            0); // The next header length is the total size - the first 8 bytes

        // 09 - Unknown option (thought about PadN but Linux kernel doesn't like it), 14 = 20 bytes length total padding
        const u16 options = 0x1409;
        // https://github.com/torvalds/linux/blob/87d6aab2389e5ce0197d8257d5f8ee965a67c4cd/net/ipv6/exthdrs.c#L150
        bpf_skb_store_bytes(skb,
                            next_hdr_start + sizeof(next_hdr) + sizeof(hdr_len),
                            &options,
                            sizeof(options),
                            0); // The next header length is the total size - the first 8 bytes

        bpf_skb_store_bytes(skb,
                            next_hdr_start + sizeof(next_hdr) + sizeof(hdr_len) + sizeof(options),
                            &tp->tp.trace_id[0],
                            sizeof(tp->tp.trace_id),
                            0);

        return 1;
    }

    return 0;
}

static __always_inline void update_outgoing_request_span_id(pid_connection_info_t *p_conn,
                                                            protocol_info_t *tcp,
                                                            tp_info_pid_t *tp,
                                                            const egress_key_t *e_key) {
    http_info_t *h_info = bpf_map_lookup_elem(&ongoing_http, p_conn);
    if (h_info && tp->valid) {
        bpf_dbg_printk("Found HTTP info, resetting the span id to %x%x", tcp->seq, tcp->ack);
        populate_span_id_from_tcp_info(&h_info->tp, tcp);
    }

    go_addr_key_t *g_key = bpf_map_lookup_elem(&go_ongoing_http, e_key);
    if (g_key) {
        bpf_dbg_printk("Found Go HTTP info, trying to find the span id");
        http_func_invocation_t *invocation =
            bpf_map_lookup_elem(&go_ongoing_http_client_requests, g_key);
        if (invocation) {
            bpf_dbg_printk(
                "Found Go HTTP invocation, resetting the span id to %x%x", tcp->seq, tcp->ack);
            populate_span_id_from_tcp_info(&invocation->tp, tcp);
        }
    }
}

static __always_inline void
encode_data_in_ip_options(struct __sk_buff *skb, protocol_info_t *tcp, tp_info_pid_t *tp) {
    // Handling IPv4
    // We only do this if the IP header doesn't have any options, this can be improved if needed
    if (tcp->h_proto == ETH_P_IP && tcp->ip_len == ETH_HLEN + k_min_ip_len) {
        bpf_dbg_printk("Adding the trace_id in the IP Options");

        inject_tc_ip_options_ipv4(skb, tcp, tp);
        tp->valid = 0;
    } else if (tcp->h_proto == ETH_P_IPV6 && tcp->l4_proto == IPPROTO_TCP &&
               tcp->ip_len == ETH_HLEN + sizeof(struct ipv6hdr)) { // Handling IPv6
        bpf_dbg_printk("Adding the trace_id in IPv6 Destination Options");

        inject_tc_ip_options_ipv6(skb, tcp, tp);
        tp->valid = 0;
    }
}

static __always_inline struct bpf_sock *lookup_sock_from_tuple(struct __sk_buff *skb,
                                                               struct bpf_sock_tuple *tuple,
                                                               enum protocol proto,
                                                               const void *data_end) {
    if (proto == protocol_ip4 &&
        (u64)((unsigned char *)tuple + sizeof(tuple->ipv4)) < (u64)data_end) {
        // Lookup to see if you can find a socket for this tuple in the
        // kernel socket tracking. We look up in all namespaces (-1).
        return bpf_sk_lookup_tcp(skb, tuple, sizeof(tuple->ipv4), BPF_F_CURRENT_NETNS, 0);
    } else if (proto == protocol_ip6 &&
               (u64)((unsigned char *)tuple + sizeof(tuple->ipv6)) < (u64)data_end) {
        return bpf_sk_lookup_tcp(skb, tuple, sizeof(tuple->ipv6), BPF_F_CURRENT_NETNS, 0);
    }

    return 0;
}

// We use this helper to read in the connection tuple information in the
// bpf_sock_tuple format. We use this struct to add sockets which are
// established before we launched Beyla, since we'll not see them in the
// sock_ops program which tracks them.
static __always_inline struct bpf_sock_tuple *get_tuple(const void *data,
                                                        __u64 nh_off,
                                                        const void *data_end,
                                                        __u16 eth_proto,
                                                        enum protocol *ip_proto) {
    struct bpf_sock_tuple *result;
    __u64 ihl_len = 0;
    __u8 proto = 0;

    *ip_proto = protocol_unknown;

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)(data + nh_off);

        if ((void *)(iph + 1) > data_end) {
            return 0;
        }

        ihl_len = iph->ihl * 4;
        proto = iph->protocol;
        *ip_proto = protocol_ip4;
        result = (struct bpf_sock_tuple *)&iph->saddr;
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + nh_off);

        if ((void *)(ip6h + 1) > data_end) {
            return 0;
        }

        ihl_len = sizeof(*ip6h);
        proto = ip6h->nexthdr;
        *ip_proto = protocol_ip6;
        result = (struct bpf_sock_tuple *)&ip6h->saddr;
    }

    if (data + nh_off + ihl_len > data_end || proto != IPPROTO_TCP) {
        return 0;
    }

    return result;
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

    // TODO revist to avoid pulling data (use bpf_skb_load_bytes instead)
    bpf_skb_pull_data(skb, skb->len);

    const void *data_end = ctx_data_end(skb);
    const void *data = ctx_data(skb);
    const struct ethhdr *eth = (struct ethhdr *)(data);

    if ((void *)(eth + 1) > data_end) {
        bpf_dbg_printk("bad size");
        return;
    }

    // Get the bpf_sock_tuple value so we can look up and see if we don't have
    // this socket yet in our map.
    enum protocol proto;
    struct bpf_sock_tuple *tuple = get_tuple(data, sizeof(*eth), data_end, eth->h_proto, &proto);
    //bpf_printk("tuple %llx, next %llx, data end %llx", tuple, (void *)((u8 *)tuple + sizeof(*tuple)), data_end);

    if (!tuple) {
        bpf_dbg_printk("bad tuple %llx, next %llx, data end %llx",
                       tuple,
                       (void *)(tuple + sizeof(struct bpf_sock_tuple)),
                       data_end);
        return;
    }

    struct bpf_sock *sk = lookup_sock_from_tuple(skb, tuple, proto, data_end);
    bpf_dbg_printk("sk=%llx\n", sk);

    if (!sk) {
        return;
    }

    bpf_map_update_elem(&sock_dir, conn, sk, BPF_NOEXIST);

    bpf_sk_release(sk);
}

static __always_inline bool
parse_ip_options(struct __sk_buff *skb, connection_info_t *conn, protocol_info_t *tcp) {

    bpf_dbg_printk(
        "parse_ip_options: h_proto=%x, ip_len=%u, skb_len=%u", tcp->h_proto, tcp->ip_len, skb->len);

    if (tcp->h_proto == ETH_P_IP && tcp->ip_len >= ETH_HLEN + k_min_ip_len + k_ip_option_len) {
        return parse_ip_options_ipv4(skb, conn, tcp);
    }

    if (tcp->h_proto == ETH_P_IPV6 && tcp->l4_proto == IP_V6_DEST_OPTS &&
        tcp->ip_len == ETH_HLEN + sizeof(struct ipv6hdr) + k_max_ipv6_opts_len) {
        return parse_ip_options_ipv6(skb, conn, tcp);
    }

    return false;
}

static __always_inline void
inject_ip_options(struct __sk_buff *skb, connection_info_t *conn, protocol_info_t *tcp) {
    const egress_key_t e_key = {
        .d_port = conn->d_port,
        .s_port = conn->s_port,
    };

    tp_info_pid_t *tp = bpf_map_lookup_elem(&outgoing_trace_map, &e_key);

    if (!tp) {
        return;
    }

    // this shouldn't ever be reached, as the tp should have already been
    // deleted by the kprobes when tp->written == 1, but it does not hurt to
    // be robust
    if (tp->written) {
        bpf_dbg_printk("tp already written by L7, not injecting IP options");
        bpf_map_delete_elem(&outgoing_trace_map, &e_key);
        return;
    }

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
    if (tp->valid == 1) {
        populate_span_id_from_tcp_info(&tp->tp, tcp);

        pid_connection_info_t p_conn = {};
        p_conn.conn = *conn;
        p_conn.pid = tp->pid;

        update_outgoing_request_span_id(&p_conn, tcp, tp, &e_key);
        // We set valid to 2, so we only run this once, the later packets
        // will have different SEQ/ACK.
        tp->valid = 2;
    }

    // The following code sets up the context information in L4 and it
    // does it only once. If it successfully injected the information it
    // will set valid to 0 so that we only run the L7 part from now on.
    if (tp->valid) {
        encode_data_in_ip_options(skb, tcp, tp);
    }
}

static __always_inline void process_ip_options(struct __sk_buff *skb) {
    protocol_info_t tcp = {};
    connection_info_t conn = {};

    if (!read_sk_buff(skb, &tcp, &conn)) {
        return;
    }

    track_sock(skb, &conn);

    sort_connection_info(&conn);

    if (parse_ip_options(skb, &conn, &tcp)) {
        return;
    }

    inject_ip_options(skb, &conn, &tcp);
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
