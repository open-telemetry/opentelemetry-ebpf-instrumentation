// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_endian.h>

#include <common/protocol_defs.h>

#include <logger/bpf_dbg.h>

#include <netolly/flows_common.h>

static u64 last_submitted = 0;
#if 1
static u64 last_sec = 0;
static u64 flow_count = 0;
#endif

struct __tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16 res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1,
        cwr : 1;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
};

struct __udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
};

static __always_inline bool read_sk_buff(struct __sk_buff *skb, flow_id *id, u16 *custom_flags) {
    // we read the protocol just like here linux/samples/bpf/parse_ldabs.c
    u16 h_proto;
    bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &h_proto, sizeof(h_proto));
    h_proto = __bpf_htons(h_proto);
    id->eth_protocol = h_proto;
    //id->if_index = skb->ifindex;

    u8 hdr_len;
    u8 proto = 0;
    // do something similar as linux/samples/bpf/parse_varlen.c
    switch (h_proto) {
    case ETH_P_IP: {
        // ip4 header lengths are variable
        // access ihl as a u8 (linux/include/linux/skbuff.h)
        bpf_skb_load_bytes(skb, ETH_HLEN, &hdr_len, sizeof(hdr_len));
        hdr_len &= 0x0f;
        hdr_len *= 4;

        /* verify hlen meets minimum size requirements */
        if (hdr_len < sizeof(struct iphdr)) {
            return false;
        }

        // we read the ip header linux/samples/bpf/parse_ldabs.c and linux/samples/bpf/tcbpf1_kern.c
        // the level 4 protocol let's us only filter TCP packets, the ip protocol gets us the source
        // and destination IP pairs
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol), &proto, sizeof(proto));

        u32 saddr;
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr), &saddr, sizeof(saddr));
        u32 daddr;
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), &daddr, sizeof(daddr));

        __builtin_memcpy(id->src_ip.s6_addr, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(id->dst_ip.s6_addr, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(id->src_ip.s6_addr + sizeof(ip4in6), &saddr, sizeof(saddr));
        __builtin_memcpy(id->dst_ip.s6_addr + sizeof(ip4in6), &daddr, sizeof(daddr));

        hdr_len = ETH_HLEN + hdr_len;
        break;
    }
    case ETH_P_IPV6:
        bpf_skb_load_bytes(
            skb, ETH_HLEN + offsetof(struct ipv6hdr, nexthdr), &proto, sizeof(proto));

        bpf_skb_load_bytes(skb,
                           ETH_HLEN + offsetof(struct ipv6hdr, saddr),
                           &id->src_ip.s6_addr,
                           sizeof(id->src_ip.s6_addr));
        bpf_skb_load_bytes(skb,
                           ETH_HLEN + offsetof(struct ipv6hdr, daddr),
                           &id->dst_ip.s6_addr,
                           sizeof(id->dst_ip.s6_addr));

        hdr_len = ETH_HLEN + sizeof(struct ipv6hdr);
        break;
    default:
        return false;
    }

    id->src_port = 0;
    id->dst_port = 0;
    id->transport_protocol = proto;

    switch (proto) {
    case IPPROTO_TCP: {
        u16 port;
        bpf_skb_load_bytes(skb, hdr_len + offsetof(struct __tcphdr, source), &port, sizeof(port));
        id->src_port = __bpf_htons(port);

        bpf_skb_load_bytes(skb, hdr_len + offsetof(struct __tcphdr, dest), &port, sizeof(port));
        id->dst_port = __bpf_htons(port);

        u8 doff;
        bpf_skb_load_bytes(
            skb,
            hdr_len + offsetof(struct __tcphdr, ack_seq) + 4,
            &doff,
            sizeof(
                doff)); // read the first byte past __tcphdr->ack_seq, we can't do offsetof bit fields
        doff &= 0xf0;   // clean-up res1
        doff >>= 4;     // move the upper 4 bits to low
        doff *= 4;      // convert to bytes length

        u8 flags;
        bpf_skb_load_bytes(
            skb,
            hdr_len + offsetof(struct __tcphdr, ack_seq) + 4 + 1,
            &flags,
            sizeof(flags)); // read the second byte past __tcphdr->doff, again bit fields offsets
        *custom_flags = ((u16)flags & 0x00ff);

        hdr_len += doff;

        if ((skb->len - hdr_len) < 0) { // less than 0 is a packet we can't parse
            return false;
        }

        break;
    }
    case IPPROTO_UDP: {
        u16 port;
        bpf_skb_load_bytes(skb, hdr_len + offsetof(struct __udphdr, source), &port, sizeof(port));
        id->src_port = __bpf_htons(port);
        bpf_skb_load_bytes(skb, hdr_len + offsetof(struct __udphdr, dest), &port, sizeof(port));
        id->dst_port = __bpf_htons(port);
        break;
    }
    default:
        return false;
    }

    // custom flags
    if ((*custom_flags & (TCPHDR_ACK | TCPHDR_SYN))) {
        *custom_flags |= SYN_ACK_FLAG;
    } else if ((*custom_flags & (TCPHDR_ACK | TCPHDR_FIN))) {
        *custom_flags |= FIN_ACK_FLAG;
    } else if ((*custom_flags & (TCPHDR_ACK | TCPHDR_RST))) {
        *custom_flags |= RST_ACK_FLAG;
    }

    return true;
}

static __always_inline bool same_ip(const u8 *ip1, const u8 *ip2) {
    for (int i = 0; i < 16; i += 4) {
        if (*((u32 *)(ip1 + i)) != *((u32 *)(ip2 + i))) {
            return false;
        }
    }

    return true;
}

#if 0
SEC("socket/filter")
int obi_socket__filter(struct __sk_buff *skb) {
    // If sampling is defined, will only parse 1 out of "sampling" flows
    if (sampling != 0 && (bpf_get_prandom_u32() % sampling) != 0) {
        return TC_ACT_UNSPEC;
    }

    u16 flags = 0;
    flow_id id;
    __builtin_memset(&id, 0, sizeof(id));
    if (!read_sk_buff(skb, &id, &flags)) {
        return TC_ACT_UNSPEC;
    }

    // ignore traffic that's not egress or ingress
    if (same_ip(id.src_ip.s6_addr, id.dst_ip.s6_addr)) {
        return TC_ACT_UNSPEC;
    }

    const u64 current_time = bpf_ktime_get_ns();

    // TODO: we need to add spinlock here when we deprecate versions prior to 5.1, or provide
    // a spinlocked alternative version and use it selectively https://lwn.net/Articles/779120/
    flow_metrics *aggregate_flow = (flow_metrics *)bpf_map_lookup_elem(&aggregated_flows, &id);
    if (aggregate_flow != NULL) {
        aggregate_flow->packets += 1;
        aggregate_flow->bytes += skb->len;
        aggregate_flow->end_mono_time_ns = current_time;
        // it might happen that start_mono_time hasn't been set due to
        // the way percpu hashmap deal with concurrent map entries
        if (aggregate_flow->start_mono_time_ns == 0) {
            aggregate_flow->start_mono_time_ns = current_time;
        }
        aggregate_flow->flags |= flags;

        long ret = bpf_map_update_elem(&aggregated_flows, &id, aggregate_flow, BPF_ANY);
        if (trace_messages && ret != 0) {
            // usually error -16 (-EBUSY) is printed here.
            // In this case, the flow is dropped, as submitting it to the ringbuffer would cause
            // a duplicated UNION of flows (two different flows with partial aggregation of the same packets),
            // which can't be deduplicated.
            // other possible values https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md
            bpf_dbg_printk("error updating flow %d\n", ret);
        }

        const u64 delta_nsec = current_time - aggregate_flow->last_submitted_time_ns;

        if (delta_nsec > 10e9) {
            //bpf_printk("current = %llu, last = %llu, delta = %llu", current_time, aggregate_flow->last_submitted_time_ns, delta_nsec);
            aggregate_flow->last_submitted_time_ns = current_time;

            const u64 rb_avail = bpf_ringbuf_query(&direct_flows, BPF_RB_AVAIL_DATA);

            bpf_printk("rb available = %llu", rb_avail);

            const u64 rb_delta_nsec = current_time - last_submitted;

            u64 rb_flags = BPF_RB_NO_WAKEUP;

            if (rb_delta_nsec > 15e9 || rb_avail + 1024 > (1 << 24)) {
                rb_flags = BPF_RB_FORCE_WAKEUP;
                last_submitted = current_time;
            }

            flow_record *record =
                (flow_record *)bpf_ringbuf_reserve(&direct_flows, sizeof(flow_record), 0);

            if (record) {
                record->id = id;
                record->metrics = *aggregate_flow;
                bpf_ringbuf_submit(record, rb_flags);

                //bpf_map_delete_elem(&aggregated_flows, &id);
            }
        }

    } else {
        // Key does not exist in the map, and will need to create a new entry.
        flow_metrics new_flow = {
            .packets = 1,
            .bytes = skb->len,
            .start_mono_time_ns = current_time,
            .end_mono_time_ns = current_time,
            .last_submitted_time_ns = current_time,
            .flags = flags,
            .iface_direction = UNKNOWN,
        };

        u8 *direction = (u8 *)bpf_map_lookup_elem(&flow_directions, &id);
        if (direction == NULL) {
            // Calculate direction based on first flag received
            // SYN and ACK mean someone else initiated the connection and this is the INGRESS direction
            if ((flags & (SYN_FLAG | ACK_FLAG)) == (SYN_FLAG | ACK_FLAG)) {
                new_flow.iface_direction = INGRESS;
            }
            // SYN only means we initiated the connection and this is the EGRESS direction
            else if ((flags & SYN_FLAG) == SYN_FLAG) {
                new_flow.iface_direction = EGRESS;
            }
            // save, when direction was calculated based on TCP flag
            if (new_flow.iface_direction != UNKNOWN) {
                // errors are intentionally omitted
                bpf_map_update_elem(&flow_directions, &id, &new_flow.iface_direction, BPF_NOEXIST);
            }
            // fallback for lost or already started connections and UDP
            else {
                new_flow.iface_direction = INGRESS;
                if (id.src_port > id.dst_port) {
                    new_flow.iface_direction = EGRESS;
                }
            }
        } else {
            // get direction from saved flow
            new_flow.iface_direction = *direction;
        }

        new_flow.initiator = get_connection_initiator(&id, flags);

        // even if we know that the entry is new, another CPU might be concurrently inserting a flow
        // so we need to specify BPF_ANY
        bpf_map_update_elem(&aggregated_flows, &id, &new_flow, BPF_ANY);

#if 0
        flow_record *record =
            (flow_record *)bpf_ringbuf_reserve(&direct_flows, sizeof(flow_record), 0);

        if (record) {
            record->id = id;
            record->metrics = new_flow;
            bpf_ringbuf_submit(record, BPF_RB_NO_WAKEUP);
        }
#endif
    }

    // finally, when flow receives FIN or RST, clean flow_directions
    if (flags & FIN_FLAG || flags & RST_FLAG) {
        bpf_map_delete_elem(&flow_directions, &id);
    }
    return TC_ACT_UNSPEC;
}
#else

static __always_inline char hex4(__u8 v) {
    v &= 0x0f;
    return v < 10 ? ('0' + v) : ('a' + (v - 10));
}

// s6 points to the 16-byte in6_addr.s6_addr
static __always_inline void print_ip6(const u8 *s6, u16 port) {
    // Check ::ffff:W.X.Y.Z
    if (!s6[0] && !s6[1] && !s6[2] && !s6[3] && !s6[4] && !s6[5] && !s6[6] && !s6[7] && !s6[8] &&
        !s6[9] && s6[10] == 0xff && s6[11] == 0xff) {
        bpf_printk("IPv4: %d.%d.%d.%d:%u\n", s6[12], s6[13], s6[14], s6[15], port);
        return;
    }

    // Fallback: print full uncompressed IPv6 hhhh:...:hhhh
    char out[40]; // 8*4 hex + 7 ':' + NUL
#pragma unroll
    for (int i = 0; i < 8; i++) {
        __u8 hi = s6[2 * i];
        __u8 lo = s6[2 * i + 1];
        int o = i * 5;

        out[o + 0] = hex4(hi >> 4);
        out[o + 1] = hex4(hi);
        out[o + 2] = hex4(lo >> 4);
        out[o + 3] = hex4(lo);
        if (i != 7)
            out[o + 4] = ':';
    }
    out[39] = '\0';
    bpf_printk("IPv6: %s:%u\n", out, port);
}

SEC("socket/filter")
int obi_socket__filter(struct __sk_buff *skb) {
    // If sampling is defined, will only parse 1 out of "sampling" flows
    if (sampling != 0 && (bpf_get_prandom_u32() % sampling) != 0) {
        return TC_ACT_UNSPEC;
    }

    u16 flags = 0;
    flow_id id;

    __builtin_memset(&id, 0, sizeof(id));

    if (!read_sk_buff(skb, &id, &flags)) {
        return TC_ACT_UNSPEC;
    }

    // ignore traffic that's not egress or ingress
    if (same_ip(id.src_ip.s6_addr, id.dst_ip.s6_addr)) {
        return TC_ACT_UNSPEC;
    }

    flow_record *record = (flow_record *)get_sk_storage(skb->sk);

    if (!record) {
        bpf_printk("sk = %llu", skb->sk);
        print_ip6(id.src_ip.s6_addr, id.src_port);
        print_ip6(id.dst_ip.s6_addr, id.dst_port);
        bpf_printk("====\n");
        return TC_ACT_UNSPEC;
    }

    //record->id.if_index = id.if_index;
    record->id.eth_protocol = id.eth_protocol;
    record->id.transport_protocol = id.transport_protocol;

    record->metrics.packets++;
    record->metrics.bytes += skb->len;
    record->metrics.flags |= flags;

    return TC_ACT_UNSPEC;
}
#endif

static __always_inline struct in6_addr encode_ipv4in6(u32 ipv4) {
    struct in6_addr addr;

    __builtin_memcpy(addr.s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(addr.s6_addr + sizeof(ip4in6), &ipv4, sizeof(ipv4));

    return addr;
}

static __always_inline void ip4_to_str(__u32 ip, char *buf, __u32 buf_size) {
    // IP is in host byte order, so split manually
    __u8 *bytes = (__u8 *)&ip;
    __u64 data[] = {bytes[0], bytes[1], bytes[2], bytes[3]};

    // Format into buffer: e.g., "127.0.0.1"
    bpf_snprintf(buf, buf_size, "%d.%d.%d.%d", data, sizeof(data));
}

static __always_inline void init_flow(struct bpf_sock_ops *skops, u8 direction) {
    const u32 local_ip = bpf_ntohl(skops->local_ip4);
    const u32 remote_ip = bpf_ntohl(skops->remote_ip4);

    if (local_ip == remote_ip) {
        return;
    }

    flow_record *record = (flow_record *)new_sk_storage(skops->sk);

    if (!record)
        return;

    const u64 current_time = bpf_ktime_get_ns();

    //FIXME IPv6
    record->id.src_ip = encode_ipv4in6(skops->local_ip4);
    record->id.dst_ip = encode_ipv4in6(skops->remote_ip4);
    record->id.src_port = skops->local_port;
    record->id.dst_port = bpf_ntohl(skops->remote_port);
    //record->id.if_index = 0; // FIXME
    record->id.eth_protocol = 0;       // FIXME
    record->id.transport_protocol = 0; // FIXME

    record->metrics.iface_direction = direction;
    record->metrics.start_mono_time_ns = current_time;
    record->metrics.end_mono_time_ns = current_time;

    bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
}

static __always_inline void on_active_established(struct bpf_sock_ops *skops) {
    init_flow(skops, EGRESS);
}

static __always_inline void on_passive_established(struct bpf_sock_ops *skops) {
    init_flow(skops, INGRESS);
}

static __always_inline u64 get_rb_flags() {
    const u64 current_time = bpf_ktime_get_ns();
    const u64 rb_avail = bpf_ringbuf_query(&direct_flows, BPF_RB_AVAIL_DATA);
    const u64 delta_nsec = current_time - last_submitted;

    bpf_printk("RB USED: %llu", rb_avail);

    if ((delta_nsec > 10e9) || (rb_avail + 1024 * 1024) >= (1 << 24)) {
        last_submitted = current_time;
        return BPF_RB_FORCE_WAKEUP;
    }

    return BPF_RB_NO_WAKEUP;
}

static __always_inline void on_state_changed(struct bpf_sock_ops *skops) {
    if (skops->args[1] != BPF_TCP_CLOSE)
        return;

    flow_record *record = (flow_record *)get_sk_storage(skops->sk);

    if (!record)
        return;

    bpf_ringbuf_output(&direct_flows, record, sizeof(*record), get_rb_flags());

    clear_sk_storage(skops->sk);
}

SEC("sockops")
int obi_flow_ops(struct bpf_sock_ops *skops) {
    char ip_buf[] = "000.000.000.000";

    const u32 local_ip = bpf_ntohl(skops->local_ip4);
    ip4_to_str(bpf_htonl(local_ip), (char *)&ip_buf, sizeof(ip_buf));

    bpf_printk(
        "sock = %llx, op = %u client addr: %s:%u", skops->sk, skops->op, ip_buf, skops->local_port);

    switch (skops->op) {
    //case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
    case BPF_SOCK_OPS_TCP_CONNECT_CB:
        on_active_established(skops);
        break;
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        on_passive_established(skops);
        break;
    case BPF_SOCK_OPS_STATE_CB:
        on_state_changed(skops);
        break;
    }

    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, flow_record);
} sk_storage_map2 SEC(".maps");

static __always_inline void update_flows_psec() {
    const u64 current_time = bpf_ktime_get_ns();

    ++flow_count;

    if (current_time - last_sec > 1e9) {
        last_sec = current_time;
        bpf_printk("flows/s: %llu", flow_count);
        flow_count = 0;
    }
}

SEC("cgroup_skb/egress")
int obi_sock_egress(struct __sk_buff *skb) {
    if (!skb->sk) {
        return 1;
    }

    update_flows_psec();

    struct bpf_sock *sk = skb->sk;

    if (sk) {
        flow_record *record =
            bpf_sk_storage_get(&sk_storage_map2, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);

        if (!record) {
            bpf_printk("sock_bind failed");
            return 1;
        }

        //FIXME IPv6
        record->id.src_ip = encode_ipv4in6(skb->local_ip4);
        record->id.dst_ip = encode_ipv4in6(skb->remote_ip4);
        record->id.src_port = skb->local_port;
        record->id.dst_port = bpf_ntohl(skb->remote_port);
        //record->id.if_index = skb->ifindex;
        record->id.eth_protocol = 0; // FIXME
        record->id.transport_protocol = skb->protocol;

        record->metrics.iface_direction = EGRESS;
#if 0
        const u64 current_time = bpf_ktime_get_ns();

        record->metrics.start_mono_time_ns = current_time;
        record->metrics.end_mono_time_ns = current_time;

        char ip_buf[] = "000.000.000.000";
        const u32 local_ip = bpf_ntohl(skb->local_ip4);
        ip4_to_str(bpf_htonl(local_ip), (char*) &ip_buf, sizeof(ip_buf));
        bpf_printk("lient addr: %s:%u", ip_buf, skb->local_port);
#endif
    }

    return 1;
}

SEC("cgroup_skb/ingress")
int obi_sock_ingress(struct __sk_buff *skb) {
    if (!skb->sk) {
        return 1;
    }

    update_flows_psec();

    struct bpf_sock *sk = skb->sk;

    if (sk) {
        flow_record *record =
            bpf_sk_storage_get(&sk_storage_map2, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);

        if (!record) {
            bpf_printk("sock_bind failed");
            return 1;
        }

        //FIXME IPv6
        record->id.src_ip = encode_ipv4in6(skb->local_ip4);
        record->id.dst_ip = encode_ipv4in6(skb->remote_ip4);
        record->id.src_port = skb->local_port;
        record->id.dst_port = bpf_ntohl(skb->remote_port);
        //record->id.if_index = skb->ingress_ifindex;
        record->id.eth_protocol = 0; // FIXME
        record->id.transport_protocol = skb->protocol;

        record->metrics.iface_direction = INGRESS;
#if 0
        const u64 current_time = bpf_ktime_get_ns();

        record->metrics.start_mono_time_ns = current_time;
        record->metrics.end_mono_time_ns = current_time;

        char ip_buf[] = "000.000.000.000";
        const u32 local_ip = bpf_ntohl(skb->local_ip4);
        ip4_to_str(bpf_htonl(local_ip), (char*) &ip_buf, sizeof(ip_buf));
        bpf_printk("lient addr: %s:%u", ip_buf, skb->local_port);
#endif
    }

    return 1;
}

SEC("cgroup/sock_release")
int obi_sock_release(struct bpf_sock *sock) {
    flow_record *record = bpf_sk_storage_get(&sk_storage_map2, sock, 0, 0);

    if (record) {
        //bpf_printk("sock_release: shipping it");
        bpf_ringbuf_output(&direct_flows, record, sizeof(*record), get_rb_flags());
    } else {
        bpf_printk("sock_release: failed");
    }

    return 1;
}

// Force emitting structs into the ELF for automatic creation of Golang struct
const flow_metrics *unused_flow_metrics __attribute__((unused));
const flow_id *unused_flow_id __attribute__((unused));
const flow_record *unused_flow_record __attribute__((unused));

char _license[] SEC("license") = "GPL";
