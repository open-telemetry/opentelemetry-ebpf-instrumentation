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
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_endian.h>

#include <common/protocol_defs.h>

#include <netolly/flow.h>

static u64 last_submitted = 0;
#if 1
static u64 last_sec = 0;
static u64 flow_count = 0;
#endif

volatile const u8 k_protocol_wl_empty;
volatile const u8 k_protocol_bl_empty;
volatile const u32 k_max_rb_size;
volatile const u64 k_rb_flush_period;
volatile const u64 k_max_flow_duration;

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, flow_socket_data);
} sk_storage_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, u8);
} protocol_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, u8);
} protocol_blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} direct_flows SEC(".maps");

enum flow_direction : u8 { k_flow_ingress = 0, k_flow_egress = 1, k_flow_unknown = 0xff };

enum : u32 { k_invalid_iface = 0 };
enum : u8 { k_proto_unknown = 0xff };

static __always_inline u64 get_rb_flags() {
    const u64 current_time = bpf_ktime_get_ns();
    const u64 rb_avail = bpf_ringbuf_query(&direct_flows, BPF_RB_AVAIL_DATA);
    const u64 delta_nsec = current_time - last_submitted;

    bpf_printk("RB USED: %llu", rb_avail);

    if ((delta_nsec > k_rb_flush_period) || (rb_avail + sizeof(flow_record)) >= k_max_rb_size) {
        last_submitted = current_time;
        return BPF_RB_FORCE_WAKEUP;
    }

    return BPF_RB_NO_WAKEUP;
}

static __always_inline u8 same_ip(const unsigned char *ip1, const unsigned char *ip2) {
    for (int i = 0; i < 16; i += 4) {
        if (*((u32 *)(ip1 + i)) != *((u32 *)(ip2 + i))) {
            return 0;
        }
    }

    return 1;
}

static __always_inline u8 get_transport_proto(const struct __sk_buff *skb) {
    u16 l3 = bpf_ntohs(skb->protocol);
    u8 nh;

    if (l3 == ETH_P_IP) {
        if (bpf_skb_load_bytes_relative(
                skb, offsetof(struct iphdr, protocol), &nh, 1, BPF_HDR_START_NET) < 0)
            return k_proto_unknown;
        return nh;
    }

    if (l3 != ETH_P_IPV6) {
        return k_proto_unknown;
    }

    // IPv6 can spread across multiple headers, we need to iterate them

    // start at ipv6hdr, then walk extension headers
    if (bpf_skb_load_bytes_relative(
            skb, offsetof(struct ipv6hdr, nexthdr), &nh, 1, BPF_HDR_START_NET) < 0) {
        return k_proto_unknown;
    }

    u32 off = sizeof(struct ipv6hdr);

#pragma unroll
    for (int i = 0; i < 6; i++) {
        // terminal (or good-enough) protocols
        if (nh == 6 ||   // TCP
            nh == 17 ||  // UDP
            nh == 58 ||  // ICMPv6
            nh == 132 || // SCTP
            nh == 136 || // UDP-Lite
            nh == 50 ||  // ESP (encrypted—stop)
            nh == 59)    // No Next Header
            return nh;

        // Hop-by-Hop / Dest Options / Routing: len = (HdrExtLen+1)*8
        if (nh == 0 || nh == 60 || nh == 43) {
            u8 next, hdrlen8;

            if (bpf_skb_load_bytes_relative(skb, off + 0, &next, 1, BPF_HDR_START_NET) < 0) {
                return k_proto_unknown;
            }

            if (bpf_skb_load_bytes_relative(skb, off + 1, &hdrlen8, 1, BPF_HDR_START_NET) < 0) {
                return k_proto_unknown;
            }

            off += ((u32)hdrlen8 + 1) * 8;

            nh = next;

            continue;
        }

        // fragment header: fixed 8 bytes
        if (nh == 44) {
            u8 next;

            if (bpf_skb_load_bytes_relative(skb, off + 0, &next, 1, BPF_HDR_START_NET) < 0) {
                return k_proto_unknown;
            }

            off += 8;
            nh = next;

            continue;
        }

        // AH: len = (PayloadLen+2)*4
        if (nh == 51) {
            __u8 next, hdrlen32;

            if (bpf_skb_load_bytes_relative(skb, off + 0, &next, 1, BPF_HDR_START_NET) < 0) {
                return k_proto_unknown;
            }

            if (bpf_skb_load_bytes_relative(skb, off + 1, &hdrlen32, 1, BPF_HDR_START_NET) < 0) {
                return k_proto_unknown;
            }

            off += ((u32)hdrlen32 + 2) * 4;
            nh = next;

            continue;
        }

        // unknown, return what we have
        return nh;
    }

    // ditto
    return nh;
}

static __always_inline u8 is_protocol_allowed(u8 proto) {
    // if both lists are empty, always allow
    if (k_protocol_wl_empty && k_protocol_bl_empty) {
        return 1;
    }

    const u32 key = proto;

    // if the whitelist is not empty, only allow a protocol that is in the
    // whitelist
    if (!k_protocol_wl_empty) {
        const u8 *b = bpf_map_lookup_elem(&protocol_whitelist, &key);
        return b && *b;
    }

    // if we get here, the whitelist is empty but the blacklist isn't, so
    // only allow a protocol that is not in the blacklist
    const u8 *b = bpf_map_lookup_elem(&protocol_blacklist, &key);
    return !(b && *b);
}

static __always_inline struct in6_addr encode_ipv4in6(u32 ipv4) {
    const unsigned char ip4in6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

    struct in6_addr addr;

    __builtin_memcpy(addr.in6_u.u6_addr8, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(addr.in6_u.u6_addr8 + sizeof(ip4in6), &ipv4, sizeof(ipv4));

    return addr;
}

static __always_inline void update_flows_psec() {
    const u64 current_time = bpf_ktime_get_ns();

    ++flow_count;

    if (current_time - last_sec > 1e9) {
        last_sec = current_time;
        bpf_printk("flows/s: %llu", flow_count);
        flow_count = 0;
    }
}

static __always_inline flow_socket_data *get_sk_storage(struct bpf_sock *sk) {
    if (!sk) {
        return NULL;
    }

    flow_socket_data init = {
        .ctx.egress_submitted_iface = k_invalid_iface,
        .ctx.start_direction = k_flow_unknown,
        .ctx.transport_protocol = k_proto_unknown,
    };

    // BPF_SK_STORAGE_GET_F_CREATE will only create a new entry initialised
    // with 'init' if it does not yet exist, returning the existing entry
    // otherwise
    return bpf_sk_storage_get(&sk_storage_map, sk, &init, BPF_SK_STORAGE_GET_F_CREATE);
}

static __always_inline void ignore_flow(struct bpf_sock *sk) {
    flow_socket_data *data = get_sk_storage(sk);

    if (!data) {
        return;
    }

    bpf_spin_lock(&data->lock);

    data->ignore = 1;

    bpf_spin_unlock(&data->lock);
}

static __always_inline void init_flow(struct bpf_sock_ops *skops, u8 direction) {
    if (skops->family != AF_INET && skops->family != AF_INET6) {
        ignore_flow(skops->sk);
        return;
    }

    if (skops->family == AF_INET && skops->local_ip4 == skops->remote_ip4) {
        ignore_flow(skops->sk);
        return;
    }

    flow_ctx ctx = {};

    if (skops->family == AF_INET) {
        ctx.local_ip = encode_ipv4in6(skops->local_ip4);
        ctx.remote_ip = encode_ipv4in6(skops->remote_ip4);
    } else if (skops->family == AF_INET6) {
        bpf_probe_read_kernel(
            ctx.local_ip.in6_u.u6_addr8, sizeof(skops->local_ip6), skops->local_ip6);
        bpf_probe_read_kernel(
            ctx.remote_ip.in6_u.u6_addr8, sizeof(skops->remote_ip6), skops->remote_ip6);

        if (same_ip(ctx.local_ip.in6_u.u6_addr8, ctx.remote_ip.in6_u.u6_addr8)) {
            // unlike ipv4, we'd always need to read the IPv6 data into a
            // buffer for comparison - so instead we just mark the record to
            // be ignored from now on, to prevent the recorf from being
            // created and deleted everytime this codepath is hit -
            // instead, it will be cleaned up when the socket dies
            ignore_flow(skops->sk);
            return;
        }
    }

    ctx.local_port = skops->local_port;
    ctx.remote_port = bpf_ntohl(skops->remote_port);
    ctx.transport_protocol = k_proto_unknown;
    ctx.start_direction = direction;

    const u64 current_time = bpf_ktime_get_ns();

    ctx.start_mono_time_ns = current_time;
    ctx.end_mono_time_ns = current_time;

    // here we unconditionally update the flow, even if it was initialised by
    // cgroup/{egress, ingress} (unlikely) as we'd like to store the correct
    // direction
    flow_socket_data *data = get_sk_storage(skops->sk);

    if (!data) {
        return;
    }

    bpf_spin_lock(&data->lock);

    data->ctx = ctx;
    data->initialized = 1;

    bpf_spin_unlock(&data->lock);
}

static __always_inline void
init_flow_skb(struct __sk_buff *skb, flow_socket_data *data, u8 direction) {
    flow_ctx ctx = {};
    ctx.transport_protocol = get_transport_proto(skb);

    if (!is_protocol_allowed(ctx.transport_protocol)) {
        ignore_flow(skb->sk);
        return;
    }

    if (skb->family == AF_INET) {
        ctx.local_ip = encode_ipv4in6(skb->local_ip4);
        ctx.remote_ip = encode_ipv4in6(skb->remote_ip4);
    } else if (skb->family == AF_INET6) {
        bpf_probe_read_kernel(ctx.local_ip.in6_u.u6_addr8, sizeof(skb->local_ip6), skb->local_ip6);
        bpf_probe_read_kernel(
            ctx.remote_ip.in6_u.u6_addr8, sizeof(skb->remote_ip6), skb->remote_ip6);

        if (same_ip(ctx.local_ip.in6_u.u6_addr8, ctx.remote_ip.in6_u.u6_addr8)) {
            // unlike IPv4, we'd always need to read the IPv6 data into a
            // buffer for comparison - so instead we just mark the record to
            // be ignored from now on, to prevent the record from being
            // created and deleted everytime this codepath is hit -
            // instead, it will be cleaned up when the socket dies
            ignore_flow(skb->sk);
            return;
        }
    }

    ctx.local_port = skb->local_port;
    ctx.remote_port = bpf_ntohl(skb->remote_port);

    const u64 current_time = bpf_ktime_get_ns();

    ctx.start_mono_time_ns = current_time;
    ctx.end_mono_time_ns = current_time;

    // fallback for lost or already started connections and UDP
    ctx.start_direction = ctx.local_port > ctx.remote_port ? k_flow_egress : k_flow_ingress;

    if (direction == k_flow_egress) {
        ctx.ingress_if_index = k_invalid_iface;
        ctx.egress_if_index = skb->ifindex;

        ctx.tx_bytes = skb->len;
        ctx.tx_packets = 1;
    } else if (direction == k_flow_ingress) {
        ctx.ingress_if_index = skb->ifindex;
        ctx.egress_if_index = k_invalid_iface;

        ctx.rx_bytes = skb->len;
        ctx.rx_packets = 1;
    }

    bpf_spin_lock(&data->lock);

    if (!data->initialized) {
        data->ctx = ctx;
        data->initialized = 1;
    }

    bpf_spin_unlock(&data->lock);
}

static __always_inline void submit_flows(const flow_ctx *ctx) {
    const u64 rb_flags = get_rb_flags();

    if (ctx->tx_bytes > 0) {
        flow_record *record = bpf_ringbuf_reserve(&direct_flows, sizeof(flow_record), 0);

        if (!record) {
            return;
        }

        record->id.local_ip = ctx->local_ip;
        record->id.remote_ip = ctx->remote_ip;
        record->id.if_index = ctx->egress_if_index;
        record->id.local_port = ctx->local_port;
        record->id.remote_port = ctx->remote_port;
        record->id.transport_protocol = ctx->transport_protocol;

        record->metrics.bytes = ctx->tx_bytes;
        record->metrics.packets = ctx->tx_packets;
        record->metrics.iface_direction = k_flow_egress;
        record->metrics.start_direction = ctx->start_direction;

        bpf_ringbuf_submit(record, rb_flags);
    }

    if (ctx->rx_bytes > 0) {
        flow_record *record = bpf_ringbuf_reserve(&direct_flows, sizeof(flow_record), 0);

        if (!record) {
            return;
        }

        record->id.local_ip = ctx->local_ip;
        record->id.remote_ip = ctx->remote_ip;
        record->id.if_index = ctx->ingress_if_index;
        record->id.local_port = ctx->local_port;
        record->id.remote_port = ctx->remote_port;
        record->id.transport_protocol = ctx->transport_protocol;

        record->metrics.bytes = ctx->rx_bytes;
        record->metrics.packets = ctx->rx_packets;
        record->metrics.iface_direction = k_flow_ingress;
        record->metrics.start_direction = ctx->start_direction;

        bpf_ringbuf_submit(record, rb_flags);
    }
}

static __always_inline void submit_and_reset_flows(flow_socket_data *data, u64 current_time_ns) {
    bpf_spin_lock(&data->lock);

    // because we can hit this at any time, settle on an interface to
    // submit to avoid cardinality explosion
    if (data->ctx.egress_submitted_iface == k_invalid_iface) {
        data->ctx.egress_submitted_iface = data->ctx.egress_if_index;
    } else {
        data->ctx.egress_if_index = data->ctx.egress_submitted_iface;
    }

    flow_ctx ctx = data->ctx;
    ctx.end_mono_time_ns = current_time_ns;

    // reset whilst preserving flow metadata
    data->ctx.tx_bytes = 0;
    data->ctx.rx_bytes = 0;
    data->ctx.tx_packets = 0;
    data->ctx.rx_packets = 0;
    data->ctx.start_mono_time_ns = current_time_ns;
    data->ctx.end_mono_time_ns = current_time_ns;

    bpf_spin_unlock(&data->lock);

    submit_flows(&ctx);
}

static __always_inline void update_flow(struct __sk_buff *skb, u8 direction) {
    if (skb->family != AF_INET && skb->family != AF_INET6) {
        return;
    }

    if (skb->family == AF_INET && skb->local_ip4 == skb->remote_ip4) {
        return;
    }

    flow_socket_data *data = get_sk_storage(skb->sk);

    if (!data) {
        bpf_printk("update_flow failed");
        return;
    }

    update_flows_psec();

    bpf_spin_lock(&data->lock);

    const u32 ingress_if_index = data->ctx.ingress_if_index;
    const u32 egress_if_index = data->ctx.egress_if_index;
    const u8 initialized = data->initialized;

    u8 transport_proto = data->ctx.transport_protocol;
    u8 ignore = data->ignore;

    u64 start_mono_ns = data->ctx.start_mono_time_ns;

    if (direction == k_flow_egress) {
        data->ctx.tx_bytes += skb->len;
        data->ctx.tx_packets++;
    } else if (direction == k_flow_ingress) {
        data->ctx.rx_bytes += skb->len;
        data->ctx.rx_packets++;
    }

    bpf_spin_unlock(&data->lock);

    if (ignore) {
        return;
    }

    if (initialized) {
        if (direction == k_flow_ingress) {
            if (ingress_if_index == k_invalid_iface) {
                // first time we see an ingress packet (the flow could have
                // been initialised on egress), update the interface

                bpf_spin_lock(&data->lock);

                data->ctx.ingress_if_index = skb->ifindex;

                bpf_spin_unlock(&data->lock);
            } else if (ingress_if_index != skb->ingress_ifindex) {
                // this packet has arrived at a different interface, we don't want
                // to account for it again
                return;
            }
        } else if (direction == k_flow_egress && egress_if_index != skb->ifindex) {
            // we have seen this packet and have already accounted for it, but
            // we want to register the last outgoing interface to ensure we
            // report the true interface used when the packet has left this
            // node
            bpf_spin_lock(&data->lock);

            data->ctx.egress_if_index = skb->ifindex;

            bpf_spin_unlock(&data->lock);
            return;
        }
    }

    // this happens when we haven't seen the flow in obi_sock_ops, i.e. the
    // flow had already begun before obi_sock_ops was loaded
    if (!initialized) {
        init_flow_skb(skb, data, direction);

        bpf_spin_lock(&data->lock);

        ignore = data->ignore;
        start_mono_ns = data->ctx.start_mono_time_ns;

        bpf_spin_unlock(&data->lock);

        if (ignore) {
            return;
        }
    }

    // this will run only the first time we see the flow to update the
    // transport protocol and check if the flow is to be ignored
    if (transport_proto == k_proto_unknown) {
        transport_proto = get_transport_proto(skb);

        const u8 proto_allowed = is_protocol_allowed(transport_proto);

        bpf_spin_lock(&data->lock);

        data->ctx.transport_protocol = transport_proto;
        data->ignore = !proto_allowed;

        bpf_spin_unlock(&data->lock);

        if (!proto_allowed) {
            return;
        }
    }

    const u64 current_time_ns = bpf_ktime_get_ns();
    const u64 delta_ns = current_time_ns - start_mono_ns;

    if (delta_ns > current_time_ns) {
        // overflow, try again later
        return;
    }

    // we've hit a time deadline, submit this flow as is and start over
    if (delta_ns > k_max_flow_duration) {
        submit_and_reset_flows(data, current_time_ns);
    }
}

SEC("sockops")
int obi_sock_ops(struct bpf_sock_ops *skops) {
    switch (skops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        init_flow(skops, k_flow_egress);
        break;
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        init_flow(skops, k_flow_ingress);
        break;
    }

    return 0;
}

SEC("cgroup_skb/egress")
int obi_sock_egress(struct __sk_buff *skb) {
    update_flow(skb, k_flow_egress);
    return 1;
}

SEC("cgroup_skb/ingress")
int obi_sock_ingress(struct __sk_buff *skb) {
    update_flow(skb, k_flow_ingress);
    return 1;
}

SEC("cgroup/sock_release")
int obi_sock_release(struct bpf_sock *sock) {
    flow_socket_data *data = bpf_sk_storage_get(&sk_storage_map, sock, 0, 0);

    if (!data) {
        return 1;
    }

    bpf_spin_lock(&data->lock);

    flow_ctx ctx = data->ctx;

    const u8 ignore = data->ignore;

    bpf_spin_unlock(&data->lock);

    if (!ignore) {
        ctx.end_mono_time_ns = bpf_ktime_get_ns();
        submit_flows(&ctx);
    }

    return 1;
}

// Force emitting structs into the ELF for automatic creation of Golang struct
const flow_metrics *unused_flow_metrics __attribute__((unused));
const flow_id *unused_flow_id __attribute__((unused));
const flow_record *unused_flow_record __attribute__((unused));

char _license[] SEC("license") = "GPL";
