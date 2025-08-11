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

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, flow_record);
} sk_storage_map SEC(".maps");

static __always_inline u8 same_ip(const unsigned char *ip1, const unsigned char *ip2) {
    for (int i = 0; i < 16; i += 4) {
        if (*((u32 *)(ip1 + i)) != *((u32 *)(ip2 + i))) {
            return 0;
        }
    }

    return 1;
}

static __always_inline struct in6_addr encode_ipv4in6(u32 ipv4) {
    struct in6_addr addr;

    __builtin_memcpy(addr.s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(addr.s6_addr + sizeof(ip4in6), &ipv4, sizeof(ipv4));

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

static __always_inline flow_record *get_sk_storage(struct bpf_sock *sk) {
    if (!sk) {
        return NULL;
    }

    // FIXME direction UNKNOWN should be 0? migrate to an enum
    flow_record init = {.metrics.iface_direction = UNKNOWN};

    // BPF_SK_STORAGE_GET_F_CREATE will only create a new entry initialised
    // with 'init' if it does not yet exist, returning the existing entry
    // otherwise
    return bpf_sk_storage_get(&sk_storage_map, sk, &init, BPF_SK_STORAGE_GET_F_CREATE);
}

static __always_inline void init_flow(struct bpf_sock_ops *skops, u8 direction) {
    if (skops->family != AF_INET && skops->family != AF_INET6) {
        return;
    }

    if (skops->family == AF_INET && skops->local_ip4 == skops->remote_ip4) {
        return;
    }

    flow_record *record = get_sk_storage(skops->sk);

    if (!record) {
        bpf_printk("sock_ops failed");
        return;
    }

    if (skops->family == AF_INET) {
        record->id.src_ip = encode_ipv4in6(skops->local_ip4);
        record->id.dst_ip = encode_ipv4in6(skops->remote_ip4);
    } else if (skops->family == AF_INET6) {
        bpf_probe_read_kernel(
            record->id.src_ip.s6_addr, sizeof(skops->local_ip6), skops->local_ip6);
        bpf_probe_read_kernel(
            record->id.dst_ip.s6_addr, sizeof(skops->remote_ip6), skops->remote_ip6);

        if (same_ip(record->id.src_ip.s6_addr, record->id.dst_ip.s6_addr)) {
            // unlike ipv4, we'd always need to read the IPv6 data into a
            // buffer for comparison - so instead we just mark the record to
            // be ignored from now on, to prevent the recorf from being
            // created and deleted everytime this codepath is hit -
            // instead, it will be cleaned up when the socket dies
            record->ignore = 1;
            return;
        }
    }

    record->id.src_port = skops->local_port;
    record->id.dst_port = bpf_ntohl(skops->remote_port);

    record->metrics.iface_direction = direction;

    const u64 current_time = bpf_ktime_get_ns();

    record->metrics.start_mono_time_ns = current_time;
    record->metrics.end_mono_time_ns = current_time;

    record->initialized = 1;
}

static __always_inline u8 init_flow_skb(struct __sk_buff *skb, flow_record *record) {
    if (skb->family == AF_INET) {
        record->id.src_ip = encode_ipv4in6(skb->local_ip4);
        record->id.dst_ip = encode_ipv4in6(skb->remote_ip4);
    } else if (skb->family == AF_INET6) {
        bpf_probe_read_kernel(record->id.src_ip.s6_addr, sizeof(skb->local_ip6), skb->local_ip6);
        bpf_probe_read_kernel(record->id.dst_ip.s6_addr, sizeof(skb->remote_ip6), skb->remote_ip6);

        if (same_ip(record->id.src_ip.s6_addr, record->id.dst_ip.s6_addr)) {
            // unlike ipv4, we'd always need to read the IPv6 data into a
            // buffer for comparison - so instead we just mark the record to
            // be ignored from now on, to prevent the recorf from being
            // created and deleted everytime this codepath is hit -
            // instead, it will be cleaned up when the socket dies
            record->ignore = 1;
            return 0;
        }
    }

    record->id.src_port = skb->local_port;
    record->id.dst_port = bpf_ntohl(skb->remote_port);
    record->id.transport_protocol = skb->protocol;
    record->id.if_index = skb->ifindex;

    const u64 current_time = bpf_ktime_get_ns();

    record->metrics.start_mono_time_ns = current_time;
    record->metrics.end_mono_time_ns = current_time;

    // fallback for lost or already started connections and UDP
    record->metrics.iface_direction = record->id.src_port > record->id.dst_port ? EGRESS : INGRESS;

    record->initialized = 1;

    return 1;
}

static __always_inline void update_flow(struct __sk_buff *skb) {
    if (skb->family != AF_INET && skb->family != AF_INET6) {
        return;
    }

    if (skb->family == AF_INET && skb->local_ip4 == skb->remote_ip4) {
        return;
    }

    flow_record *record = get_sk_storage(skb->sk);

    if (!record) {
        bpf_printk("sock_egress failed");
        return;
    }

    update_flows_psec();

    if (record->ignore) {
        return;
    }

    // this happens when we haven't seen the flow in obi_sock_ops, i.e. the
    // flow had already begun before obi_sock_ops was loaded
    if (!record->initialized) {
        init_flow_skb(skb, record);
    }

    record->metrics.packets++;
    record->metrics.bytes += skb->len;
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

SEC("sockops")
int obi_sock_ops(struct bpf_sock_ops *skops) {
    switch (skops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        init_flow(skops, EGRESS);
        break;
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        init_flow(skops, INGRESS);
        break;
    }

    return 0;
}
SEC("cgroup_skb/egress")
int obi_sock_egress(struct __sk_buff *skb) {
    update_flow(skb);
    return 1;
}

SEC("cgroup_skb/ingress")
int obi_sock_ingress(struct __sk_buff *skb) {
    update_flow(skb);
    return 1;
}

SEC("cgroup/sock_release")
int obi_sock_release(struct bpf_sock *sock) {
    flow_record *record = bpf_sk_storage_get(&sk_storage_map, sock, 0, 0);

    if (record && !record->ignore) {
        const u64 current_time = bpf_ktime_get_ns();
        record->metrics.end_mono_time_ns = current_time;

        bpf_ringbuf_output(&direct_flows, record, sizeof(*record), get_rb_flags());
    }

    return 1;
}

// Force emitting structs into the ELF for automatic creation of Golang struct
const flow_metrics *unused_flow_metrics __attribute__((unused));
const flow_id *unused_flow_id __attribute__((unused));
const flow_record *unused_flow_record __attribute__((unused));

char _license[] SEC("license") = "GPL";
