// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_endian.h>

#include <common/protocol_defs.h>

#include <netolly/flow.h>

#define DISCARD 1
#define SUBMIT 0

// according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
#define INGRESS 0
#define EGRESS 1
#define UNKNOWN 255

// Flags according to RFC 9293 & https://www.iana.org/assignments/ipfix/ipfix.xhtml
#define FIN_FLAG 0x01
#define SYN_FLAG 0x02
#define RST_FLAG 0x04
#define PSH_FLAG 0x08
#define ACK_FLAG 0x10
#define URG_FLAG 0x20
#define ECE_FLAG 0x40
#define CWR_FLAG 0x80
// Custom flags exported
#define SYN_ACK_FLAG 0x100
#define FIN_ACK_FLAG 0x200
#define RST_ACK_FLAG 0x400

// In conn_initiator_key, which sorted ip:port initiated the connection
#define INITIATOR_LOW 1
#define INITIATOR_HIGH 2

// In flow_metrics, who initiated the connection
#define INITIATOR_SRC 1
#define INITIATOR_DST 2

#define INITIATOR_UNKNOWN 0

// Common Ringbuffer as a conduit for ingress/egress flows to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} direct_flows SEC(".maps");

// Key: the flow identifier. Value: the flow metrics for that identifier.
// The userspace will aggregate them into a single flow.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, flow_id);
    __type(value, flow_metrics);
    __uint(max_entries, 262144);
} aggregated_flows SEC(".maps");

// Key: the flow identifier. Value: the flow direction.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, flow_id);
    __type(value, u8);
} flow_directions SEC(".maps");

// To know who initiated each connection, we store the src/dst ip:ports but ordered
// by numeric value of the IP (and port as secondary criteria), so the key is consistent
// for either client and server flows.
typedef struct conn_initiator_key_t {
    struct in6_addr low_ip;
    struct in6_addr high_ip;
    u16 low_ip_port;
    u16 high_ip_port;
} __attribute__((packed)) conn_initiator_key;

// Key: the flow identifier.
// Value: the connection initiator index (INITIATOR_LOW, INITIATOR_HIGH).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, conn_initiator_key);
    __type(value, u8);
} conn_initiators SEC(".maps");

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

const u8 ip4in6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

// Constant definitions, to be overridden by the invoker
volatile const u32 sampling = 0;

static u64 last_submitted = 0;

volatile const u8 k_protocol_wl_empty;
volatile const u8 k_protocol_bl_empty;
volatile const u32 k_max_rb_size;
volatile const u64 k_rb_flush_period;
volatile const u64 k_max_flow_duration;

// we can safely assume that the passed address is IPv6 as long as we encode IPv4
// as IPv6 during the creation of the flow_id.
static inline s32 compare_ipv6(const flow_id *fid) {
    for (int i = 0; i < 4; i++) {
        s32 diff = fid->src_ip.in6_u.u6_addr32[i] - fid->dst_ip.in6_u.u6_addr32[i];
        if (diff != 0) {
            return diff;
        }
    }
    return 0;
}

// creates a key that is consistent for both requests and responses, by
// ordering endpoints (ip:port) numerically into a lower and a higher endpoint.
// returns true if the lower address corresponds to the source address
// (false if the lower address corresponds to the destination address)
static inline u8 fill_conn_initiator_key(const flow_id *id, conn_initiator_key *key) {
    const s32 cmp = compare_ipv6(id);

    if (cmp < 0) {
        __builtin_memcpy(&key->low_ip, &id->src_ip, sizeof(struct in6_addr));
        key->low_ip_port = id->src_port;
        __builtin_memcpy(&key->high_ip, &id->dst_ip, sizeof(struct in6_addr));
        key->high_ip_port = id->dst_port;
        return 1;
    }
    // if the IPs are equal (cmp == 0) we will use the ports as secondary order criteria
    __builtin_memcpy(&key->high_ip, &id->src_ip, sizeof(struct in6_addr));
    __builtin_memcpy(&key->low_ip, &id->dst_ip, sizeof(struct in6_addr));
    if (cmp > 0 || id->src_port > id->dst_port) {
        key->high_ip_port = id->src_port;
        key->low_ip_port = id->dst_port;
        return 0;
    }
    key->low_ip_port = id->src_port;
    key->high_ip_port = id->dst_port;
    return 1;
}

// returns INITIATOR_SRC or INITIATOR_DST, but might return INITIATOR_UNKNOWN
// if the connection initiator couldn't be found. The user-space Beyla pipeline
// will handle this last case heuristically
static inline u8 get_connection_initiator(const flow_id *id, u16 flags) {
    conn_initiator_key initiator_key;
    // from the initiator_key with sorted ip/ports, know the index of the
    // endpoint that that initiated the connection, which might be the low or the high address
    u8 low_is_src = fill_conn_initiator_key(id, &initiator_key);
    u8 *initiator = (u8 *)bpf_map_lookup_elem(&conn_initiators, &initiator_key);
    u8 initiator_index = INITIATOR_UNKNOWN;
    if (initiator == NULL) {
        // SYN and ACK is sent from the server to the client
        // The initiator is the destination address
        if ((flags & (SYN_FLAG | ACK_FLAG)) == (SYN_FLAG | ACK_FLAG)) {
            if (low_is_src) {
                initiator_index = INITIATOR_HIGH;
            } else {
                initiator_index = INITIATOR_LOW;
            }
        }
        // SYN is sent from the client to the server.
        // The initiator is the source address
        else if (flags & SYN_FLAG) {
            if (low_is_src) {
                initiator_index = INITIATOR_LOW;
            } else {
                initiator_index = INITIATOR_HIGH;
            }
        }

        if (initiator_index != INITIATOR_UNKNOWN) {
            bpf_map_update_elem(&conn_initiators, &initiator_key, &initiator_index, BPF_NOEXIST);
        }
    } else {
        initiator_index = *initiator;
    }

    // when flow receives FIN or RST, clean flow_directions
    if (flags & FIN_FLAG || flags & RST_FLAG || flags & FIN_ACK_FLAG || flags & RST_ACK_FLAG) {
        bpf_map_delete_elem(&conn_initiators, &initiator_key);
    }

    u8 flow_initiator = INITIATOR_UNKNOWN;
    // at this point, we should know the index of the endpoint that initiated the connection.
    // Then we accordingly set whether the initiator is the source or the destination address.
    // If not, we forward the unknown status and the userspace will take
    // heuristic actions to guess who is
    switch (initiator_index) {
    case INITIATOR_LOW:
        if (low_is_src) {
            flow_initiator = INITIATOR_SRC;
        } else {
            flow_initiator = INITIATOR_DST;
        }
        break;
    case INITIATOR_HIGH:
        if (low_is_src) {
            flow_initiator = INITIATOR_DST;
        } else {
            flow_initiator = INITIATOR_SRC;
        }
        break;
    default:
        break;
    }

    return flow_initiator;
}

static __always_inline u8 get_flow_direction(const flow_id *id, u64 flags) {
    const u8 *direction = (u8 *)bpf_map_lookup_elem(&flow_directions, id);

    if (direction) {
        return *direction;
    }

    u8 ret = UNKNOWN;

    // Calculate direction based on first flag received
    // SYN and ACK mean someone else initiated the connection and this is the INGRESS direction
    if ((flags & (SYN_FLAG | ACK_FLAG)) == (SYN_FLAG | ACK_FLAG)) {
        ret = INGRESS;
    }
    // SYN only means we initiated the connection and this is the EGRESS direction
    else if ((flags & SYN_FLAG) == SYN_FLAG) {
        ret = EGRESS;
    }

    // save, when direction was calculated based on TCP flag
    if (ret != UNKNOWN) {
        // errors are intentionally omitted
        bpf_map_update_elem(&flow_directions, id, &ret, BPF_NOEXIST);
    }
    // fallback for lost or already started connections and UDP
    else {
        ret = (id->src_port > id->dst_port) ? EGRESS : INGRESS;
    }

    return ret;
}

static __always_inline flow_metrics *get_flow_storage(const flow_id *id, u16 flags) {
    flow_metrics *f = bpf_map_lookup_elem(&aggregated_flows, id);

    if (f) {
        return f;
    }

    flow_metrics init = {};
    init.start_mono_time_ns = bpf_ktime_get_ns();
    init.iface_direction = get_flow_direction(id, flags);
    init.initiator = get_connection_initiator(id, flags);

    bpf_map_update_elem(&aggregated_flows, id, &init, BPF_NOEXIST);

    return bpf_map_lookup_elem(&aggregated_flows, id);
}

static __always_inline u8 must_submit(u64 start_time, u64 current_time, u16 flags) {
    if (flags & (FIN_FLAG | RST_FLAG)) {
        return 1;
    }

    if (current_time < start_time) {
        return 0;
    }

    const u64 delta_ns = current_time - start_time;

    return delta_ns > k_max_flow_duration;
}

static __always_inline u64 get_rb_flags() {
    const u64 current_time = bpf_ktime_get_ns();
    const u64 rb_avail = bpf_ringbuf_query(&direct_flows, BPF_RB_AVAIL_DATA);
    const u64 delta_nsec = current_time - last_submitted;

    //bpf_printk("RB USED: %llu", rb_avail);

    if ((delta_nsec > k_rb_flush_period) || (rb_avail + sizeof(flow_record)) >= k_max_rb_size) {
        last_submitted = current_time;
        return BPF_RB_FORCE_WAKEUP;
    }

    return BPF_RB_NO_WAKEUP;
}

static __always_inline void submit_flow(const flow_id *id, flow_metrics *metrics, u16 flags) {
    // whilst highly unlikely, it is theoretically possible for submit flow to
    // push duplicates - this is mitigated by the call to bpf_map_delete_elem
    // (1) which causes subsequent calls to bpf_map_lookup_elem (2) to fail -
    // the actual aggregated_flows value is ref-counted by the kernel and
    // remains valid until the event is submitted
    if (bpf_map_lookup_elem(&aggregated_flows, id) == NULL) { // (2)
        return;
    }

    bpf_map_delete_elem(&aggregated_flows, id); // (1)

    if (flags & (FIN_FLAG | RST_FLAG | FIN_ACK_FLAG | RST_ACK_FLAG)) {
        bpf_map_delete_elem(&flow_directions, id);
    }

    flow_record *record = bpf_ringbuf_reserve(&direct_flows, sizeof(flow_record), 0);

    if (!record) {
        return;
    }

    record->metrics = *metrics;
    record->metrics.end_mono_time_ns = bpf_ktime_get_ns();
    record->id = *id;

    //bpf_printk("submit %u -> %u (%u)", id->src_port, id->dst_port, id->if_index);
    bpf_ringbuf_submit(record, get_rb_flags());
}

static __always_inline bool read_sk_buff(struct __sk_buff *skb, flow_id *id, u16 *custom_flags) {
    // we read the protocol just like here linux/samples/bpf/parse_ldabs.c
    u16 h_proto;
    bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &h_proto, sizeof(h_proto));
    h_proto = __bpf_htons(h_proto);
    id->eth_protocol = h_proto;
    id->if_index = skb->ifindex;

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
        break;
    }

    id->src_port = 0;
    id->dst_port = 0;
    id->transport_protocol = proto;

    switch (proto) {
    case IPPROTO_TCP: {
        u16 port;
        bpf_skb_load_bytes(skb, hdr_len + offsetof(struct tcphdr, source), &port, sizeof(port));
        id->src_port = __bpf_htons(port);

        bpf_skb_load_bytes(skb, hdr_len + offsetof(struct tcphdr, dest), &port, sizeof(port));
        id->dst_port = __bpf_htons(port);

        u8 doff;
        bpf_skb_load_bytes(
            skb,
            hdr_len + offsetof(struct tcphdr, ack_seq) + 4,
            &doff,
            sizeof(
                doff)); // read the first byte past tcphdr->ack_seq, we can't do offsetof bit fields
        doff &= 0xf0;   // clean-up res1
        doff >>= 4;     // move the upper 4 bits to low
        doff *= 4;      // convert to bytes length

        u8 flags;
        bpf_skb_load_bytes(
            skb,
            hdr_len + offsetof(struct tcphdr, ack_seq) + 4 + 1,
            &flags,
            sizeof(flags)); // read the second byte past tcphdr->doff, again bit fields offsets
        *custom_flags = ((u16)flags & 0x00ff);

        hdr_len += doff;

        if ((skb->len - hdr_len) < 0) { // less than 0 is a packet we can't parse
            return false;
        }

        break;
    }
    case IPPROTO_UDP: {
        u16 port;
        bpf_skb_load_bytes(skb, hdr_len + offsetof(struct udphdr, source), &port, sizeof(port));
        id->src_port = __bpf_htons(port);
        bpf_skb_load_bytes(skb, hdr_len + offsetof(struct udphdr, dest), &port, sizeof(port));
        id->dst_port = __bpf_htons(port);
        break;
    }
    default:
        break;
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

static __always_inline int flow_monitor(struct __sk_buff *skb) {
    // If sampling is defined, will only parse 1 out of "sampling" flows
    if (sampling != 0 && (bpf_get_prandom_u32() % sampling) != 0) {
        return TC_ACT_UNSPEC;
    }

    u16 flags = 0;
    flow_id id = {};

    if (!read_sk_buff(skb, &id, &flags)) {
        return TC_ACT_UNSPEC;
    }

    // ignore traffic that's not egress or ingress
    if (same_ip(id.src_ip.s6_addr, id.dst_ip.s6_addr)) {
        return TC_ACT_UNSPEC;
    }

    if (!is_protocol_allowed(id.transport_protocol)) {
        return TC_ACT_UNSPEC;
    }

    flow_metrics *aggregate_flow = get_flow_storage(&id, flags);

    if (!aggregate_flow) {
        return TC_ACT_UNSPEC;
    }

    const u64 current_time = bpf_ktime_get_ns();

    __sync_fetch_and_add(&aggregate_flow->bytes, skb->len);
    __sync_fetch_and_add(&aggregate_flow->packets, 1);

    if (must_submit(aggregate_flow->start_mono_time_ns, current_time, flags)) {
        submit_flow(&id, aggregate_flow, flags);
    }

    return TC_ACT_UNSPEC;
}
