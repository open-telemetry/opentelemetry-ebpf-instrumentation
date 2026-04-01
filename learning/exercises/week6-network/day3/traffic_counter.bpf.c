// Week 6 - Day 3: TC 流量计数器 — 统计每个目标 IP 的流量
//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define TC_ACT_OK 0

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);       // 目标 IPv4 地址
    __type(value, u64);     // 累计字节数
} traffic_bytes SEC(".maps");

SEC("tc_ingress")
int count_traffic(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // 步骤 1: 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;  // 只处理 IPv4

    // 步骤 2: 解析 IP 头
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return TC_ACT_OK;

    // 步骤 3: 更新目标 IP 的流量计数
    u32 dst_ip = ip->daddr;
    u64 bytes = skb->len;

    u64 *count = bpf_map_lookup_elem(&traffic_bytes, &dst_ip);
    if (count) {
        __sync_fetch_and_add(count, bytes);
    } else {
        bpf_map_update_elem(&traffic_bytes, &dst_ip, &bytes, BPF_ANY);
    }

    return TC_ACT_OK;  // 不修改数据包，只统计
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
