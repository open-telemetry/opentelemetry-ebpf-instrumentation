// Week 6 - Day 2: 五元组提取 — 数据包解析步骤详解
/*
=== 数据包层次结构 ===

TC 程序收到的数据 (__sk_buff):

  data                                               data_end
  │                                                        │
  ▼                                                        ▼
  ┌──────────┬──────────┬──────────┬──────────────────────┐
  │Ethernet  │ IP Header│TCP/UDP   │     Payload          │
  │ 14 bytes │ 20 bytes │ Header   │     (HTTP/gRPC...)   │
  └──────────┴──────────┴──────────┴──────────────────────┘

五元组 = (源IP, 目标IP, 源端口, 目标端口, 协议)

=== 解析步骤 (来自 OBI flows.c) ===

步骤 1: 定位以太网头
  struct ethhdr *eth = (void *)(long)skb->data;
  if ((void *)eth + sizeof(*eth) > data_end) return DISCARD;  // 边界检查!
  u16 eth_type = eth->h_proto;  // 0x0800=IPv4, 0x86DD=IPv6

步骤 2: 跳过以太网头，定位 IP 头
  struct iphdr *ip = (void *)eth + sizeof(*eth);
  if ((void *)ip + sizeof(*ip) > data_end) return DISCARD;  // 边界检查!
  // 提取: ip->saddr, ip->daddr, ip->protocol

步骤 3: 跳过 IP 头，定位传输层头
  // TCP:
  struct tcphdr *tcp = (void *)ip + sizeof(*ip);
  if ((void *)tcp + sizeof(*tcp) <= data_end) {
      src_port = ntohs(tcp->source);
      dst_port = ntohs(tcp->dest);
  }

=== 关键: 每次指针移动都必须做边界检查 ===
  这不是可选的！没有边界检查，verifier 会拒绝程序。
*/
