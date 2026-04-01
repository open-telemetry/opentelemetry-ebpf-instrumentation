// Week 6 - Day 1: 深入研读 OBI 的 bpf/netolly/flows.c
/*
=== flows.c 架构 ===

flows.c 是 OBI 的网络流量追踪 TC 程序。

入口点:
  SEC("tc_ingress") → 处理入站流量
  SEC("tc_egress")  → 处理出站流量

数据流:
  网卡 → TC ingress → flows.c → 聚合到 Map / 发到 RingBuffer → 用户态

核心函数调用链:
  tc_ingress_func()
    → parse_eth_header()        解析以太网头
    → fill_iphdr/fill_ip6hdr()  解析 IP 头，提取五元组
    → flow_monitor()            更新流量统计 Map

Map 使用:
  aggregated_flows (LRU_PERCPU_HASH) — 按五元组聚合流量统计
  direct_flows (RINGBUF)             — Map 满时直接发到用户态
  flow_directions (LRU_HASH)         — 记录流方向 (ingress/egress)
  conn_initiators (LRU_HASH)         — 记录连接发起方

=== 练习 ===
完整阅读 bpf/netolly/flows.c，标注:
  1. 每个 SEC() 入口点
  2. 数据包解析流程
  3. Map 操作逻辑
  4. 返回值 (TC_ACT_OK 等)
*/
