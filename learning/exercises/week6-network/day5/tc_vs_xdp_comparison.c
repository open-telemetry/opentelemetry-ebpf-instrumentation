// Week 6 - Day 5: TC vs XDP vs Socket Filter 对比
/*
=== 数据包在内核中的处理顺序 ===

  网卡硬件
    │
    ▼
  [XDP] ← 最早! 可以 DROP/PASS/TX/REDIRECT
    │
    ▼
  内核网络栈 (sk_buff 创建)
    │
    ▼
  [TC ingress] ← 有完整的 sk_buff
    │
    ▼
  路由决策
    │
    ▼
  [TC egress] ← 出站流量
    │
    ▼
  网卡发送

  同时，Socket 层:
  应用 → Socket → [Socket Filter / sk_msg] → TCP/UDP → IP → ...

=== OBI 中的使用 ===

XDP:
  文件: bpf/rdns/rdns_xdp.c
  用途: DNS 反向解析 (需要最快速度，在栈之前处理)

TC:
  文件: bpf/netolly/flows.c
  用途: 网络流量统计 (需要 sk_buff 的完整信息)

Socket Filter:
  文件: bpf/generictracer/k_tracer.c (SEC("socket/http_filter"))
  用途: HTTP 协议检测 (在 Socket 层看到应用数据)

=== 选择指南 ===

用 XDP 当: 需要最高性能、简单包过滤、DDoS 防护
用 TC 当:  需要流量统计、包修改、需要 sk_buff 元数据
用 Socket Filter 当: 需要看到应用层数据、按 Socket 过滤
用 kprobe 当: 需要追踪内核网络函数的调用 (更灵活但更慢)
*/
