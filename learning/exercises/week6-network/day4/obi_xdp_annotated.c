// Week 6 - Day 4: 精读 OBI 的 XDP 程序 (bpf/rdns/rdns_xdp.c)
/*
=== XDP 基础 ===

XDP (eXpress Data Path) 在网卡驱动层处理数据包:
  - 最快的 eBPF 网络处理点
  - 在内核网络栈之前执行
  - 可以丢包、重定向、修改数据包

返回值:
  XDP_PASS    → 正常传递给内核网络栈
  XDP_DROP    → 丢弃数据包 (最快的防火墙!)
  XDP_TX      → 从同一网卡发回
  XDP_REDIRECT → 重定向到其他网卡/CPU

OBI 的 rdns_xdp.c 用 XDP 做反向 DNS:
  → 在网卡层捕获 DNS 响应
  → 解析 DNS 应答，提取 IP → 域名 映射
  → 存入 Map 供其他组件使用

=== XDP vs TC 对比 ===

             XDP                    TC
位置:     网卡驱动层            网络栈 TC 层
速度:     最快                  快
功能:     有限 (无 skb)         完整 (有 skb)
修改包:   可以                  可以
sk_buff:  不可用                可用
适用:     高性能过滤/转发       流量统计/修改

=== 练习 ===
阅读 bpf/rdns/rdns_xdp.c，理解:
  1. DNS 响应数据包的解析方式
  2. 为什么用 XDP 而不是 TC 来做 DNS 解析
*/
