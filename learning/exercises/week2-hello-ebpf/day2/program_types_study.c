// Week 2 - Day 2: Program Types — 对照 OBI 中的 SEC() 宏
// 这是一个代码阅读练习日
// 任务: 在 OBI 项目中找到所有 SEC() 类型，理解每种的用途

/*
=== 今日学习任务 ===

运行以下命令查看 OBI 中所有的 eBPF 程序类型:
  grep -r 'SEC("' bpf/ --include="*.c" | grep -oP 'SEC\("[^"]*"' | sort -u

=== OBI 中使用的 Program Types ===

填写每种类型的说明:

1. kprobe  SEC("kprobe/tcp_sendmsg")
   挂载点: 内核函数入口
   触发时机: (你的理解)
   OBI 用途: (你的理解)

2. kretprobe  SEC("kretprobe/sys_connect")
   挂载点: 内核函数返回
   触发时机: (你的理解)
   OBI 用途: (你的理解)

3. uprobe  SEC("uprobe/roundTrip")
   挂载点: 用户态函数入口
   触发时机: (你的理解)
   OBI 用途: (你的理解)

4. uretprobe  SEC("uretprobe/libssl.so:SSL_read")
   挂载点: 用户态函数返回
   触发时机: (你的理解)
   OBI 用途: (你的理解)

5. tc_ingress / tc_egress  SEC("tc_ingress")
   挂载点: 网络流量控制层
   触发时机: (你的理解)
   OBI 用途: (你的理解)

6. xdp  SEC("xdp")
   挂载点: 网卡驱动层
   触发时机: (你的理解)
   OBI 用途: (你的理解)

7. socket/filter  SEC("socket/http_filter")
   挂载点: Socket 层
   触发时机: (你的理解)
   OBI 用途: (你的理解)

8. iter/tcp  SEC("iter/tcp")
   挂载点: BPF 迭代器
   触发时机: (你的理解)
   OBI 用途: (你的理解)

9. sk_msg  SEC("sk_msg")
   挂载点: Socket 消息层
   触发时机: (你的理解)
   OBI 用途: (你的理解)

10. sockops  SEC("sockops")
    挂载点: Socket 操作回调
    触发时机: (你的理解)
    OBI 用途: (你的理解)

=== 统计 ===

OBI 中各类型程序数量 (填写):
  kprobe:     ~___ 个
  kretprobe:  ~___ 个
  uprobe:     ~___ 个 (最多!)
  uretprobe:  ~___ 个
  tc:         ~___ 个
  xdp:        ~___ 个
  其他:       ~___ 个

*/
