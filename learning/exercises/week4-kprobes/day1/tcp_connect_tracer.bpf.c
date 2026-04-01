// Week 4 - Day 1: kprobe 追踪 tcp_connect — 监控出站连接
// 编译: clang -O2 -target bpf -c tcp_connect_tracer.bpf.c -o tcp_connect_tracer.bpf.o
//
// OBI 参考: bpf/generictracer/k_tracer.c 的 SEC("kprobe/tcp_connect")

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// 事件结构体: 每次 tcp_connect 触发时记录
struct event {
    u32 pid;
    u32 daddr;      // 目标 IPv4 地址
    u16 dport;      // 目标端口
    char comm[16];  // 进程名
};

// RingBuffer 用于将事件发送到用户态
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

// kprobe 挂载到 tcp_connect 内核函数
// tcp_connect 在 TCP 三次握手发起时调用
// 参数 sk 是 struct sock 指针，包含连接信息
SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    // 从寄存器中获取第一个参数 (struct sock *)
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    // 获取当前进程信息
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    // 预留 RingBuffer 空间
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    // 填充事件数据
    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 从 sock 结构体读取目标地址和端口
    // BPF_CORE_READ 是 CO-RE 安全的读取方式
    e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    // 注意: dport 是网络字节序，需要 bpf_ntohs() 转换
    e->dport = __builtin_bswap16(e->dport);

    // 提交事件到 RingBuffer
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/*
=== 对比 OBI 的 tcp_connect kprobe ===

OBI k_tracer.c:
  SEC("kprobe/tcp_connect")
  int BPF_KPROBE(obi_kprobe_tcp_connect, struct sock *sk) {
      // 1. PID 过滤 (valid_pid)    ← 我们没有
      // 2. 读取连接信息              ← 我们简化了
      // 3. 存入 Map 等待后续处理     ← 我们直接发到 RingBuffer
  }

关键区别:
  - OBI 用 BPF_KPROBE 宏自动解析参数，我们手动用 PT_REGS_PARM1
  - OBI 有 PID 过滤，只追踪目标进程
  - OBI 把数据存入 Map，由其他 kprobe 串联处理完整请求
*/
