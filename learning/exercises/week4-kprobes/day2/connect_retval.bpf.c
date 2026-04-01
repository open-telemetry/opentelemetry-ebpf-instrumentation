// Week 4 - Day 2: kretprobe — 获取 sys_connect 的返回值
// 主题: 用 kprobe + kretprobe 组合，追踪连接成功/失败
//
// OBI 参考: k_tracer.c 的 kprobe/sys_connect + kretprobe/sys_connect

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// 在 kprobe 入口存储连接参数，kretprobe 时取出
struct connect_args {
    u64 start_ns;   // 连接开始时间
    u32 pid;
    char comm[16];
};

// HashMap: 用 tid 作为 key 关联 entry 和 exit
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);                // tid
    __type(value, struct connect_args);
} active_connects SEC(".maps");

// kprobe 入口: 记录连接开始时间
SEC("kprobe/sys_connect")
int trace_connect_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    struct connect_args args = {};
    args.start_ns = bpf_ktime_get_ns();
    args.pid = id >> 32;
    bpf_get_current_comm(&args.comm, sizeof(args.comm));

    // 以 tid 为 key 存入 Map
    bpf_map_update_elem(&active_connects, &id, &args, BPF_ANY);
    return 0;
}

// kretprobe 出口: 获取返回值，计算延迟
SEC("kretprobe/sys_connect")
int trace_connect_exit(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    // 从 Map 中取出入口时保存的数据
    struct connect_args *args = bpf_map_lookup_elem(&active_connects, &id);
    if (!args) return 0;  // 没找到，说明入口没有记录

    // 获取返回值: 0 = 成功, 负数 = 错误码
    int ret = PT_REGS_RC(ctx);

    // 计算连接耗时
    u64 duration_ns = bpf_ktime_get_ns() - args->start_ns;

    bpf_printk("connect: pid=%d comm=%s ret=%d latency=%llu us",
               args->pid, args->comm, ret, duration_ns / 1000);

    // 清理 Map
    bpf_map_delete_elem(&active_connects, &id);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/*
=== kprobe + kretprobe 配对模式 ===

这是 eBPF 中最常见的模式:
  1. kprobe 入口: 记录参数和开始时间到 HashMap (key=tid)
  2. kretprobe 出口: 从 HashMap 取出数据，获取返回值，计算延迟
  3. 清理 HashMap 条目

OBI 中的对应:
  kprobe/sys_connect → 记录连接参数
  kretprobe/sys_connect → 获取结果，建立连接映射

关键 API:
  bpf_ktime_get_ns()  — 纳秒级时间戳
  PT_REGS_RC(ctx)     — 获取函数返回值
  bpf_map_delete_elem — 清理 Map 避免内存泄漏
*/
