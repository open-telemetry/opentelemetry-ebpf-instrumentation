// Week 4 - Day 6: 文件 IO 延迟追踪 (类似 biolatency)
// 编译: clang -O2 -target bpf -c bio_latency.bpf.c -o bio_latency.bpf.o
// OBI 参考: 同样的 kprobe+kretprobe+时间戳 模式

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// 记录 vfs_read 入口时的信息
struct read_args {
    u64 start_ns;
};

// 用于传递 kprobe 入口到 kretprobe 出口的数据
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);                  // tid
    __type(value, struct read_args);
} active_reads SEC(".maps");

// 延迟直方图: 按 log2 分桶
// key = log2(latency_us), value = count
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u32);       // bucket (log2)
    __type(value, u64);     // count
} latency_hist SEC(".maps");

// 简单的 log2 实现
static __always_inline u32 log2l(u64 v) {
    u32 r = 0;
    while (v > 1) {
        v >>= 1;
        r++;
    }
    return r;
}

// kprobe: vfs_read 入口 — 记录开始时间
SEC("kprobe/vfs_read")
int trace_read_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    struct read_args args = {};
    args.start_ns = bpf_ktime_get_ns();

    bpf_map_update_elem(&active_reads, &id, &args, BPF_ANY);
    return 0;
}

// kretprobe: vfs_read 返回 — 计算延迟并记录直方图
SEC("kretprobe/vfs_read")
int trace_read_exit(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    struct read_args *args = bpf_map_lookup_elem(&active_reads, &id);
    if (!args) return 0;

    // 计算延迟 (微秒)
    u64 duration_us = (bpf_ktime_get_ns() - args->start_ns) / 1000;

    // 放入直方图
    u32 bucket = log2l(duration_us);
    u64 *count = bpf_map_lookup_elem(&latency_hist, &bucket);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        u64 init = 1;
        bpf_map_update_elem(&latency_hist, &bucket, &init, BPF_ANY);
    }

    // 清理
    bpf_map_delete_elem(&active_reads, &id);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/*
=== 对比 bpftrace 的 biolatency ===

bpftrace 版本 (明天 Day 7):
  kprobe:vfs_read { @start[tid] = nsecs; }
  kretprobe:vfs_read /@start[tid]/ {
      @usecs = hist((nsecs - @start[tid]) / 1000);
      delete(@start[tid]);
  }

C 版本 vs bpftrace:
  - C: 更灵活，可以自定义直方图桶、添加过滤条件
  - bpftrace: 更简洁，3 行搞定，适合快速诊断
  - OBI: 用 C 版本的灵活性，但添加了协议检测、PID 过滤、OTEL 导出等
*/
