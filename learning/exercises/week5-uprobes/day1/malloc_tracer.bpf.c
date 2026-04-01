// Week 5 - Day 1: uprobe 追踪 malloc — 监控内存分配
// 编译: clang -O2 -target bpf -c malloc_tracer.bpf.c -o malloc_tracer.bpf.o
// OBI 参考: bpf/generictracer/libssl.c (同样的 uprobe 模式)
//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct alloc_event {
    u32 pid;
    u64 size;       // malloc 请求的大小
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

// uprobe 挂载到 libc 的 malloc 函数
// 第一个参数就是分配大小
SEC("uprobe/libc.so.6:malloc")
int trace_malloc(struct pt_regs *ctx) {
    u64 size = PT_REGS_PARM1(ctx);

    // 只关注大分配 (> 1MB)
    if (size < 1024 * 1024) return 0;

    struct alloc_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->size = size;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
/*
对比 OBI 的 uprobe 模式:
  OBI libssl.c: SEC("uprobe/libssl.so:SSL_read")
  我们:         SEC("uprobe/libc.so.6:malloc")
  模式相同: 指定 .so 文件和函数名，从 PT_REGS 读取参数
*/
