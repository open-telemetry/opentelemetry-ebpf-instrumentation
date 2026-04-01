// Week 5 - Day 6: 自定义 uprobe 追踪你的 Go 函数
// 这是一个模板，替换 TARGET_FUNC 为你要追踪的函数
//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

struct go_func_event {
    u32 pid;
    u64 timestamp_ns;
    char comm[16];
    // 根据你的函数参数自定义字段
};

// 替换 TARGET_FUNC 为你的 Go 函数名
// 例如: SEC("uprobe/main.handleRequest")
SEC("uprobe/TARGET_FUNC")
int trace_go_func(struct pt_regs *ctx) {
    struct go_func_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Go 1.17+ 寄存器传参: 第一个参数在 RAX
    // u64 arg1 = PT_REGS_PARM1(ctx);  // 注意: Go 的 ABI 不同!

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
/*
使用步骤:
  1. 找到 Go 函数符号: go tool nm your_binary | grep handleRequest
  2. 替换上面的 TARGET_FUNC
  3. 编译: clang -O2 -target bpf -c go_func_tracer.bpf.c -o go_func_tracer.bpf.o
  4. 加载并指定目标二进制: 用 Go cilium/ebpf 的 link.Uprobe()
*/
