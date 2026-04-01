// Week 2 - Day 5: 第一个 eBPF Hello World — 追踪文件打开
// 主题: 用 kprobe 挂载到 sys_openat，打印进程名和文件名
//
// 编译: clang -O2 -target bpf -c hello_openat.bpf.c -o hello_openat.bpf.o
// 加载: 明天 Day 6 用 Go 程序加载
//
// 这个程序做什么:
//   每当任何进程调用 open/openat 打开文件时，记录:
//   - 进程名 (comm)
//   - 进程 PID
//   - 打印到内核 trace_pipe (/sys/kernel/debug/tracing/trace_pipe)

// === 注意: 这是 eBPF 内核态程序，不能直接用 gcc 编译 ===
// 需要 clang -target bpf 编译

//go:build ignore

#include "vmlinux.h"           // 内核类型定义 (需要 bpftool btf dump 生成)
#include <bpf/bpf_helpers.h>   // eBPF helper 函数

// SEC() 宏: 指定这个函数挂载到 kprobe/sys_openat
// 当内核执行 sys_openat 系统调用时，这个函数会被触发
SEC("kprobe/sys_openat")
int hello_openat(struct pt_regs *ctx) {
    // 获取当前进程的 PID 和 TID
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;  // 高 32 位是 PID

    // 获取进程名 (最多 16 字节)
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // 打印到 trace_pipe (最基本的 eBPF 输出方式)
    // 查看输出: sudo cat /sys/kernel/debug/tracing/trace_pipe
    bpf_printk("Hello eBPF! pid=%d comm=%s", pid, comm);

    return 0;
}

// 每个 eBPF 程序必须声明许可证
char LICENSE[] SEC("license") = "Dual MIT/GPL";

/*
=== 运行方式 ===

方法 1 (bpftrace 快速验证):
  sudo bpftrace -e 'kprobe:sys_openat { printf("pid=%d comm=%s\n", pid, comm); }'

方法 2 (编译+加载，明天 Day 6 会做):
  1. clang -O2 -target bpf -c hello_openat.bpf.c -o hello_openat.bpf.o
  2. 用 Go 程序加载 (见 day6/main.go)

方法 3 (bpftool 手动加载):
  sudo bpftool prog load hello_openat.bpf.o /sys/fs/bpf/hello
  sudo bpftool prog attach pinned /sys/fs/bpf/hello kprobe sys_openat
  sudo cat /sys/kernel/debug/tracing/trace_pipe

=== 对比 OBI 的实现 ===

OBI k_tracer.c 中的 kprobe 结构:
  SEC("kprobe/security_socket_accept")
  int BPF_KPROBE(obi_kprobe_security_socket_accept, struct socket *sock, ...) {
      const u64 id = bpf_get_current_pid_tgid();
      if (!valid_pid(id)) { return 0; }  // OBI 多了 PID 过滤
      // ... 业务逻辑
  }

区别:
  1. OBI 用 BPF_KPROBE 宏 (自动处理 ctx 参数)，我们直接用 struct pt_regs *ctx
  2. OBI 有 valid_pid 过滤 (只追踪目标进程)，我们追踪所有进程
  3. OBI 用 RingBuffer 传递数据，我们用 bpf_printk (仅用于调试)
*/
