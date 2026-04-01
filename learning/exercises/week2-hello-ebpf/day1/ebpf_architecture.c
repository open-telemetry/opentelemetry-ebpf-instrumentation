// Week 2 - Day 1: eBPF 架构总览
// 这是一个概念学习日，没有可运行的代码
// 阅读任务 + 笔记模板

/*
=== 今日学习任务 ===

1. 阅读 https://ebpf.io/what-is-ebpf/ 完整页面
2. 理解以下架构图并在下方填写你的理解

=== eBPF 架构图 ===

  用户态 (User Space)
  ┌─────────────────────────────────────────────┐
  │  Go/Python/C 用户态程序                      │
  │    │                                        │
  │    ├── 编译 eBPF C 代码 (clang → .o)        │
  │    ├── 通过 bpf() 系统调用加载到内核          │
  │    ├── 从 Map 中读取数据                     │
  │    └── 从 RingBuffer 接收事件                │
  └──────────────────┬──────────────────────────┘
                     │ bpf() 系统调用
  ═══════════════════╪═══════════════════════════
                     │
  内核态 (Kernel Space)
  ┌──────────────────┴──────────────────────────┐
  │                                             │
  │  1. Verifier (验证器)                       │
  │     → 检查程序安全性 (无死循环、无越界等)     │
  │                                             │
  │  2. JIT Compiler (即时编译器)                │
  │     → 把 eBPF 字节码编译为本机机器码          │
  │                                             │
  │  3. eBPF 程序挂载到钩子 (hooks)              │
  │     ├── kprobe    → 内核函数入口/出口         │
  │     ├── uprobe    → 用户态函数入口/出口       │
  │     ├── tracepoint → 内核预定义追踪点         │
  │     ├── XDP       → 网卡驱动层               │
  │     ├── TC        → 流量控制层               │
  │     └── socket    → Socket 操作              │
  │                                             │
  │  4. eBPF Maps (数据存储)                    │
  │     → 内核态程序和用户态程序共享的数据结构     │
  │                                             │
  │  5. Helper Functions (辅助函数)              │
  │     → eBPF 程序可调用的内核 API               │
  └─────────────────────────────────────────────┘

=== 在 OBI 项目中的对应 ===

  OBI Go 程序 (pkg/, cmd/)
    │
    ├── 用 cilium/ebpf 加载 eBPF 程序
    ├── 从 RingBuffer 读取追踪事件
    └── 导出到 OTEL/Prometheus
         │
  ═══════╪═══════════════════════════
         │
  OBI eBPF 程序 (bpf/)
    ├── bpf/generictracer/k_tracer.c  → kprobe 挂载
    ├── bpf/gotracer/go_nethttp.c     → uprobe 挂载
    ├── bpf/netolly/flows.c           → TC 挂载
    ├── bpf/rdns/rdns_xdp.c           → XDP 挂载
    ├── bpf/maps/                     → Map 定义
    └── bpf/common/ringbuf.h          → RingBuffer 定义

=== 请在下方记录你的理解 ===

Q1: eBPF 程序为什么不能有死循环?
A1: (你的回答)

Q2: Verifier 主要检查哪些安全问题?
A2: (你的回答)

Q3: 为什么 eBPF 程序的栈大小限制为 512 字节?
A3: (你的回答)

Q4: JIT 编译的好处是什么?
A4: (你的回答)

*/
