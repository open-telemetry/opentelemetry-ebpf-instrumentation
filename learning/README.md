# eBPF 学习计划 — 基于 OBI (OpenTelemetry eBPF Instrumentation) 项目

> 开始日期: 2026-03-31
> 预计周期: 8 周 (每天 30 分钟)
> 学习者背景: Linux 内核有基础概念 | C 语言零基础 | Go+Python 熟练 | 用过 bpftrace/BCC 工具
> 学习目标: 系统性能分析 (综合场景: K8s/容器、微服务延迟、系统级)

## 文件结构

```
learning/
├── README.md                         ← 本文件: 学习计划总览
├── PROGRESS.md                       ← 学习进度追踪 (每日打勾)
├── exercises/                        ← 练习代码 (按周/天划分)
│   ├── week1-c-basics/               ← 第1周: C语言速成
│   │   ├── day1/types_and_control.c  ← 基本类型与控制流
│   │   ├── day2/pointers.c           ← 指针与地址
│   │   ├── day3/structs.c            ← 结构体与联合体
│   │   ├── day4/memory_ops.c         ← 内存操作
│   │   ├── day5/macros.c             ← 预处理器
│   │   ├── day6/bitops.c             ← 枚举与位运算
│   │   └── day7/flows_annotated.c    ← 综合: OBI flows.c 注释版
│   ├── week2-hello-ebpf/             ← 第2周: eBPF Hello World
│   │   ├── day1/ ~ day7/             ← 架构→Program Types→Verifier→环境→C→Go→调试
│   ├── week3-maps/                   ← 第3周: eBPF Maps
│   │   ├── day1/ ~ day7/             ← HashMap→RingBuf→OBI Maps→深入→PerCPU→Go→调试
│   ├── week4-kprobes/                ← 第4周: Kprobes
│   │   ├── day1/ ~ day7/             ← tcp_connect→retval→OBI accept→send/recv→PID→IO→bpftrace
│   ├── week5-uprobes/                ← 第5周: Uprobes
│   │   ├── day1/ ~ day7/             ← malloc→SSL→Go HTTP→调用约定→偏移量→自定义→验证
│   ├── week6-network/                ← 第6周: 网络追踪
│   │   ├── day1/ ~ day7/             ← flows.c→五元组→TC→XDP→对比→Socket→连接追踪
│   ├── week7-http-tracer/            ← 第7周: 综合实战
│   │   ├── day1/ ~ day7/             ← 设计→内核态→HTTP检测→Go加载→延迟→Prometheus→测试
│   └── week8-obi-deep-dive/          ← 第8周: 深入OBI
│       ├── day1/ ~ day7/             ← Pipeline→Go加载→进程发现→Context→构建→追踪→贡献
└── notes/                            ← 学习笔记
    ├── c-for-ebpf.md                 ← C 语言知识总结
    └── troubleshooting.md            ← 问题记录
```

---

## 背景分析

| 维度 | 现状 | 策略 |
|------|------|------|
| Linux 内核 | 了解用户态/内核态、系统调用、进程调度等基本概念 | 够用，边学 eBPF 边补充内核子系统知识 |
| C 语言 | 主要使用 Go/Python，C 基本不会 | 需要先补 C 基础 (eBPF 内核程序必须用 C) |
| 主力语言 | Go + Python | 用户态程序用 Go (cilium/ebpf)，与 OBI 项目一致 |
| eBPF 经验 | 用过 bpftrace/BCC 等工具 | 有体感，可快速过渡到编程 |
| 工作场景 | 综合: K8s/容器、微服务延迟、系统级性能分析 | 所有场景在 OBI 项目中都有对应实现 |

---

## 总体路线图

```
Week 1: C 语言速成 (专注 eBPF 需要的子集)
Week 2: eBPF 基础概念 + 第一个 Hello World
Week 3: eBPF Maps 与用户态通信 (Go/cilium-ebpf)
Week 4: Kprobes/Kretprobes — 追踪内核函数
Week 5: Uprobes — 追踪用户态函数 (读懂 OBI 的 Go/SSL 探针)
Week 6: 网络追踪: TC/XDP/Socket Filter (读懂 OBI 的网络流量采集)
Week 7: 综合实战 — 写一个 HTTP 延迟追踪器
Week 8: 深入 OBI 项目架构，贡献或扩展
```

---

## Week 1: C 语言速成 (eBPF 子集)

**目标**: 能读懂和写简单的 eBPF C 代码

eBPF 不需要完整的 C 知识。以下是必须掌握的子集:

| Day | 主题 | 知识点 | 实践任务 | 对应 OBI 文件 |
|-----|------|--------|---------|---------------|
| 1 | 基本类型与控制流 | `int`, `u32`, `u64`, `char`, `if/else/switch` | 写 3 个基础类型操作的小程序 | - |
| 2 | 指针与地址 | `*ptr`, `&var`, 指针解引用 | 用指针访问和修改结构体成员 | - |
| 3 | 结构体 | `struct` 定义、成员访问、嵌套 | 定义一个"网络连接"结构体 | `bpf/common/connection_info.h` |
| 4 | 内存操作 | 数组, `__builtin_memcpy`, 内存布局 | 模仿 OBI 的连接信息拷贝 | `bpf/common/connection_info.h` |
| 5 | 预处理器 | `#define` 宏, 条件编译, 头文件组织 | 读懂 OBI 的宏定义和头文件结构 | `bpf/common/common.h` |
| 6 | 枚举与位运算 | `enum`, `\|`, `&`, `<<`, `>>` | 读懂 TCP flags 处理逻辑 | `bpf/netolly/flows.c` |
| 7 | 综合练习 | 综合运用以上所有知识 | 逐行注释 `flows.c` 的前 60 行 | `bpf/netolly/flows.c` |

### 重点 C 语言概念 (eBPF 专用)

```c
// 1. eBPF 常用的固定宽度类型 (不是标准 C 的 int/long)
u8, u16, u32, u64    // 无符号
s8, s16, s32, s64    // 有符号

// 2. 指针 — eBPF 最核心的操作
struct sock *sk;              // sk 是指向 sock 结构体的指针
u32 pid = sk->sk_num;         // -> 是通过指针访问成员

// 3. 结构体 — eBPF 的数据组织方式
typedef struct connection_info {
    u8  s_addr[16];
    u8  d_addr[16];
    u16 s_port;
    u16 d_port;
} connection_info_t;

// 4. __builtin_memcpy — eBPF 中的内存拷贝 (不能用标准库的 memcpy)
__builtin_memcpy(&dst, &src, sizeof(src));

// 5. 位运算 — 网络编程和标志位处理
*flags |= SYN_FLAG;           // 设置标志位
if (th->ack && th->syn)       // 检查标志位
```

---

## Week 2: eBPF 基础概念 + Hello World

**目标**: 理解 eBPF 运行机制，写出第一个程序

### 核心概念

| 概念 | 说明 | OBI 项目中的体现 |
|------|------|-----------------|
| eBPF 虚拟机 | 内核中的沙箱化虚拟机，运行安全验证过的代码 | 所有 `bpf/*.c` 编译后加载到内核运行 |
| Verifier | 内核验证器，确保程序安全 (不能死循环/越界) | OBI 中大量的边界检查、`#pragma unroll` |
| Program Types | 不同类型挂载在不同内核钩子 | `kprobe`, `uprobe`, `tc`, `xdp`, `socket` |
| Helper Functions | eBPF 可调用的内核辅助函数 | `bpf_get_current_pid_tgid()`, `bpf_probe_read()` |
| CO-RE | Compile Once, Run Everywhere | `bpf/bpfcore/` — vmlinux.h 和 BTF 头文件 |
| SEC() 宏 | 声明 eBPF 程序的挂载点 | `SEC("kprobe/tcp_sendmsg")` |

### 每日任务

| Day | 主题 | 任务 |
|-----|------|------|
| 1 | eBPF 架构 | 阅读 ebpf.io 的 "What is eBPF?" 页面，画出架构图 |
| 2 | Program Types | 列出 OBI 项目中用到的所有 `SEC()` 类型，理解每种的用途 |
| 3 | Verifier 规则 | 了解验证器限制: 循环次数、栈大小、指针边界检查 |
| 4 | 环境搭建 | 安装 clang, llvm, libbpf-dev, bpftool, cilium/ebpf |
| 5 | Hello World (C) | 写 kprobe 挂载 `sys_enter_openat`，打印进程名 |
| 6 | Hello World (Go) | 用 Go + cilium/ebpf 加载上面的程序，读取输出 |
| 7 | 调试工具 | 用 `bpftool prog list` / `bpftool map list` 查看运行状态 |

### 环境搭建命令

```bash
# Ubuntu/Debian
sudo apt install clang llvm libbpf-dev linux-tools-common linux-tools-$(uname -r) bpftool

# Go eBPF 库
go get github.com/cilium/ebpf
go install github.com/cilium/ebpf/cmd/bpf2go@latest

# 验证环境
bpftool version
clang --version
```

---

## Week 3: eBPF Maps — 内核与用户态的桥梁

**目标**: 掌握各种 Map 类型和数据通信模式

### Map 类型对照表

| Map 类型 | 用途 | OBI 项目中的使用 |
|----------|------|-----------------|
| `BPF_MAP_TYPE_HASH` | 键值存储 | `bpf/maps/fd_map.h` — FD 到连接的映射 |
| `BPF_MAP_TYPE_RINGBUF` | 高性能事件流 (内核->用户态) | `bpf/common/ringbuf.h` — 事件上报 |
| `BPF_MAP_TYPE_PERCPU_HASH` | 每 CPU 哈希表，无锁竞争 | 连接追踪的性能关键路径 |
| `BPF_MAP_TYPE_LRU_HASH` | 自动淘汰的缓存 | 连接状态缓存 |
| `BPF_MAP_TYPE_ARRAY` | 全局配置/索引 | PID 过滤配置 |

### 每日任务

| Day | 主题 | 任务 |
|-----|------|------|
| 1 | HashMap | 写一个统计每个进程系统调用次数的程序 |
| 2 | RingBuffer | 把事件从内核发送到 Go 用户态程序 |
| 3 | 阅读 OBI Maps | 读 `bpf/maps/` 目录下所有头文件，理解每个 Map 的用途 |
| 4 | RingBuffer 深入 | 读 `bpf/common/ringbuf.h`，理解 OBI 如何上报事件 |
| 5 | Per-CPU Map | 学习 Per-CPU Map，理解并发安全 |
| 6 | Go 用户态 Map 操作 | 用 Go (cilium/ebpf) 写完整的 Map CRUD 程序 |
| 7 | 调试 Map | 用 `bpftool map dump` 调试 Map 内容 |

### OBI Maps 目录速查

```
bpf/maps/
├── accepted_connections.h      — 已接受的连接
├── active_ssl_connections.h    — 活跃 SSL 连接
├── fd_map.h                    — 文件描述符映射
├── fd_to_connection.h          — FD 到连接信息
├── incoming_trace_map.h        — 入站追踪上下文
├── msg_buffers.h               — 消息缓冲区
├── ongoing_http.h              — 进行中的 HTTP 请求
├── ongoing_http2_connections.h — 进行中的 HTTP2 连接
├── outgoing_trace_map.h        — 出站追踪上下文
├── server_traces.h             — 服务端追踪
├── sock_dir.h                  — Socket 方向
├── sock_pids.h                 — Socket 到 PID 映射
├── ssl_to_conn.h               — SSL 到连接映射
├── tp_info_mem.h               — 追踪上下文内存
└── trace_map.h                 — 追踪映射
```

---

## Week 4: Kprobes — 追踪内核函数

**目标**: 理解内核探针机制，能追踪网络和文件操作

### 核心文件: `bpf/generictracer/k_tracer.c`

这是 OBI 的内核追踪核心，挂载了以下内核函数:

| 钩子 | 追踪目标 | 性能分析价值 |
|------|---------|-------------|
| `kprobe/tcp_sendmsg` | TCP 发送数据 | 网络发送延迟 |
| `kprobe/tcp_recvmsg` | TCP 接收数据 | 请求响应时间 |
| `kretprobe/tcp_sendmsg` | TCP 发送完成 | 发送耗时统计 |
| `kretprobe/tcp_recvmsg` | TCP 接收完成 | 接收耗时统计 |
| `kprobe/security_socket_accept` | 新连接接受 | 连接建立追踪 |
| `kprobe/sys_connect` | 出站连接 | 上游依赖发现 |
| `kretprobe/sys_connect` | 连接结果 | 连接成功/失败统计 |
| `kprobe/tcp_connect` | TCP 连接 | 三次握手追踪 |
| `kprobe/tcp_close` | 连接关闭 | 连接生命周期 |
| `kretprobe/sys_clone` | 进程创建 | 子进程追踪 |
| `kprobe/sys_exit` | 进程退出 | 进程清理 |
| `kprobe/udp_sendmsg` | UDP 发送 | DNS 查询追踪 |
| `kprobe/tcp_cleanup_rbuf` | 接收缓冲清理 | 精确接收统计 |
| `kprobe/sock_def_error_report` | Socket 错误 | 错误率监控 |

### 每日任务

| Day | 主题 | 任务 |
|-----|------|------|
| 1 | kprobe 基础 | 写 kprobe 追踪 `tcp_connect`，打印目标 IP 和端口 |
| 2 | kretprobe | 加 kretprobe 获取返回值，判断连接成功/失败 |
| 3 | 精读 OBI (1) | 逐行精读 `k_tracer.c` 的 `obi_kprobe_security_socket_accept` |
| 4 | 精读 OBI (2) | 精读 `k_tracer.c` 的 `tcp_sendmsg` / `tcp_recvmsg` 探针 |
| 5 | PID 过滤 | 理解 OBI 如何用 `bpf_get_current_pid_tgid()` + `valid_pid()` 过滤 |
| 6 | 文件 IO 追踪 | 写追踪文件 I/O 延迟的 kprobe 程序 (类似 biolatency) |
| 7 | 对比学习 | 对比你写的程序和 bpftrace 的 `biolatency`，理解同一功能的不同实现 |

### OBI 的 PID 过滤机制

```c
// 来自 k_tracer.c 第 54-60 行
SEC("kprobe/security_socket_accept")
int BPF_KPROBE(obi_kprobe_security_socket_accept, struct socket *sock, ...) {
    const u64 id = bpf_get_current_pid_tgid();  // 获取当前 PID+TID
    if (!valid_pid(id)) {                        // 只追踪目标进程
        return 0;
    }
    // ... 记录连接信息
}
```

---

## Week 5: Uprobes — 追踪用户态函数

**目标**: 理解无侵入追踪应用程序的机制

这是 OBI 的核心竞争力 — 不修改应用代码就能追踪 HTTP/gRPC/SQL/Redis 调用。

### OBI 的 Uprobe 全景

| 分类 | 探针 | 追踪目标 | 源文件 |
|------|------|---------|--------|
| Go HTTP | `uprobe/roundTrip`, `uprobe/ServeHTTP` | HTTP 客户端/服务端 | `bpf/gotracer/go_nethttp.c` |
| Go gRPC | `uprobe/ClientConn_Invoke`, `uprobe/server_handleStream` | gRPC 调用 | `bpf/gotracer/go_grpc.c` |
| Go Redis | `uprobe/redis_process`, `uprobe/redis_with_writer` | Redis 命令 | `bpf/gotracer/go_redis.c` |
| Go SQL | `uprobe/queryDC`, `uprobe/execDC` | 数据库查询 | `bpf/gotracer/go_sql.c` |
| Go MongoDB | `uprobe/op_coll_find`, `uprobe/op_coll_insert` ... | MongoDB 操作 | `bpf/gotracer/go_mongo.c` |
| Go Kafka | `uprobe/writer_produce`, `uprobe/reader_read` | Kafka 生产/消费 | `bpf/gotracer/go_kafka_go.c` |
| SSL/TLS | `uprobe/libssl.so:SSL_read/write` | 加密流量明文抓取 | `bpf/generictracer/libssl.c` |
| Nginx | `uprobe/nginx:ngx_http_upstream_init` | 反向代理 | `bpf/generictracer/nginx.c` |
| Node.js | `uprobe/node:uv_fs_access` | Node.js 运行时 | `bpf/generictracer/nodejs.c` |
| Ruby | `uprobe/ruby:rb_obj_call_init_kw` | Ruby 运行时 | `bpf/generictracer/ruby.c` |

### 每日任务

| Day | 主题 | 任务 |
|-----|------|------|
| 1 | uprobe 基础 | 写 uprobe 追踪 `malloc` 的大小参数 |
| 2 | SSL 追踪 | 读 `bpf/generictracer/libssl.c`，理解如何追踪加密流量 |
| 3 | Go HTTP 追踪 | 读 `bpf/gotracer/go_nethttp.c`，理解 Go HTTP 请求追踪 |
| 4 | Go 调用约定 | 理解 Go 函数调用约定与 C 的区别 (寄存器 vs 栈) |
| 5 | 偏移量机制 | 读 `bpf/gotracer/go_offsets.h`，理解为什么需要动态偏移量 |
| 6 | 自定义 uprobe | 写 uprobe 追踪你自己写的 Go 程序的某个函数 |
| 7 | 验证与调试 | 用 `bpftool` 查看已挂载的 uprobe，理解挂载生命周期 |

### Go 追踪的特殊挑战

```
问题: Go 的二进制是静态链接的，不经过 libc
解决: OBI 直接在 Go 二进制的符号上挂 uprobe

问题: Go 的 goroutine 可以在不同 OS 线程间迁移
解决: OBI 追踪 goroutine ID 而不是 thread ID

问题: Go 函数参数通过寄存器传递 (不同版本有差异)
解决: OBI 维护 offsets.json 记录不同 Go 版本的偏移量
```

---

## Week 6: 网络追踪 — TC/XDP/Socket Filter

**目标**: 掌握网络数据面的 eBPF 编程

### OBI 的网络层实现

| 程序类型 | 挂载点 | 速度 | OBI 源文件 | 用途 |
|----------|--------|------|-----------|------|
| XDP | 网卡驱动层 | 最快 | `bpf/rdns/rdns_xdp.c` | 反向 DNS 查询 |
| TC ingress/egress | 流量控制层 | 快 | `bpf/netolly/flows.c` | 网络流量统计 |
| Socket Filter | Socket 层 | 中等 | `k_tracer.c (socket/http_filter)` | HTTP 协议解析 |
| SK_MSG | Socket 消息 | 快 | `bpf/netolly/flows_sock.c` | Socket 级别流追踪 |

### 每日任务

| Day | 主题 | 任务 |
|-----|------|------|
| 1 | TC 基础 | 精读 `bpf/netolly/flows.c`，理解数据包解析流程 |
| 2 | 五元组提取 | 理解 `fill_iphdr()` 如何从 IP/TCP 头提取五元组 |
| 3 | TC 实践 | 写一个 TC 程序统计每个目标 IP 的流量 |
| 4 | XDP | 读 `bpf/rdns/rdns_xdp.c`，理解 XDP 程序结构和返回值 |
| 5 | 对比三种类型 | 理解 `tc_ingress` vs `tc_egress` vs `xdp` 的挂载点和性能差异 |
| 6 | Socket Filter | 读 OBI 的 `socket/http_filter`，理解 HTTP 协议匹配方式 |
| 7 | 综合 | 写一个简单的 TCP 连接追踪器 (新建/关闭/统计) |

### 数据包解析示意

```
XDP/TC 程序看到的数据:
┌──────────┬──────────┬──────────┬──────────────┐
│ Ethernet │ IP Header│TCP Header│   Payload    │
│  14 bytes│ 20 bytes │ 20 bytes │  HTTP/gRPC   │
└──────────┴──────────┴──────────┴──────────────┘
                                        │
     flows.c 的 fill_iphdr() ──────────┘
     提取: src_ip, dst_ip, src_port, dst_port, protocol
```

---

## Week 7: 综合实战 — 写一个 HTTP 延迟追踪器

**目标**: 从零写一个完整的性能分析工具

### 项目: mini-http-tracer

模仿 OBI 的简化版，实现完整的 HTTP 请求延迟追踪:

```
架构:
┌─────────────────────────────┐
│          Go 用户态           │
│  cilium/ebpf 加载 + 读取     │
│  RingBuffer → 延迟计算       │
│  Prometheus metrics 导出     │
└──────────────┬──────────────┘
               │
═══════════════╪═══════════════
               │ 内核态
┌──────────────┴──────────────┐
│  kprobe/tcp_sendmsg         │
│  kprobe/tcp_recvmsg         │
│  → 识别 HTTP 请求/响应       │
│  → 记录时间戳到 HashMap      │
│  → 通过 RingBuffer 上报事件  │
└─────────────────────────────┘
```

### 每日任务

| Day | 主题 | 任务 |
|-----|------|------|
| 1 | 设计 | 定义数据结构: 请求信息结构体、Map 定义、事件格式 |
| 2 | 内核态 (1) | 写 kprobe 追踪 TCP 收发，记录时间戳 |
| 3 | 内核态 (2) | 加入 HTTP 协议识别 (匹配 "GET ", "POST ", "HTTP/1.") |
| 4 | 用户态 (1) | 用 Go + cilium/ebpf 加载 eBPF 程序，读取 RingBuffer |
| 5 | 用户态 (2) | 实现延迟计算逻辑和统计聚合 |
| 6 | 导出 | 接入 Prometheus client_golang，暴露 HTTP 延迟直方图 |
| 7 | 验证 | 用 curl/wrk 测试，对比 OBI 的实现 `bpf/generictracer/protocol_http.h` |

---

## Week 8: 深入 OBI 项目架构

**目标**: 能读懂整个 OBI 项目，具备贡献能力

### OBI 架构全景

```
┌──────────────────────────────────────────────────────────┐
│                      Go 用户态                            │
│                                                          │
│  ProcessWatcher → CriteriaMatcher → TraceAttacher         │
│       │                                    │              │
│  发现目标进程               为每个进程加载 eBPF 程序       │
│                                    │              │
│                              ┌─────┴─────┐       │
│                              │           │       │
│                         gotracer   generictracer  │
│                         (Go程序)    (通用C程序)    │
│                              │           │       │
│                              └─────┬─────┘       │
│                                    │              │
│  RingBuffer Reader ← ─ ─ ─ ─ ─ ─ ─┘              │
│       │                                          │
│  traces.ReadDecorator → Routes → K8s Decorator    │
│       │                                          │
│  ┌────┴────────────────────┐                     │
│  │                         │                     │
│  OTEL Traces Exporter   OTEL Metrics Exporter    │
│  Prometheus Endpoint     Service Graph           │
└──────────────────────────────────────────────────────────┘
                         │ cilium/ebpf
═════════════════════════╪═══════════════════════════════════
                         │ 内核态
┌────────────────────────┴─────────────────────────────────┐
│                                                          │
│  kprobes (TCP/Socket层)  +  uprobes (应用层)              │
│       │                         │                        │
│  网络连接追踪              HTTP/gRPC/SQL/Redis 追踪       │
│       │                         │                        │
│  Maps: 连接状态、PID映射、协议缓冲、追踪上下文             │
│       │                                                  │
│  RingBuffer → 事件上报到用户态                            │
│                                                          │
│  TC/XDP: 网络流量统计、DNS 追踪                           │
└──────────────────────────────────────────────────────────┘
```

### 每日任务

| Day | 主题 | 任务 |
|-----|------|------|
| 1 | 数据流全貌 | 读 `devdocs/pipeline-map.md`，画出完整数据流图 |
| 2 | Go eBPF 加载 | 读 Go 端的 eBPF 加载逻辑 (`pkg/` 目录) |
| 3 | 进程发现 | 理解 OBI 如何自动发现进程并挂载探针 |
| 4 | 分布式追踪 | 读 `devdocs/context-propagation.md`，理解 Trace Propagation |
| 5 | 本地构建 | 本地构建 OBI: `make docker-generate` |
| 6 | 实际使用 | 用 OBI 追踪一个你自己的 Go HTTP 服务 |
| 7 | 贡献准备 | 找一个 GitHub Issue，理解并规划解决方案 |

---

## 学习资源

### 必读

| 资源 | 用途 | 优先级 |
|------|------|--------|
| [ebpf.io](https://ebpf.io) | eBPF 官方入门，概念理解 | 最高 |
| *Learning eBPF* (Liz Rice) | 最好的系统性入门书 | 最高 |
| [cilium/ebpf Go 库文档](https://pkg.go.dev/github.com/cilium/ebpf) | Go 用户态开发参考 | 最高 |

### C 语言速成

| 资源 | 说明 |
|------|------|
| [Beej's Guide to C](https://beej.us/guide/bgc/) | 免费在线 C 教程，简洁实用 |
| 直接读 OBI 代码 + 让 Claude 逐行讲解 | 最高效: 结合实际项目学 |

### 进阶

| 资源 | 用途 |
|------|------|
| [BPF Performance Tools](http://www.brendangregg.com/bpf-performance-tools-book.html) (Brendan Gregg) | 性能分析大全 |
| [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) | 项目模板参考 |
| [cilium/ebpf examples](https://github.com/cilium/ebpf/tree/main/examples) | Go + eBPF 代码示例 |

### 工具链安装

```bash
# Ubuntu/Debian
sudo apt install clang llvm libbpf-dev linux-tools-common \
    linux-tools-$(uname -r) bpftool linux-headers-$(uname -r)

# Go eBPF 库
go get github.com/cilium/ebpf
go install github.com/cilium/ebpf/cmd/bpf2go@latest

# 验证
bpftool version && clang --version && bpf2go --help
```

---

## OBI 项目中用到的所有 eBPF 技术汇总

供快速查阅，了解 OBI 使用了哪些 eBPF 能力:

### Program Types

| 类型 | SEC() 宏示例 | OBI 中的数量 |
|------|-------------|-------------|
| kprobe | `SEC("kprobe/tcp_sendmsg")` | ~15 个 |
| kretprobe | `SEC("kretprobe/sys_connect")` | ~5 个 |
| uprobe (Go) | `SEC("uprobe/roundTrip")` | ~60+ 个 |
| uprobe (C libs) | `SEC("uprobe/libssl.so:SSL_read")` | ~12 个 |
| uretprobe | `SEC("uretprobe/libssl.so:SSL_read")` | ~4 个 |
| TC | `SEC("tc_ingress")`, `SEC("tc_egress")` | 2 个 |
| XDP | `SEC("xdp")` | 1 个 |
| Socket Filter | `SEC("socket/http_filter")` | 1 个 |
| SK_MSG | `SEC("sk_msg")` | 1 个 |
| SOCKOPS | `SEC("sockops")` | 1 个 |
| BPF Iterator | `SEC("iter/tcp")` | 2 个 |

### Map Types 使用

| Map 类型 | 用途分类 |
|----------|---------|
| HASH | 连接状态、FD 映射、PID 过滤 |
| PERCPU_HASH | 高频更新的连接计数 |
| LRU_HASH | 自动过期的缓存 |
| ARRAY | 全局配置 |
| RINGBUF | 事件上报到用户态 |

### Helper Functions 使用

| Helper | 用途 |
|--------|------|
| `bpf_get_current_pid_tgid()` | 获取当前进程 PID 和线程 TID |
| `bpf_probe_read()` | 安全读取内核内存 |
| `bpf_probe_read_user()` | 安全读取用户态内存 |
| `bpf_ktime_get_ns()` | 获取高精度时间戳 |
| `bpf_ringbuf_reserve/submit()` | RingBuffer 事件提交 |
| `bpf_map_lookup/update/delete_elem()` | Map 操作 |
| `bpf_get_current_comm()` | 获取进程名 |
| `bpf_skb_load_bytes()` | Socket Buffer 读取 |
