# Week 8 - Day 7: 贡献指南与学习总结

## 学习目标
了解如何为 OBI 项目贡献代码，并回顾 8 周学习成果。

## 一、向 OBI 贡献代码

### 1. 项目结构回顾

```
opentelemetry-ebpf-instrumentation/
├── bpf/                    # eBPF C 代码 (内核态)
│   ├── common/             #   公共头文件 (connection_info, ringbuf, pid)
│   ├── generictracer/      #   通用追踪器 (kprobe, uprobe)
│   │   ├── k_tracer.c      #     kprobe 探针
│   │   ├── libssl.c        #     SSL uprobe 探针
│   │   └── protocol_*.h    #     协议检测
│   └── netolly/            #   网络可观测性 (TC, XDP)
│       └── flows.c         #     流量统计
├── pkg/                    # Go 代码 (用户态)
│   ├── ebpf/               #   eBPF 加载和管理
│   ├── export/             #   OTEL/Prometheus 导出
│   └── discover/           #   进程发现
├── cmd/                    # 入口点
├── devdocs/                # 开发文档
└── test/                   # 测试
```

### 2. 贡献流程

```
1. Fork 仓库
   → https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation

2. 创建分支
   → git checkout -b feature/add-redis-protocol

3. 开发
   → 编写代码 + 测试
   → 遵循项目编码规范

4. 本地测试
   → make test
   → make lint

5. 提交 PR
   → 清晰的 PR 描述
   → 关联 Issue
   → 等待 CI 通过

6. Code Review
   → 回应评论
   → 修改代码
   → 获得 Approval

7. 合并
   → Maintainer 合并 PR
```

### 3. 适合新手的贡献方向

#### 方向 A: 添加新的协议检测

```
难度: ★★★☆☆ (中等)
涉及文件: bpf/generictracer/protocol_*.h

例子: 添加 Redis 协议检测

步骤:
1. 研究 Redis 协议格式 (RESP)
   - "*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n"
   
2. 创建 protocol_redis.h
   - 检测函数: is_redis(buf, len)
   - 匹配: buf[0] == '*' || buf[0] == '+'

3. 在 k_tracer.c 中集成
   - tcp_sendmsg/recvmsg 中调用 is_redis()

4. 在 Go 端添加解析
   - 解析 Redis 命令名和参数

5. 添加测试
```

#### 方向 B: 改进文档

```
难度: ★☆☆☆☆ (简单)
涉及文件: devdocs/, README.md

例子:
- 改进安装文档
- 添加架构图
- 翻译文档 (中英文)
- 添加更多代码注释
```

#### 方向 C: 添加新的 Metrics

```
难度: ★★☆☆☆ (简单-中等)
涉及文件: pkg/export/

例子:
- 添加连接数统计
- 添加按 HTTP 路径的延迟直方图
- 添加 DNS 查询统计
```

#### 方向 D: 改进测试

```
难度: ★★☆☆☆ (简单-中等)
涉及文件: test/

例子:
- 添加端到端测试
- 添加性能基准测试
- 改进 CI 流程
```

### 4. 编码规范

#### eBPF C 代码规范

```c
// 1. 文件头注释
// SPDX-License-Identifier: Apache-2.0

// 2. 函数命名: obi_ 前缀
SEC("kprobe/xxx")
int BPF_KPROBE(obi_kprobe_xxx, ...) { }

// 3. 始终检查 valid_pid
if (!valid_pid(id)) return 0;

// 4. Map 名使用 snake_case
struct { ... } active_reads SEC(".maps");

// 5. 使用 __always_inline
static __always_inline int helper_func(...) { }

// 6. 边界检查必须严格
if (offset + sizeof(struct iphdr) > data_end) return 0;
```

#### Go 代码规范

```go
// 1. 标准 Go 项目结构
// 2. 使用 Go 标准错误处理
if err != nil {
    return fmt.Errorf("failed to load program: %w", err)
}

// 3. 使用 context 管理生命周期
func (t *Tracer) Run(ctx context.Context) error { }

// 4. 使用 slog 或 zap 日志
slog.Info("attached kprobe", "function", "tcp_sendmsg", "pid", pid)
```

## 二、8 周学习总结

### 学习路径回顾

```
Week 1: C 语言基础
  ✓ 整数类型 (u8/u16/u32/u64)
  ✓ 指针和结构体
  ✓ 内存操作和宏
  ✓ 位运算
  → 打下了读懂 eBPF C 代码的基础

Week 2: eBPF 基础
  ✓ 架构和程序类型
  ✓ 验证器规则
  ✓ 环境搭建
  ✓ 第一个 eBPF 程序
  → 理解了 eBPF 的工作原理

Week 3: Map 深入
  ✓ HashMap, Array, PerCPU, LRU
  ✓ RingBuffer 和 PerfBuffer
  ✓ Map 操作和调试
  → 掌握了内核态-用户态数据传递

Week 4: Kprobe 实战
  ✓ TCP 追踪 (connect, accept, send, recv)
  ✓ kprobe + kretprobe 配对模式
  ✓ PID 过滤
  ✓ 延迟直方图
  → 能够编写实用的追踪程序

Week 5: Uprobe 和用户态追踪
  ✓ 库函数追踪 (malloc, SSL)
  ✓ Go 程序追踪的特殊性
  ✓ OBI 的 offset 机制
  → 理解了应用层追踪

Week 6: 网络追踪
  ✓ TC 和 XDP 程序
  ✓ 数据包解析 (L2/L3/L4)
  ✓ Socket Filter
  ✓ 连接追踪
  → 掌握了网络可观测性

Week 7: HTTP Tracer 项目
  ✓ 设计架构
  ✓ 编写 eBPF + Go 代码
  ✓ 协议检测
  ✓ Prometheus 导出
  → 独立完成了完整项目

Week 8: OBI 深度学习
  ✓ Pipeline 架构
  ✓ Go 加载器
  ✓ 进程发现
  ✓ OTEL Context Propagation
  ✓ 构建和运行 OBI
  → 具备了参与项目的能力
```

### 技能矩阵

```
技能                        学前    学后
─────────────────────────────────────────
C 语言读写                   ☆☆☆   ★★★☆
eBPF 程序编写                ☆☆☆   ★★★☆
内核态编程概念               ★☆☆   ★★★☆
Go + eBPF 集成               ☆☆☆   ★★★☆
网络包解析                   ☆☆☆   ★★★☆
性能分析工具                 ★★☆   ★★★★
分布式追踪                   ★☆☆   ★★★☆
OBI 项目理解                 ☆☆☆   ★★★★
```

### 继续学习建议

```
短期 (1-2 周):
  □ 为 OBI 提交一个 PR (从文档/测试开始)
  □ 用你的 HTTP Tracer 监控一个真实服务
  □ 阅读 Brendan Gregg 的 "BPF Performance Tools"

中期 (1-2 月):
  □ 添加新的协议检测 (Redis/Kafka)
  □ 学习 eBPF 的 CO-RE 细节
  □ 参与 OBI 的 Issue 讨论
  □ 写一篇 eBPF 学习博客

长期 (3-6 月):
  □ 成为 OBI 的 Regular Contributor
  □ 深入学习 Linux 内核网络栈
  □ 探索 eBPF 在安全领域的应用 (Falco, Tetragon)
  □ 用 eBPF 解决实际工作中的问题
```

## 三、推荐资源

### 书籍
- "Learning eBPF" — Liz Rice (入门首选)
- "BPF Performance Tools" — Brendan Gregg (参考手册)
- "Linux Observability with BPF" — David Calavera

### 在线资源
- https://ebpf.io — eBPF 官网
- https://nakryiko.com — Andrii Nakryiko 的博客 (libbpf 维护者)
- https://brendangregg.com — Brendan Gregg 的博客
- https://github.com/iovisor/bcc — BCC 工具集

### 社区
- OTEL eBPF SIG — OpenTelemetry eBPF 兴趣组
- eBPF Slack — https://ebpf.io/slack
- Cilium Slack — cilium/ebpf 相关讨论

### 实践项目
- OBI — 本学习计划的主项目
- Cilium — 基于 eBPF 的网络方案
- Falco — 基于 eBPF 的安全监控
- Tetragon — 运行时安全可观测

## 恭喜完成 8 周 eBPF 学习！

```
    ╔═══════════════════════════════════════════════╗
    ║                                               ║
    ║   从零基础到能够参与 OBI 项目贡献              ║
    ║                                               ║
    ║   你已经掌握了:                                ║
    ║   ✓ eBPF 编程基础                             ║
    ║   ✓ 内核追踪技术                              ║
    ║   ✓ 网络可观测性                              ║
    ║   ✓ 生产级工具开发                            ║
    ║                                               ║
    ║   Keep learning, keep hacking!                ║
    ║                                               ║
    ╚═══════════════════════════════════════════════╝
```
