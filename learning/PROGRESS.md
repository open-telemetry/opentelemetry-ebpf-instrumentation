# eBPF 学习进度追踪

> 开始日期: 2026-03-31
> 最后更新: 2026-04-01 (Week2 Day7 完成, Week2 全部完成)

## 进度总览

| 阶段 | 主题 | 状态 | 开始日期 | 完成日期 | 备注 |
|------|------|------|---------|---------|------|
| Week 1 | C 语言速成 | `已完成` | 2026-03-31 | 2026-03-31 | 7天全部完成 |
| Week 2 | eBPF 基础 + Hello World | `已完成` | 2026-03-31 | 2026-04-01 | 7天全部完成,成功编译运行eBPF程序 |
| Week 3 | eBPF Maps | `未开始` | - | - | |
| Week 4 | Kprobes | `未开始` | - | - | |
| Week 5 | Uprobes | `未开始` | - | - | |
| Week 6 | 网络追踪 TC/XDP | `未开始` | - | - | |
| Week 7 | 综合实战 HTTP 追踪器 | `未开始` | - | - | |
| Week 8 | 深入 OBI 项目 | `未开始` | - | - | |

状态说明: `未开始` → `进行中` → `已完成` → `已复习`

---

## Week 1: C 语言速成

| Day | 主题 | Demo 文件 | 状态 | 日期 | 笔记/收获 |
|-----|------|----------|------|------|----------|
| 1 | 基本类型与控制流 | `day1/types_and_control.c` | `已完成` | 2026-03-31 | u8/u16/u32/u64 固定宽度类型; bpf_get_current_pid_tgid() 返回触发探针进程的 PID+TID; TID 用于 kprobe/kretprobe 配对 |
| 2 | 指针与地址 | `day2/pointers.c` | `已完成` | 2026-03-31 | &取地址 *解引用; ->访问结构体成员; 指针参数传出多值; void*强转+NULL检查是Map查找必备模式; *在声明=指针类型,在使用=解引用 |
| 3 | 结构体 | `day3/structs.c` | `已完成` | 2026-03-31 | struct打包数据; union共享内存(同一数据不同视角,OBI用于IP地址按字节写/按u32比较); 嵌套三层ssl>pid_conn>conn; {0}初始化是eBPF铁律 |
| 4 | 内存操作 | `day4/memory_ops.c` | `已完成` | 2026-03-31 | __builtin_memcpy(dst,src,len)是eBPF唯一内存拷贝; 边界检查ptr+size>data_end是verifier铁律; IPv4-mapped-IPv6两步拷贝(12字节前缀+4字节IP); HTTP方法逐字节匹配 |
| 5 | 预处理器 | `day5/macros.c` | `已完成` | 2026-03-31 | #define是文本替换(eBPF数组大小只能用它不能用const); SEC("type/target")给函数贴标签告诉加载器类型和挂载点; __always_inline必须内联因为verifier需要; 宏用于常量/标记,内联函数用于逻辑 |
| 6 | 枚举与位运算 | `day6/bitops.c` | `已完成` | 2026-03-31 | enum给数字取名(协议类型); TCP flags每位一个含义(SYN/ACK/FIN/RST); |=设置 &检查 &=~清除; set_flags()判断TCP连接阶段; >><<处理字节序和PID组合 |
| 7 | 综合: 读懂 flows.c | `day7/flows_annotated.c` | `已完成` | 2026-03-31 | fill_iphdr综合运用全部知识: 边界检查→memcpy IP→指针跳转TCP头→字节序转换端口→set_flags; 5道验证题全部通过 |

路径前缀: `exercises/week1-c-basics/`

### Week 1 阅读的 OBI 文件

- [ ] `bpf/common/connection_info.h` — Day 3, 4 参考: 连接信息结构体
- [ ] `bpf/common/common.h` — Day 5 参考: 宏定义和类型
- [ ] `bpf/netolly/flows_common.h` — Day 6 参考: TCP flags 定义
- [ ] `bpf/netolly/flows.c` (前 120 行) — Day 7 综合精读

---

## Week 2: eBPF 基础概念 + Hello World

| Day | 主题 | Demo 文件 | 状态 | 日期 | 笔记/收获 |
|-----|------|----------|------|------|----------|
| 1 | eBPF 架构总览 | `day1/ebpf_architecture.c` | `已完成` | 2026-03-31 | 6步流程:写C→编译.o→加载内核→verifier+JIT→挂hook运行→Go读数据; 5组件:Verifier/JIT/Hooks/Maps/Helpers; 栈512字节限制; verifier保证安全 |
| 2 | Program Types | `day2/program_types_study.c` | `已完成` | 2026-03-31 | 10种类型:kprobe/kretprobe/uprobe/uretprobe/tc/xdp/socket/iter/sk_msg/sockops; uprobe通过ELF符号表找函数偏移量,内核用(文件inode+偏移)绑定,运行时基地址+偏移算实际地址; ASLR不影响 |
| 3 | Verifier 规则 | `day3/verifier_rules.c` | `已完成` | 2026-03-31 | 7条规则:必须return/无死循环/栈512字节/边界检查/指针只比data_end/Map查NULL/helper类型正确; OBI用scratch_mem Map绕栈限制; __uint是宏把Map配置编码进BTF |
| 4 | 环境搭建 | `day4/setup_env.sh` | `已完成` | 2026-04-01 | 7个工具:clang编译/llvm后端/libbpf-dev提供eBPF API头文件/linux-headers提供内核结构体/bpftool调试/Go用户态/bpf2go代码生成; CO-RE使编译运行内核可不同,靠BTF运行时修正偏移 |
| 5 | Hello World (C) | `day5/hello_openat.bpf.c` | `已完成` | 2026-04-01 | 最小kprobe程序:SEC+ctx+helper+return+LICENSE; pt_regs是CPU寄存器快照用于读函数参数; BPF_KPROBE宏自动提取参数; 实际编译运行成功,捕获到sys_openat事件 |
| 6 | Hello World (Go) | `day6/main.go` | `已完成` | 2026-04-01 | bpf2go自动生成Go绑定(.o嵌入binary); 4步:RemoveMemlock→加载→Kprobe附加→等信号; 手动加载vs bpf2go:后者类型安全+单文件部署; OBI用bpf2go模式 |
| 7 | bpftool 调试 | `day7/bpftool_debug.sh` | `已完成` | 2026-04-01 | bpftool prog list查程序/map list查Map/map dump看数据/trace_pipe看printk输出/prog profile看性能; 类比docker ps; 可用于调试OBI运行状态 |

路径前缀: `exercises/week2-hello-ebpf/`

### Week 2 环境搭建检查清单

- [ ] clang 安装并验证版本
- [ ] llvm 安装
- [ ] libbpf-dev 安装
- [ ] bpftool 安装并能运行 `bpftool version`
- [ ] linux-headers 安装 (匹配当前内核)
- [ ] Go cilium/ebpf 库安装
- [ ] bpf2go 工具安装
- [ ] 第一个 eBPF 程序成功加载到内核

---

## Week 3: eBPF Maps

| Day | 主题 | Demo 文件 | 状态 | 日期 | 笔记/收获 |
|-----|------|----------|------|------|----------|
| 1 | HashMap: 进程系统调用计数 | `day1/syscall_counter.bpf.c` | `未开始` | - | |
| 2 | RingBuffer: 事件上报 | `day2/event_ringbuf.bpf.c` | `未开始` | - | |
| 3 | 阅读 OBI Maps 目录 | `day3/obi_maps_study.c` | `未开始` | - | |
| 4 | 深入 OBI ringbuf.h | `day4/ringbuf_deep_dive.c` | `未开始` | - | |
| 5 | Per-CPU Map | `day5/percpu_counter.bpf.c` | `未开始` | - | |
| 6 | Go Map CRUD | `day6/map_ops.go` | `未开始` | - | |
| 7 | bpftool map 调试 | `day7/bpftool_map_debug.sh` | `未开始` | - | |

路径前缀: `exercises/week3-maps/`

### Week 3 阅读的 OBI 文件

- [ ] `bpf/maps/fd_map.h` — HashMap 定义参考
- [ ] `bpf/maps/fd_to_connection.h` — 关联 Map 参考
- [ ] `bpf/maps/ongoing_http.h` — 进行中请求 Map
- [ ] `bpf/maps/sock_pids.h` — Socket-PID 映射
- [ ] `bpf/common/ringbuf.h` — RingBuffer 定义和优化
- [ ] `bpf/common/map_sizing.h` — Map 大小配置

---

## Week 4: Kprobes

| Day | 主题 | Demo 文件 | 状态 | 日期 | 笔记/收获 |
|-----|------|----------|------|------|----------|
| 1 | kprobe tcp_connect | `day1/tcp_connect_tracer.bpf.c` | `未开始` | - | |
| 2 | kretprobe 返回值 | `day2/connect_retval.bpf.c` | `未开始` | - | |
| 3 | 精读 OBI accept 探针 | `day3/obi_accept_annotated.c` | `未开始` | - | |
| 4 | 精读 OBI tcp_send/recv | `day4/obi_tcp_sendrecv_annotated.c` | `未开始` | - | |
| 5 | PID 过滤机制 | `day5/pid_filter.bpf.c` | `未开始` | - | |
| 6 | 文件 IO 延迟追踪 | `day6/bio_latency.bpf.c` | `未开始` | - | |
| 7 | 对比 bpftrace | `day7/compare_bpftrace.bt` | `未开始` | - | |

路径前缀: `exercises/week4-kprobes/`

### Week 4 阅读的 OBI 文件

- [ ] `bpf/generictracer/k_tracer.c` — 完整精读 (核心!)
- [ ] `bpf/generictracer/k_tracer_defs.h` — 内核追踪器定义
- [ ] `bpf/generictracer/k_send_receive.h` — TCP 收发追踪
- [ ] `bpf/pid/pid.h` — PID 过滤核心逻辑
- [ ] `bpf/pid/pid_helpers.h` — PID 辅助函数

---

## Week 5: Uprobes

| Day | 主题 | Demo 文件 | 状态 | 日期 | 笔记/收获 |
|-----|------|----------|------|------|----------|
| 1 | uprobe 追踪 malloc | `day1/malloc_tracer.bpf.c` | `未开始` | - | |
| 2 | 精读 OBI SSL 追踪 | `day2/obi_ssl_annotated.c` | `未开始` | - | |
| 3 | 精读 OBI Go HTTP | `day3/obi_go_http_annotated.c` | `未开始` | - | |
| 4 | Go 调用约定 | `day4/go_calling_convention.c` | `未开始` | - | |
| 5 | OBI 偏移量机制 | `day5/obi_offsets_study.c` | `未开始` | - | |
| 6 | 自定义 Go uprobe | `day6/go_func_tracer.bpf.c` | `未开始` | - | |
| 7 | 验证 uprobe 挂载 | `day7/verify_uprobe.sh` | `未开始` | - | |

路径前缀: `exercises/week5-uprobes/`

### Week 5 阅读的 OBI 文件

- [ ] `bpf/generictracer/libssl.c` — SSL/TLS 追踪
- [ ] `bpf/gotracer/go_nethttp.c` — Go HTTP 追踪
- [ ] `bpf/gotracer/go_grpc.c` — Go gRPC 追踪
- [ ] `bpf/gotracer/go_offsets.h` — Go 偏移量定义
- [ ] `bpf/gotracer/go_common.h` — Go 追踪公共函数
- [ ] `bpf/gotracer/go_str.h` — Go 字符串处理

---

## Week 6: 网络追踪 TC/XDP/Socket Filter

| Day | 主题 | Demo 文件 | 状态 | 日期 | 笔记/收获 |
|-----|------|----------|------|------|----------|
| 1 | 精读 flows.c 完整版 | `day1/obi_flows_deep_dive.c` | `未开始` | - | |
| 2 | 五元组提取 | `day2/five_tuple_extractor.c` | `未开始` | - | |
| 3 | TC 流量计数器 | `day3/traffic_counter.bpf.c` | `未开始` | - | |
| 4 | 精读 XDP 程序 | `day4/obi_xdp_annotated.c` | `未开始` | - | |
| 5 | TC vs XDP 对比 | `day5/tc_vs_xdp_comparison.c` | `未开始` | - | |
| 6 | Socket Filter 研究 | `day6/obi_socket_filter_study.c` | `未开始` | - | |
| 7 | TCP 连接追踪器 | `day7/conn_tracker.bpf.c` | `未开始` | - | |

路径前缀: `exercises/week6-network/`

### Week 6 阅读的 OBI 文件

- [ ] `bpf/netolly/flows.c` — 完整精读 (TC 流追踪)
- [ ] `bpf/netolly/flows_common.h` — 流追踪公共定义
- [ ] `bpf/netolly/flow.h` — 流数据结构
- [ ] `bpf/netolly/flows_sock.c` — Socket 级别流追踪
- [ ] `bpf/rdns/rdns_xdp.c` — XDP 反向 DNS
- [ ] `bpf/common/tc_common.h` — TC 公共定义
- [ ] `bpf/common/tc_act.h` — TC 返回值

---

## Week 7: 综合实战 — HTTP 延迟追踪器

| Day | 主题 | Demo 文件 | 状态 | 日期 | 笔记/收获 |
|-----|------|----------|------|------|----------|
| 1 | 设计数据结构 | `day1/design.md` | `未开始` | - | |
| 2 | 内核态 TCP 追踪 | `day2/http_tracer.bpf.c` | `未开始` | - | |
| 3 | HTTP 协议检测 | `day3/http_detect.h` | `未开始` | - | |
| 4 | Go 加载器 | `day4/loader.go` | `未开始` | - | |
| 5 | 延迟计算 | `day5/latency_calc.go` | `未开始` | - | |
| 6 | Prometheus 导出 | `day6/metrics.go` | `未开始` | - | |
| 7 | 测试与对比 | `day7/test_and_compare.sh` | `未开始` | - | |

路径前缀: `exercises/week7-http-tracer/`

### Week 7 参考的 OBI 文件

- [ ] `bpf/generictracer/protocol_http.h` — HTTP 协议解析
- [ ] `bpf/common/http_types.h` — HTTP 类型定义
- [ ] `bpf/common/http_info.h` — HTTP 请求信息
- [ ] `pkg/export/prom/prom.go` — Prometheus 导出

---

## Week 8: 深入 OBI 项目架构

| Day | 主题 | Demo 文件 | 状态 | 日期 | 笔记/收获 |
|-----|------|----------|------|------|----------|
| 1 | Pipeline 全貌 | `day1/pipeline_study.md` | `未开始` | - | |
| 2 | Go eBPF 加载逻辑 | `day2/go_loader_study.md` | `未开始` | - | |
| 3 | 进程发现与挂载 | `day3/process_discovery_study.md` | `未开始` | - | |
| 4 | Context Propagation | `day4/context_propagation_study.md` | `未开始` | - | |
| 5 | 本地构建 OBI | `day5/build_obi.sh` | `未开始` | - | |
| 6 | 追踪自己的服务 | `day6/trace_my_service.sh` | `未开始` | - | |
| 7 | 贡献指南 | `day7/contribution_guide.md` | `未开始` | - | |

路径前缀: `exercises/week8-obi-deep-dive/`

### Week 8 阅读的 OBI 文件

- [ ] `devdocs/pipeline-map.md` — 数据流全貌
- [ ] `devdocs/context-propagation.md` — 分布式追踪上下文
- [ ] `devdocs/features.md` — 功能列表
- [ ] `devdocs/profiling.md` — 性能剖析
- [ ] `pkg/internal/appolly/appolly.go` — 核心应用追踪逻辑
- [ ] `CONTRIBUTING.md` — 贡献指南

---

## 学习笔记索引

| 文件 | 主题 | 状态 |
|------|------|------|
| `notes/c-for-ebpf.md` | eBPF 需要的 C 语言知识总结 | 已创建框架 |
| `notes/ebpf-architecture.md` | eBPF 架构和核心概念 | 待创建 |
| `notes/maps-cheatsheet.md` | Map 类型速查表 | 待创建 |
| `notes/obi-architecture.md` | OBI 项目架构分析 | 待创建 |
| `notes/kprobe-patterns.md` | Kprobe 常见模式 | 待创建 |
| `notes/uprobe-go-tricks.md` | Go 程序 Uprobe 的特殊技巧 | 待创建 |
| `notes/network-ebpf.md` | 网络相关 eBPF 编程笔记 | 待创建 |
| `notes/troubleshooting.md` | 常见问题和解决方案 | 已创建框架 |

---

## 里程碑

| 里程碑 | 预期完成 | 实际完成 | 验证标准 |
|--------|---------|---------|---------|
| 能读懂 eBPF C 代码 | Week 1 结束 | - | 能逐行解释 `flows.c` 前 60 行 |
| 第一个 eBPF 程序运行 | Week 2 Day 6 | - | kprobe 程序成功加载并输出 |
| 理解 Map 通信机制 | Week 3 结束 | - | Go 程序能读写 eBPF Map |
| 能写 kprobe 追踪程序 | Week 4 结束 | - | 独立写出文件 IO 延迟追踪 |
| 理解 OBI 的追踪原理 | Week 5 结束 | - | 能解释 OBI 如何追踪 Go HTTP |
| 理解网络数据面 eBPF | Week 6 结束 | - | 能解释 TC vs XDP 的区别和使用场景 |
| 独立完成 HTTP 追踪器 | Week 7 结束 | - | 追踪器能正确报告 HTTP 延迟 |
| 能贡献 OBI 项目 | Week 8 结束 | - | 提交第一个 PR 或详细的 Issue 分析 |

---

## 每周回顾

### Week 1 回顾 (日期: _______)

**本周完成:**
-

**最大收获:**
-

**遇到的困难:**
-

**下周计划调整:**
-

**OBI 代码阅读心得:**
-

### Week 2 回顾 (日期: _______)

**本周完成:**
-

**最大收获:**
-

**遇到的困难:**
-

**下周计划调整:**
-

### Week 3 回顾 (日期: _______)

**本周完成:**
-

**最大收获:**
-

**遇到的困难:**
-

**下周计划调整:**
-

### Week 4 回顾 (日期: _______)

**本周完成:**
-

**最大收获:**
-

**遇到的困难:**
-

**下周计划调整:**
-

### Week 5 回顾 (日期: _______)

**本周完成:**
-

**最大收获:**
-

**遇到的困难:**
-

**下周计划调整:**
-

### Week 6 回顾 (日期: _______)

**本周完成:**
-

**最大收获:**
-

**遇到的困难:**
-

**下周计划调整:**
-

### Week 7 回顾 (日期: _______)

**本周完成:**
-

**最大收获:**
-

**遇到的困难:**
-

**下周计划调整:**
-

### Week 8 回顾 (日期: _______)

**本周完成:**
-

**最大收获:**
-

**遇到的困难:**
-

**最终总结:**
-
