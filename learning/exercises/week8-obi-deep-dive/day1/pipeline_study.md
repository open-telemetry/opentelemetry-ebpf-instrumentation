# Week 8 - Day 1: OBI Pipeline 架构深度学习

## 学习目标
精读 `devdocs/pipeline-map.md`，理解 OBI 从内核事件到 OTEL Span 的完整数据流。

## OBI Pipeline 总览

```
  eBPF 内核态                    Go 用户态                     外部
┌──────────────┐           ┌──────────────────┐          ┌──────────┐
│  kprobe/     │           │  RingBuffer      │          │ OTEL     │
│  uprobe/     │──Ring──→  │  Reader          │──HTTP──→ │ Collector│
│  TC/XDP      │  Buffer   │    ↓             │          └──────────┘
│              │           │  Protocol        │
│  协议检测     │           │  Parser          │          ┌──────────┐
│  PID 过滤     │           │    ↓             │          │Prometheus│
│  连接追踪     │           │  Span Builder    │──────→   │ Metrics  │
└──────────────┘           │    ↓             │          └──────────┘
                           │  OTEL Exporter   │
                           └──────────────────┘
```

## 关键阶段分析

### Stage 1: 内核事件采集

**涉及文件:**
- `bpf/generictracer/k_tracer.c` — kprobe 探针
- `bpf/generictracer/libssl.c` — SSL uprobe 探针
- `bpf/netolly/flows.c` — TC 网络流量

**核心 Map:**
```
events RingBuffer    ← 存放完整的请求/响应事件
ongoing_http HashMap ← 正在进行的 HTTP 请求
ongoing_tcp  HashMap ← 正在进行的 TCP 连接
active_*     HashMap ← kprobe/kretprobe 之间的数据传递
```

**数据流向:**
1. kprobe 捕获函数调用 → 存入 active_* Map
2. kretprobe 捕获返回 → 从 active_* 取出数据
3. 协议检测 → 识别 HTTP/gRPC/SQL
4. 组装完整事件 → 写入 RingBuffer

### Stage 2: 用户态读取

**涉及文件:**
- `pkg/ebpf/tracer.go` — eBPF 程序加载和管理
- `pkg/ebpf/reader.go` — RingBuffer 读取

**流程:**
```go
// 伪代码
reader := ringbuf.NewReader(objs.Events)
for {
    record, err := reader.Read()  // 阻塞等待内核事件
    event := parseEvent(record)   // 解析二进制数据
    pipeline.Send(event)          // 发送到处理管道
}
```

### Stage 3: 协议解析和 Span 构建

**涉及文件:**
- `pkg/export/` — 导出相关代码

**流程:**
```
原始事件 → 协议解析 → HTTP Request 对象
    ↓
Method: GET
Path: /api/users
Status: 200
Latency: 15ms
    ↓
构建 OTEL Span:
  - service.name = "my-app"
  - http.method = "GET"
  - http.url = "/api/users"
  - http.status_code = 200
  - duration = 15ms
```

### Stage 4: 导出

**两种导出路径:**

1. **OTEL Traces** → OTEL Collector → Jaeger/Tempo
   - 每个 HTTP 请求 = 一个 Span
   - 包含完整的 trace context

2. **Prometheus Metrics** → /metrics endpoint → Prometheus
   - http_request_duration_seconds (histogram)
   - http_requests_total (counter)
   - 按 service/method/status 分组

## 练习任务

### TODO 1: 阅读 pipeline-map.md
```bash
cat devdocs/pipeline-map.md
```
记录你不理解的地方。

### TODO 2: 追踪一个 HTTP 请求的完整路径

从 kprobe 到 OTEL Span，列出经过的所有函数:

1. `tcp_recvmsg` kprobe 触发
2. ??? (填写中间步骤)
3. OTEL Span 导出

### TODO 3: 理解 Map 的生命周期

对于 `ongoing_http` Map:
- 什么时候写入？(哪个探针？)
- 什么时候读取？(哪个探针？)
- 什么时候删除？(请求完成还是超时？)

### TODO 4: 画出你自己的架构图

用任何工具(纸笔、draw.io、ASCII art)画出 OBI 的数据流。
重点标注:
- [ ] 内核态和用户态的边界
- [ ] 数据通过哪些 Map 传递
- [ ] 协议检测发生在哪里(内核态还是用户态)

## 参考文件

| 文件 | 内容 |
|------|------|
| `devdocs/pipeline-map.md` | 官方 pipeline 文档 |
| `pkg/ebpf/tracer.go` | Go 加载器入口 |
| `bpf/generictracer/k_tracer.c` | 内核探针 |
| `bpf/common/ringbuf.h` | RingBuffer 定义 |

## 关键概念

- **RingBuffer vs PerfBuffer**: OBI 使用 RingBuffer (BPF_MAP_TYPE_RINGBUF)
  - RingBuffer: 共享内存，多 CPU 共用，自动排序
  - PerfBuffer: 每 CPU 一个缓冲区，需要用户态合并
  - RingBuffer 更适合高频事件，OBI 选择它是因为简化了用户态代码

- **Wakeup 优化**: 不是每个事件都唤醒用户态
  - `get_flags()` 函数控制是否设置 BPF_RB_FORCE_WAKEUP
  - 减少内核到用户态的上下文切换
