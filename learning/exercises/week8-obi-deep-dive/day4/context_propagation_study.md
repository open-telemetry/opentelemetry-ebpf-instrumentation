# Week 8 - Day 4: OpenTelemetry Context Propagation 学习

## 学习目标
理解 OBI 如何将 eBPF 事件转化为符合 OTEL 标准的 Trace/Span。

## OpenTelemetry 基础概念

### Trace 和 Span

```
一次完整的用户请求 = 一个 Trace

Trace: abc-123
├── Span: Client → Gateway (10ms)
│   └── Span: Gateway → UserService (8ms)
│       ├── Span: UserService → DB (3ms)
│       └── Span: UserService → Cache (1ms)
└── 总耗时: 10ms

每个 Span 包含:
  - TraceID: 全局唯一的追踪 ID (128-bit)
  - SpanID: 当前 Span 的 ID (64-bit)
  - ParentSpanID: 父 Span 的 ID
  - 操作名: "GET /api/users"
  - 开始时间 + 持续时间
  - 属性 (Attributes): key-value 对
  - 事件 (Events): 时间点日志
  - 状态 (Status): OK, ERROR
```

### OTEL 标准属性

```
HTTP Span 的标准属性:
  http.method        = "GET"
  http.url           = "/api/users"
  http.status_code   = 200
  http.scheme        = "http"
  net.peer.ip        = "10.0.0.1"
  net.peer.port      = 8080
  service.name       = "user-service"
  service.namespace  = "production"
```

## OBI 的 Context Propagation

### 挑战: eBPF 没有 Trace Context

传统的分布式追踪:
```
Client → Server
  HTTP Header 携带: traceparent: 00-abc123-def456-01
  Server 读取 header，创建子 Span
```

OBI 的 eBPF 追踪:
```
Client → Server
  eBPF 在内核层捕获 TCP 数据
  问题: 如何获取 HTTP header 中的 trace context?
```

### OBI 的解决方案

```
方案 1: 从 TCP 数据中提取 Trace Context
  ├── 在 kprobe/tcp_recvmsg 中读取数据缓冲区
  ├── 解析 HTTP header
  ├── 找到 "traceparent:" header
  └── 提取 TraceID 和 ParentSpanID

方案 2: 生成新的 Trace Context
  ├── 如果没有找到传入的 context
  ├── OBI 自动生成 TraceID
  └── 创建根 Span (root span)

方案 3: 混合模式
  ├── 有传入 context → 关联到现有 Trace
  └── 没有 context → 创建新 Trace
```

### W3C Trace Context 格式

```
HTTP Header:
  traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
               ^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^  ^^
               |   TraceID (32 hex = 128-bit)        SpanID (16 hex)  Flags
               Version                                                (01=sampled)
```

### OBI 中的提取逻辑

```c
// 在 eBPF 程序中搜索 traceparent header
// 简化版伪代码

static __always_inline int extract_trace_context(
    const char *buf, int len, struct trace_context *ctx) {
    
    // 在 HTTP header 中搜索 "traceparent:"
    for (int i = 0; i < len - 55; i++) {
        if (buf[i] == 't' && buf[i+1] == 'r' && buf[i+2] == 'a' &&
            /* ... "traceparent: " ... */ ) {
            
            // 解析 version-traceid-spanid-flags
            parse_hex(buf + i + 14, 32, ctx->trace_id);
            parse_hex(buf + i + 47, 16, ctx->span_id);
            ctx->flags = parse_hex_byte(buf + i + 64);
            
            return 1; // 找到了
        }
    }
    return 0; // 没找到
}
```

## 从 eBPF 事件到 OTEL Span

### 内核态采集的数据

```c
// eBPF 事件结构体 (通过 RingBuffer 传递)
struct http_event {
    // 连接信息
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    
    // 时间信息
    u64 start_ns;      // 请求开始时间
    u64 end_ns;        // 响应完成时间
    
    // HTTP 信息
    u8  method;         // GET=1, POST=2, ...
    u16 status;         // 200, 404, 500, ...
    char path[128];     // "/api/users"
    
    // Trace Context (如果有)
    u8 trace_id[16];
    u8 parent_span_id[8];
    u8 has_trace_context;
    
    // 进程信息
    u32 pid;
    char comm[16];      // 进程名
};
```

### Go 用户态转换

```go
// 将 eBPF 事件转换为 OTEL Span
func eventToSpan(event *HTTPEvent) trace.ReadOnlySpan {
    // 1. 确定 TraceID
    var traceID trace.TraceID
    if event.HasTraceContext {
        // 使用传入的 Trace Context
        copy(traceID[:], event.TraceID[:])
    } else {
        // 生成新的 TraceID
        traceID = generateTraceID()
    }
    
    // 2. 生成 SpanID
    spanID := generateSpanID()
    
    // 3. 确定 ParentSpanID
    var parentSpanID trace.SpanID
    if event.HasTraceContext {
        copy(parentSpanID[:], event.ParentSpanID[:])
    }
    // 没有 parent 则为 root span
    
    // 4. 构建 Span
    span := &exportedSpan{
        TraceID:    traceID,
        SpanID:     spanID,
        ParentID:   parentSpanID,
        Name:       fmt.Sprintf("%s %s", event.Method, event.Path),
        Start:      bootTimeToWallClock(event.StartNs),
        End:        bootTimeToWallClock(event.EndNs),
        Kind:       trace.SpanKindServer,
        Attributes: []attribute.KeyValue{
            semconv.HTTPMethodKey.String(event.Method),
            semconv.HTTPURLKey.String(event.Path),
            semconv.HTTPStatusCodeKey.Int(int(event.Status)),
            semconv.NetPeerIPKey.String(event.SrcIP),
            semconv.NetPeerPortKey.Int(int(event.SrcPort)),
            attribute.String("service.name", event.ServiceName),
        },
        Status: statusFromHTTP(event.Status),
    }
    
    return span
}
```

### 时间戳转换

```go
// eBPF 使用 bpf_ktime_get_ns() (boot time)
// OTEL 需要 wall clock time

func bootTimeToWallClock(bootNs uint64) time.Time {
    // 计算 boot time 与 wall clock 的偏移量
    // offset = wall_clock_now - boot_time_now
    // wall_clock = boot_time + offset
    
    bootNow := unix.ClockGettime(unix.CLOCK_BOOTTIME)
    wallNow := time.Now()
    offset := wallNow.UnixNano() - bootNow.Nsec
    
    return time.Unix(0, int64(bootNs) + offset)
}
```

## 导出到 OTEL Collector

```go
// 创建 OTEL Exporter
func setupExporter() trace.SpanExporter {
    exporter, err := otlptracegrpc.New(context.Background(),
        otlptracegrpc.WithEndpoint("otel-collector:4317"),
        otlptracegrpc.WithInsecure(),
    )
    return exporter
}

// 批量导出 Span
func exportSpans(exporter trace.SpanExporter, spans []trace.ReadOnlySpan) {
    err := exporter.ExportSpans(context.Background(), spans)
    if err != nil {
        log.Printf("export failed: %v", err)
    }
}
```

## 练习任务

### TODO 1: 查找 OBI 的 Trace Context 提取代码
```bash
grep -r "traceparent\|trace_context\|TraceID" --include="*.c" --include="*.h" .
```

### TODO 2: 查找 Span 构建逻辑
```bash
grep -r "SpanKind\|NewSpan\|ExportSpans\|ReadOnlySpan" --include="*.go" .
```

### TODO 3: 理解时间戳转换
```bash
grep -r "CLOCK_BOOTTIME\|boottime\|ktime_get_ns" --include="*.go" .
```

### TODO 4: 查看 OTEL 导出配置
```bash
grep -r "otlp\|otel.*collector\|ExporterConfig" --include="*.go" .
```

## 关键概念总结

| 概念 | 说明 |
|------|------|
| TraceID | 128-bit，标识一次完整请求链 |
| SpanID | 64-bit，标识链中的一个操作 |
| ParentSpanID | 关联父子 Span |
| W3C traceparent | 标准传播格式 |
| Boot Time vs Wall Clock | eBPF 时间 vs 人类时间 |
| Sampling | 采样策略 (全量/概率/基于头部) |

## 参考文件

| 文件 | 内容 |
|------|------|
| `pkg/export/` | OTEL 导出逻辑 |
| `bpf/common/trace_context.h` | Trace Context 提取 (如存在) |
| W3C Trace Context 规范 | https://www.w3.org/TR/trace-context/ |
| OTEL Go SDK 文档 | https://opentelemetry.io/docs/languages/go/ |
