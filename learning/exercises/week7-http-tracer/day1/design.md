# Week 7 - Day 1: HTTP 延迟追踪器设计

## 架构

```
  Go 用户态 (loader.go + latency_calc.go + metrics.go)
  ├── 加载 eBPF 程序
  ├── 读取 RingBuffer 事件
  ├── 计算请求延迟
  └── 暴露 Prometheus metrics
       │
  ═════╪══════════════════
       │ 内核态
  eBPF (http_tracer.bpf.c + http_detect.h)
  ├── kprobe/tcp_sendmsg → 检测 HTTP 请求/响应
  ├── kprobe/tcp_recvmsg → 记录接收
  ├── HashMap: 请求时间戳 (key=连接五元组)
  └── RingBuffer: 完整 HTTP 事件
```

## 数据结构

```c
// 连接标识 (五元组简化版)
struct conn_key {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

// HTTP 事件 (通过 RingBuffer 发送)
struct http_event {
    struct conn_key conn;
    u32 pid;
    u64 start_ns;
    u64 end_ns;
    u8  method;        // 0=GET,1=POST,2=PUT,3=DELETE
    u16 status;        // 200, 404, 500...
    char path[64];
};
```

## Map 设计

| Map | 类型 | Key | Value | 用途 |
|-----|------|-----|-------|------|
| active_requests | HASH | conn_key | request_info | 记录进行中的请求 |
| events | RINGBUF | - | http_event | 上报完整事件 |

## Prometheus Metrics

- `http_request_duration_seconds` (histogram) — 请求延迟分布
- `http_requests_total` (counter) — 请求总数，按 method/status 标签
