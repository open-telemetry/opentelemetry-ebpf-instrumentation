#!/bin/bash
# Week 8 - Day 6: 使用 OBI 追踪你自己的服务
# 运行: bash trace_my_service.sh
# 前提: OBI 已构建，有一个运行中的 HTTP 服务

set -e

echo "================================================"
echo "  使用 OBI 追踪你自己的服务"
echo "================================================"

# ==========================================
# Step 1: 准备一个测试服务
# ==========================================
echo ""
echo "=== Step 1: 准备测试服务 ==="
echo ""
echo "如果你还没有测试服务，可以用这个简单的 Go HTTP 服务:"
echo ""

# 创建临时测试服务
TEST_SERVICE="/tmp/test_http_server.go"
cat > "$TEST_SERVICE" << 'GOCODE'
package main

import (
    "fmt"
    "math/rand"
    "net/http"
    "time"
)

func main() {
    http.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
        // 模拟处理延迟 (1-50ms)
        time.Sleep(time.Duration(rand.Intn(50)+1) * time.Millisecond)
        w.WriteHeader(200)
        fmt.Fprintf(w, `{"users": [{"id": 1, "name": "Alice"}]}`)
    })

    http.HandleFunc("/api/orders", func(w http.ResponseWriter, r *http.Request) {
        // 模拟较慢的处理 (10-200ms)
        time.Sleep(time.Duration(rand.Intn(200)+10) * time.Millisecond)
        w.WriteHeader(200)
        fmt.Fprintf(w, `{"orders": []}`)
    })

    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(200)
        fmt.Fprintf(w, "ok")
    })

    http.HandleFunc("/api/error", func(w http.ResponseWriter, r *http.Request) {
        // 模拟错误
        time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
        w.WriteHeader(500)
        fmt.Fprintf(w, `{"error": "internal server error"}`)
    })

    fmt.Println("Test HTTP server listening on :8080")
    fmt.Println("Endpoints: /api/users, /api/orders, /health, /api/error")
    http.ListenAndServe(":8080", nil)
}
GOCODE

echo "  测试服务已写入: $TEST_SERVICE"
echo ""
echo "  启动测试服务:"
echo "    go run $TEST_SERVICE &"
echo ""

# ==========================================
# Step 2: 生成测试流量
# ==========================================
echo "=== Step 2: 生成测试流量 ==="
echo ""

LOAD_GEN="/tmp/load_generator.sh"
cat > "$LOAD_GEN" << 'LOADGEN'
#!/bin/bash
# 简单的流量生成器
echo "开始生成测试流量 (按 Ctrl+C 停止)..."

ENDPOINTS=(
    "http://localhost:8080/api/users"
    "http://localhost:8080/api/orders"
    "http://localhost:8080/health"
    "http://localhost:8080/api/error"
)

# 请求权重: users 多, error 少
WEIGHTS=(40 30 20 10)

count=0
while true; do
    # 按权重选择 endpoint
    r=$((RANDOM % 100))
    if [ $r -lt 40 ]; then
        idx=0
    elif [ $r -lt 70 ]; then
        idx=1
    elif [ $r -lt 90 ]; then
        idx=2
    else
        idx=3
    fi

    url="${ENDPOINTS[$idx]}"

    # 随机选择 HTTP 方法
    if [ $((RANDOM % 3)) -eq 0 ]; then
        method="POST"
    else
        method="GET"
    fi

    status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$url" 2>/dev/null)
    count=$((count + 1))

    if [ $((count % 10)) -eq 0 ]; then
        echo "  已发送 $count 个请求 (最近: $method $url → $status)"
    fi

    # 随机间隔 50-200ms
    sleep 0.$(printf '%03d' $((RANDOM % 150 + 50)))
done
LOADGEN
chmod +x "$LOAD_GEN"

echo "  流量生成器已写入: $LOAD_GEN"
echo "  启动: bash $LOAD_GEN &"
echo ""

# ==========================================
# Step 3: 启动 OBI
# ==========================================
echo "=== Step 3: 启动 OBI ==="
echo ""

OBI_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo '.')"

cat << 'INSTRUCTIONS'
  方式 A: 直接运行 (开发模式)

    sudo ./obi \
      --config config.yaml \
      --print-traces        # 打印到终端

  方式 B: 使用 Docker Compose (推荐)

    docker compose up
    # 包含: OBI + OTEL Collector + Jaeger UI
    # Jaeger UI: http://localhost:16686

  方式 C: 使用 Kubernetes

    kubectl apply -f deploy/kubernetes/
    # OBI 以 DaemonSet 运行
    # 自动追踪所有 Pod

  最小配置 (config.yaml):
INSTRUCTIONS

echo ""
echo "  # config.yaml"
echo "  ---"
echo "  log_level: debug"
echo "  ebpf:"
echo "    enable_kprobes: true"
echo "    enable_uprobes: true"
echo "  discovery:"
echo "    services:"
echo "      - name: test-server"
echo "        namespace: default"
echo "  export:"
echo "    type: otel"
echo "    endpoint: localhost:4317"

# ==========================================
# Step 4: 观察追踪结果
# ==========================================
echo ""
echo "=== Step 4: 观察追踪结果 ==="
echo ""

cat << 'OBSERVE'
  1. 终端输出 (如果用了 --print-traces):

     Trace: abc-123
       Span: GET /api/users → 200 (12ms)
       Span: POST /api/orders → 200 (145ms)
       Span: GET /api/error → 500 (67ms)

  2. Jaeger UI (http://localhost:16686):
     - 选择 Service: test-server
     - 查看 Trace 列表
     - 点击查看 Span 详情
     - 查看延迟直方图

  3. Prometheus Metrics (http://localhost:9090):

     # 请求延迟直方图
     histogram_quantile(0.99,
       rate(http_request_duration_seconds_bucket[5m])
     )

     # 请求速率
     rate(http_requests_total[5m])

     # 错误率
     rate(http_requests_total{status_code=~"5.."}[5m])
     /
     rate(http_requests_total[5m])
OBSERVE

# ==========================================
# Step 5: 验证和调试
# ==========================================
echo ""
echo "=== Step 5: 验证和调试 ==="
echo ""

cat << 'DEBUG'
  如果没有看到追踪数据，检查:

  1. eBPF 程序是否加载成功?
     sudo bpftool prog list | grep obi

  2. kprobe 是否挂载?
     sudo cat /sys/kernel/debug/tracing/kprobe_events

  3. Map 中是否有数据?
     sudo bpftool map dump name events | head

  4. 目标进程的 PID 是否被发现?
     sudo bpftool map dump name valid_pids

  5. 查看 OBI 日志:
     journalctl -u obi -f  # 如果是 systemd 服务
     docker logs obi -f    # 如果是 Docker

  6. 查看 trace_pipe (原始 bpf_printk 输出):
     sudo cat /sys/kernel/debug/tracing/trace_pipe
DEBUG

# ==========================================
# Step 6: 对比分析
# ==========================================
echo ""
echo "=== Step 6: 对比你之前写的工具 ==="
echo ""

cat << 'COMPARE'
  对比 Week 7 你自己写的 HTTP Tracer 与 OBI:

  ┌──────────────────┬─────────────────┬──────────────────┐
  │  特性             │ 你的 Tracer      │ OBI              │
  ├──────────────────┼─────────────────┼──────────────────┤
  │ 协议支持          │ HTTP 1.x        │ HTTP/gRPC/SQL/.. │
  │ 进程发现          │ 手动指定 PID     │ 自动发现          │
  │ uprobe           │ 无              │ SSL/Go/...       │
  │ 导出格式          │ Prometheus      │ OTEL + Prometheus│
  │ Context 传播      │ 无              │ W3C traceparent  │
  │ 生产环境          │ 不适合          │ 可以             │
  │ 代码量            │ ~200 行         │ ~50000+ 行       │
  └──────────────────┴─────────────────┴──────────────────┘

  思考:
  - OBI 的哪些设计让你印象深刻?
  - 你的 Tracer 还能改进什么?
  - 如果重新设计，你会怎么做?
COMPARE

echo ""
echo "================================================"
echo "  追踪指南完成！"
echo "  享受你的 eBPF 之旅！"
echo "================================================"
