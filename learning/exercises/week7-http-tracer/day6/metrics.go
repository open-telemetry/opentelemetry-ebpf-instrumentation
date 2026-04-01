// Week 7 - Day 6: Prometheus metrics 导出
package main

import "fmt"

// 实际使用时引入:
// import (
//     "github.com/prometheus/client_golang/prometheus"
//     "github.com/prometheus/client_golang/prometheus/promhttp"
// )

// Prometheus 指标定义模板:
//
// var httpDuration = prometheus.NewHistogramVec(
//     prometheus.HistogramOpts{
//         Name:    "http_request_duration_seconds",
//         Help:    "HTTP request latency distributions",
//         Buckets: prometheus.DefBuckets,
//     },
//     []string{"method", "status_code", "path"},
// )
//
// var httpTotal = prometheus.NewCounterVec(
//     prometheus.CounterOpts{
//         Name: "http_requests_total",
//         Help: "Total HTTP requests",
//     },
//     []string{"method", "status_code"},
// )

func main() {
	fmt.Println("=== Prometheus Metrics 导出 ===")
	fmt.Println("Day 6 模板: 暴露 HTTP 延迟直方图")
	fmt.Println("")
	fmt.Println("指标:")
	fmt.Println("  http_request_duration_seconds{method,status_code,path}")
	fmt.Println("  http_requests_total{method,status_code}")
	fmt.Println("")
	fmt.Println("参考 OBI: pkg/export/prom/prom.go")
}
