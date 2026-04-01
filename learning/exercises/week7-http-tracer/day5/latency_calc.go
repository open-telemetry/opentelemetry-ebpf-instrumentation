// Week 7 - Day 5: 延迟计算模块
package main

import "fmt"

// HTTPRequest 表示一个完成的 HTTP 请求
type HTTPRequest struct {
	Method     string
	Path       string
	StatusCode int
	DurationNs uint64
	PID        uint32
	Comm       string
}

// CalculateLatency 从原始事件计算延迟
func CalculateLatency(startNs, endNs uint64) uint64 {
	if endNs <= startNs {
		return 0
	}
	return endNs - startNs
}

// DurationToMs 纳秒转毫秒
func DurationToMs(ns uint64) float64 {
	return float64(ns) / 1_000_000.0
}

func main() {
	// 示例: 模拟计算
	req := HTTPRequest{
		Method:     "GET",
		Path:       "/api/v1/users",
		StatusCode: 200,
		DurationNs: 15_000_000, // 15ms
		PID:        12345,
		Comm:       "my-service",
	}

	fmt.Printf("HTTP %s %s → %d (%.2f ms) [pid=%d %s]\n",
		req.Method, req.Path, req.StatusCode,
		DurationToMs(req.DurationNs), req.PID, req.Comm)
}
