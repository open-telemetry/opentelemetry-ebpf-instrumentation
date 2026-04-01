// Week 7 - Day 4: Go 加载器 — 加载 eBPF 程序并读取 RingBuffer
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// 实际使用时取消注释:
// //go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 tracer ../day2/http_tracer.bpf.c

func main() {
	fmt.Println("=== HTTP Latency Tracer ===")
	fmt.Println("Day 4 模板: 加载 eBPF 程序并读取 RingBuffer")
	fmt.Println("")
	fmt.Println("完整实现步骤:")
	fmt.Println("  1. rlimit.RemoveMemlock()")
	fmt.Println("  2. loadTracerObjects() 加载 eBPF 程序")
	fmt.Println("  3. link.Kprobe('tcp_sendmsg', objs.TraceTcpSend)")
	fmt.Println("  4. ringbuf.NewReader(objs.Events)")
	fmt.Println("  5. 循环读取事件: reader.Read()")
	fmt.Println("  6. 解析事件结构体，传给 latency_calc")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("退出")
}
