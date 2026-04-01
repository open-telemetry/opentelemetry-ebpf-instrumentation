// Week 2 - Day 6: Go 用户态程序 — 用 cilium/ebpf 加载 eBPF 程序
// 主题: 用 Go 加载昨天写的 eBPF 程序，读取输出
//
// 前置: 确保 Day 4 的环境已搭建，Day 5 的 eBPF C 程序已编译
//
// 构建步骤:
//   1. go mod init hello-ebpf
//   2. go get github.com/cilium/ebpf
//   3. go generate ./...   (会调用 bpf2go 编译 C 程序)
//   4. go build -o hello-ebpf . && sudo ./hello-ebpf

package main

// 使用 bpf2go 在编译时将 eBPF C 程序编译为 Go 代码
// 这行注释是 go generate 指令:
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 hello ../day5/hello_openat.bpf.c

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// 步骤 1: 移除内存锁定限制 (eBPF 需要锁定内存)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("移除 memlock 限制失败: %v", err)
	}

	// 步骤 2: 加载编译好的 eBPF 程序
	// helloObjects 是 bpf2go 自动生成的结构体
	objs := helloObjects{}
	if err := loadHelloObjects(&objs, nil); err != nil {
		log.Fatalf("加载 eBPF 对象失败: %v", err)
	}
	defer objs.Close()

	// 步骤 3: 将 eBPF 程序挂载到 kprobe
	kp, err := link.Kprobe("sys_openat", objs.HelloOpenat, nil)
	if err != nil {
		log.Fatalf("挂载 kprobe 失败: %v", err)
	}
	defer kp.Close()

	fmt.Println("eBPF 程序已加载！正在追踪 sys_openat...")
	fmt.Println("查看输出: sudo cat /sys/kernel/debug/tracing/trace_pipe")
	fmt.Println("按 Ctrl+C 退出")

	// 步骤 4: 等待退出信号
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\n已退出")
}

/*
=== 对比 OBI 的 Go 用户态 ===

OBI 使用 cilium/ebpf 的方式更复杂:

1. 程序发现: ProcessWatcher 自动发现目标进程
2. 动态挂载: TraceAttacher 为每个进程动态挂载 uprobe/kprobe
3. 事件读取: 从 RingBuffer 读取结构化事件 (不是 trace_pipe)
4. 数据处理: 解析事件 → 装饰 → 导出到 OTEL/Prometheus

我们的 Hello World:
  编译 C → 加载 → 挂载 kprobe → 读 trace_pipe

OBI 的完整流程:
  发现进程 → 编译 C → 加载 → 挂载 kprobe+uprobe → 读 RingBuffer → 解析 → 导出

=== 运行效果 ===

终端 1:
  $ sudo ./hello-ebpf
  eBPF 程序已加载！正在追踪 sys_openat...

终端 2:
  $ sudo cat /sys/kernel/debug/tracing/trace_pipe
  hello-ebpf-12345 [000] ... Hello eBPF! pid=12345 comm=cat
  bash-67890 [001] ... Hello eBPF! pid=67890 comm=bash

*/
