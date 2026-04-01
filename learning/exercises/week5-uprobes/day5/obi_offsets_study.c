// Week 5 - Day 5: OBI 偏移量机制研究
/*
=== 为什么需要偏移量? ===

Go 结构体在内存中的布局随版本变化:

  Go 1.20 的 http.Request:     Go 1.22 的 http.Request:
    offset 0:  Method             offset 0:  Method
    offset 16: URL                offset 16: URL
    offset 24: Proto              offset 24: Proto  (可能不同!)

eBPF 程序需要在编译时知道这些偏移量才能正确读取数据。

=== OBI 的偏移量管理 ===

文件: pkg/internal/goexec/offsets.json

  这个 JSON 文件记录了不同 Go 版本的偏移量:
  {
    "go1.20": {
      "net/http.Request.Method": { "offset": 0 },
      "net/http.Request.URL":    { "offset": 16 },
      ...
    }
  }

文件: bpf/gotracer/go_offsets.h

  eBPF 端通过全局变量接收偏移量:
  volatile const u64 method_ptr_pos;   // Go 用户态在加载时注入
  volatile const u64 url_ptr_pos;
  
  使用:
  void *method_ptr;
  bpf_probe_read(&method_ptr, sizeof(method_ptr), 
                  (void *)goroutine_addr + method_ptr_pos);

=== 流程 ===

  1. Go 用户态: 检测目标进程的 Go 版本
  2. Go 用户态: 从 offsets.json 查找对应版本的偏移量
  3. Go 用户态: 通过 cilium/ebpf 把偏移量注入 eBPF 全局变量
  4. eBPF 内核态: 使用注入的偏移量读取 Go 结构体

文件: pkg/internal/goexec/offsets.go — 偏移量加载逻辑

=== 练习 ===
  读 bpf/gotracer/go_offsets.h
  找到所有 volatile const 变量，理解每个偏移量的用途
*/
