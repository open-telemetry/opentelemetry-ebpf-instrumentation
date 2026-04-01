// Week 5 - Day 3: 精读 OBI 的 Go HTTP 追踪 (bpf/gotracer/go_nethttp.c)
/*
=== Go HTTP 追踪的特殊挑战 ===

1. Go 是静态链接的，不经过 libc
   → 不能用 uprobe/libc，必须直接挂到 Go 二进制的符号上

2. Go 用寄存器传参 (Go 1.17+)，不是 C 的 ABI
   → 参数位置不同，需要知道每个 Go 版本的偏移量

3. Go 的 string 是 (ptr, len) 对，不是 C 的 null-terminated
   → 需要分别读取指针和长度

OBI 追踪 Go HTTP 的关键 uprobe:

服务端:
  SEC("uprobe/ServeHTTP")           → 处理 HTTP 请求入口
  SEC("uprobe/ServeHTTP_ret")       → 处理完成，计算延迟
  SEC("uprobe/readRequest")         → 读取 HTTP 请求头
  SEC("uprobe/readMimeHeader")      → 读取 MIME 头部

客户端:
  SEC("uprobe/roundTrip")           → HTTP 客户端发送请求
  SEC("uprobe/roundTrip_return")    → 客户端收到响应

Go string 读取:
  // Go string 在内存中: [ptr(8 bytes)][len(8 bytes)]
  void *str_ptr;
  u64 str_len;
  bpf_probe_read(&str_ptr, sizeof(str_ptr), go_str_addr);
  bpf_probe_read(&str_len, sizeof(str_len), go_str_addr + 8);
  bpf_probe_read_user(buf, min(str_len, BUF_SIZE), str_ptr);

=== 练习 ===
读 bpf/gotracer/go_nethttp.c 并回答:
Q1: OBI 如何知道 HTTP 方法 (GET/POST) 在 Go Request 结构体的哪个偏移量?
Q2: 为什么 OBI 需要 go_offsets.h?
*/
