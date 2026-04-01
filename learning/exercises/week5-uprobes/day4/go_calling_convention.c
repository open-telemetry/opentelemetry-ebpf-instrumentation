// Week 5 - Day 4: Go 函数调用约定 vs C
/*
=== C 调用约定 (System V AMD64 ABI) ===

  参数传递: RDI, RSI, RDX, RCX, R8, R9 (前 6 个整数参数)
  返回值:   RAX
  
  int connect(int sockfd, struct sockaddr *addr, socklen_t addrlen)
              ↑ RDI      ↑ RSI                  ↑ RDX

=== Go 调用约定 (Go 1.17+ register-based) ===

  参数传递: RAX, RBX, RCX, RDI, RSI, R8, R9, R10, R11 (顺序不同!)
  返回值:   RAX (第一个返回值)

  Go 特殊之处:
  1. Go 函数可以有多个返回值
  2. Go string 是 (ptr, len) 两个值
  3. Go interface 是 (type, value) 两个指针
  4. 不同 Go 版本的寄存器分配可能不同!

=== Go 1.16 及更早 (stack-based) ===

  所有参数通过栈传递:
  func foo(a int, b string) int
  
  栈布局:
    SP+0:  a (int, 8 bytes)
    SP+8:  b.ptr (string pointer, 8 bytes)
    SP+16: b.len (string length, 8 bytes)
    SP+24: 返回值 (int, 8 bytes)

=== OBI 的解决方案: offsets ===

  OBI 维护 pkg/internal/goexec/offsets.json
  记录每个 Go 版本中关键结构体成员的偏移量
  
  例如 net/http.Request:
    Method: offset 0   (Go string: ptr + len)
    URL:    offset 16  (pointer to url.URL)
    Header: offset 24  (map)
  
  这些偏移量在不同 Go 版本间可能变化!

=== 练习 ===
用 go tool objdump 查看你的 Go 程序的符号:
  go tool objdump -s 'main.handler' ./your_binary
*/
