// Week 6 - Day 6: Socket Filter 研究
/*
来自 OBI k_tracer.c:
  SEC("socket/http_filter")

Socket Filter 的作用:
  - 附加到一个 socket 上
  - 每个通过该 socket 的数据包都会触发
  - 可以读取数据包内容 (看到 HTTP 明文!)
  - 可以决定是否传递给应用 (过滤)

OBI 用 Socket Filter 做 HTTP 协议检测:
  1. 创建一个原始 socket 监听网络
  2. 附加 eBPF socket filter
  3. filter 检查每个包的前几个字节
  4. 匹配 "GET ", "POST ", "HTTP/1." 等模式
  5. 把 HTTP 信息存入 Map

与 kprobe tcp_recvmsg 的区别:
  kprobe: 追踪函数调用，能看到哪个进程在操作
  socket filter: 追踪数据包，性能更好但不知道进程

=== 练习 ===
在 k_tracer.c 中找到 SEC("socket/http_filter") 部分
理解它如何检测 HTTP 协议
*/
