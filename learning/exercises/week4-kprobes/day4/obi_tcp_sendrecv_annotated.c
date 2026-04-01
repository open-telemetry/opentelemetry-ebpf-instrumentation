// Week 4 - Day 4: 精读 OBI 的 tcp_sendmsg / tcp_recvmsg 探针
// 对照 bpf/generictracer/k_tracer.c 的 TCP 收发追踪

/*
=== OBI 的 TCP 追踪策略 ===

OBI 通过追踪 TCP 收发来捕获 HTTP/gRPC/SQL 等应用层协议:

  tcp_sendmsg → 应用发送数据 (请求或响应)
  tcp_recvmsg → 应用接收数据 (请求或响应)

数据流:
  Client                          Server
    │ connect()                      │
    │─── tcp_sendmsg ──────────────→ │ tcp_recvmsg (收到请求)
    │                                │ 处理请求...
    │ tcp_recvmsg (收到响应) ←────── │ tcp_sendmsg
    │                                │

=== tcp_sendmsg kprobe ===

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(obi_kprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {

  参数:
    sk   — TCP socket，包含连接五元组
    msg  — 要发送的消息 (包含应用数据)
    size — 发送数据的大小

  OBI 在这里做什么:
    1. valid_pid 检查
    2. 从 sk 提取连接信息 (src_ip, dst_ip, src_port, dst_port)
    3. 记录发送时间戳: bpf_ktime_get_ns()
    4. 读取 msg 缓冲区的前 N 字节来判断协议:
       - "GET ", "POST ", "PUT ", "DELETE " → HTTP
       - 特殊帧头 → HTTP/2 / gRPC
       - 特定字节模式 → MySQL / PostgreSQL / Kafka
    5. 把信息存入 Map (ongoing_http, ongoing_tcp_req 等)

=== tcp_recvmsg kprobe ===

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(obi_kprobe_tcp_recvmsg, struct sock *sk, struct msghdr *msg, ...) {

  OBI 在这里做什么:
    1. valid_pid 检查
    2. 记录接收开始时间
    3. 存入 active_recv_args Map (等 kretprobe 时读取数据)

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(obi_kretprobe_tcp_recvmsg, int copied_len) {

  OBI 在这里做什么:
    1. 从 active_recv_args 取出数据
    2. 读取接收缓冲区内容判断协议
    3. 匹配之前的请求 (通过 connection_info 作为 key)
    4. 计算延迟 = 响应时间 - 请求时间
    5. 通过 RingBuffer 上报完整事件 (请求方法/路径/状态码/延迟)

=== 协议检测逻辑 ===

来自 bpf/generictracer/protocol_http.h:

  判断是否是 HTTP 请求:
    buf[0]=='G' && buf[1]=='E' && buf[2]=='T' && buf[3]==' '  → GET
    buf[0]=='P' && buf[1]=='O' && buf[2]=='S' && buf[3]=='T'  → POST
    buf[0]=='H' && buf[1]=='T' && buf[2]=='T' && buf[3]=='P'  → HTTP 响应

  判断是否是 HTTP/2 (来自 protocol_http2.h):
    检查 HTTP/2 魔术字节: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    或检查 HTTP/2 帧头格式

  判断是否是 MySQL (来自 protocol_mysql.h):
    检查 MySQL 协议的包头格式

=== 学习练习 ===

阅读以下文件并回答:

Q1: OBI 在 tcp_sendmsg 中最多读取多少字节来判断协议?
    提示: 看 K_TCP_MAX_LEN 的定义

Q2: 为什么 tcp_recvmsg 需要 kprobe + kretprobe，而 tcp_sendmsg 只需要 kprobe?
    提示: sendmsg 的数据在调用时就准备好了，recvmsg 的数据在返回时才可用

Q3: OBI 如何关联请求和响应? 用什么作为 key?
    提示: 看 connection_info_t 结构体
*/
