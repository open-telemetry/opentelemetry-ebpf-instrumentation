// Week 5 - Day 2: 精读 OBI 的 SSL 追踪 (bpf/generictracer/libssl.c)
/*
=== SSL 追踪原理 ===

  应用程序                  libssl.so                 网络
  ┌────────┐  明文数据  ┌──────────┐  加密数据  ┌──────┐
  │  App   │──────────→│ SSL_write │──────────→│  TCP  │
  │        │←──────────│ SSL_read  │←──────────│      │
  └────────┘  明文数据  └──────────┘  加密数据  └──────┘
                 ↑                        ↑
            OBI 在这里抓    tcpdump 在这里抓
            (明文!)          (密文,看不懂)

OBI 的 uprobe 挂在 SSL_read/SSL_write 的入口和出口:
  - 入口 (uprobe): 记录 buf 指针和 ssl 上下文
  - 出口 (uretprobe): 读取 buf 内容 (此时已填充明文数据)

来自 libssl.c 的核心代码:

  SEC("uprobe/libssl.so:SSL_read")
  int BPF_UPROBE(obi_uprobe_ssl_read, void *ssl, const void *buf, int num) {
      // ssl = SSL 连接上下文
      // buf = 接收缓冲区指针 (此时还是空的!)
      // num = 缓冲区大小

      ssl_args_t args = {};
      args.buf = (u64)buf;    // 记住缓冲区地址
      args.ssl = (u64)ssl;    // 记住 SSL 上下文

      // 存入 Map，等 uretprobe 时读取
      bpf_map_update_elem(&active_ssl_read_args, &id, &args, BPF_ANY);
  }

  SEC("uretprobe/libssl.so:SSL_read")
  int BPF_URETPROBE(obi_uretprobe_ssl_read, int ret) {
      // ret = 实际读取的字节数
      // 此时 buf 中已经有明文数据了!

      // 从 Map 取出之前保存的 buf 地址
      // 用 bpf_probe_read_user() 读取 buf 内容
      // 检测 HTTP 协议，提取请求/响应信息
  }

=== 练习 ===
Q1: 为什么 uprobe 时不直接读 buf? 因为此时 buf 还是空的!
Q2: 为什么需要 ssl 指针? 用来关联连接信息，通过 ssl_to_conn Map
*/
