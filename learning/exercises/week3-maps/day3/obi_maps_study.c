// ============================================================================
// Week 3 Day 3: OBI bpf/maps/ 目录研读指南
// ============================================================================
//
// 这不是可编译的代码！这是一份学习笔记/研读指南。
// 目的: 系统性地理解 OBI 项目中每个 Map 文件的用途和设计模式。
//
// OBI 的 bpf/maps/ 目录是整个项目数据架构的核心。
// 每个 .h 文件定义一个或多个 BPF Map，这些 Map 构成了
// OBI 在内核态收集可观测性数据的"数据库"。
//
// ============================================================================

// ============================================================================
// 一、OBI Map 定义的统一模式
// ============================================================================
//
// OBI 中所有 Map 都遵循相同的定义模式:
//
//   struct {
//       __uint(type, BPF_MAP_TYPE_XXX);                // Map类型
//       __type(key, some_key_t);                        // Key类型
//       __type(value, some_value_t);                    // Value类型
//       __uint(max_entries, MAX_CONCURRENT_REQUESTS);   // 最大条目数
//       __uint(pinning, OBI_PIN_INTERNAL);              // Pinning策略
//   } map_name SEC(".maps");
//
// 关键观察:
//   1. 几乎所有Map都使用 BPF_MAP_TYPE_LRU_HASH (自动淘汰旧条目)
//   2. 几乎所有共享Map都使用 OBI_PIN_INTERNAL pinning
//   3. max_entries 有两个标准值:
//      - MAX_CONCURRENT_REQUESTS = 10000 (单进程级别)
//      - MAX_CONCURRENT_SHARED_REQUESTS = 30000 (跨进程共享)
//   4. 唯一的非LRU_HASH Map 是 events (RINGBUF) 和 sock_dir (SOCKHASH)

// ============================================================================
// 二、按功能分类的 Map 文件清单
// ============================================================================

// ------- 2.1 连接跟踪类 Map -------

// [fd_map.h] - 文件描述符映射
// 类型: LRU_HASH
// Key:  connection_info_part_t (连接信息: IP + port + 类型)
// Value: fd_info_t (文件描述符 + pid/tid)
// 用途: 将网络连接与处理它的进程/线程关联起来
// 场景: 当检测到新的 connect() 或 accept() 时更新
//       当需要知道某个连接属于哪个进程时查找
// 辅助函数: store_connect_fd_info(), store_accept_fd_info(), fd_info_for_conn()
// max_entries: MAX_CONCURRENT_SHARED_REQUESTS (30000)

// [fd_to_connection.h] - FD到连接的反向映射 (推测)
// 与 fd_map.h 互补，提供从 FD 到连接信息的反向查找

// [accepted_connections.h] - 已接受的连接
// 类型: LRU_HASH
// Key:  connection_info_t (完整连接信息)
// Value: u64 (时间戳)
// 用途: 记录服务器端接受的连接及其时间
// max_entries: MAX_CONCURRENT_SHARED_REQUESTS (30000)

// [ssl_to_conn.h] - SSL指针到连接映射
// 类型: LRU_HASH
// Key:  u64 (SSL struct 指针)
// Value: ssl_pid_connection_info_t (SSL连接+PID信息)
// 用途: 将OpenSSL的SSL*指针映射到对应的网络连接
//       这样在 ssl_read/ssl_write 时能知道数据属于哪个连接
// 设计亮点: 通过uprobe hook ssl_handshake 时建立映射

// [active_ssl_connections.h] - 活跃SSL连接
// 类型: LRU_HASH
// Key:  pid_connection_info_t (PID + 连接信息)
// Value: u64 (SSL指针)
// 用途: 反向映射——从连接信息找到SSL指针
// max_entries: MAX_CONCURRENT_SHARED_REQUESTS (30000)

// [active_ssl_read_args.h] / [active_ssl_write_args.h]
// SSL读写操作的参数暂存
// 在 ssl_read/ssl_write 的入口保存参数，在出口取出使用

// [active_unix_socks.h] - Unix Socket 跟踪
// 类型: LRU_HASH
// Key:  u64 (pid_tid)
// Value: u32 (最后看到的 inode 号)
// 用途: 跟踪进程的 Unix Domain Socket 活动

// [sock_pids.h] - Socket到PID映射
// 类型: LRU_HASH
// Key:  connection_info_t (连接信息)
// Value: conn_pid_t (PID信息 + ID + 时间戳)
// 用途: 在 sock_filter 层面提供PID信息
//       自定义了 conn_pid_t 结构体包含更多上下文

// [sock_dir.h] - Socket 方向映射 (特殊类型!)
// 类型: BPF_MAP_TYPE_SOCKHASH (不是LRU_HASH!)
// Key:  u64
// Value: u32
// max_entries: 65535 (u16最大值)
// 用途: 配合 sock_ops 和 sock_msg 程序使用
//       这是 eBPF socket 层面的特殊Map类型
// 注意: 这是 OBI 中唯一使用 SOCKHASH 类型的Map

// ------- 2.2 HTTP/gRPC 请求跟踪类 Map -------

// [ongoing_http.h] - 正在进行的HTTP请求
// 类型: LRU_HASH
// Key:  pid_connection_info_t (PID + 连接)
// Value: http_info_t (HTTP请求/响应信息)
// 用途: 跟踪正在处理中的HTTP请求，匹配请求和响应
//       当看到请求头时创建条目，看到响应时完成匹配

// [ongoing_http2_connections.h] - HTTP/2 连接状态
// 类型: LRU_HASH
// Key:  pid_connection_info_t
// Value: http2_conn_info_data_t (flags + id)
// 用途: 跟踪 HTTP/2 连接的多路复用状态
// 注意: 没有 pinning! 这说明它不在多个BPF程序间共享

// [ongoing_tcp_req.h] - TCP请求跟踪
// 用途: 在TCP层面跟踪请求

// [nginx_upstream.h] - Nginx upstream 信息
// 用途: 专门用于Nginx的反向代理场景

// ------- 2.3 分布式追踪类 Map -------

// [trace_map.h] - 主追踪Map
// 类型: LRU_HASH
// Key:  trace_map_key_t (追踪用的连接标识)
// Value: tp_info_pid_t (traceparent信息 + PID)
// 用途: 存储 W3C Trace Context (traceparent)
//       这是 OBI 实现分布式追踪的核心Map

// [server_traces.h] - 服务端追踪 (定义了两个Map!)
// Map 1: server_traces
//   Key:  trace_key_t (pid_tid)
//   Value: tp_info_pid_t
// Map 2: server_traces_aux (辅助Map)
//   Key:  connection_info_part_t (临时端口 + 地址)
//   Value: tp_info_pid_t
// 用途: 服务端接收到的请求的trace信息
//       辅助Map用于通过临时端口查找trace

// [outgoing_trace_map.h] - 出站追踪
// 类型: LRU_HASH
// Key:  egress_key_t (出站连接标识)
// Value: tp_info_pid_t
// 用途: 发出的请求携带的trace信息

// [incoming_trace_map.h] - 入站追踪
// 用途: 收到的请求携带的trace信息

// ------- 2.4 进程/线程管理类 Map -------

// [clone_map.h] - 进程克隆(fork)映射
// 类型: LRU_HASH
// Key:  pid_key_t (子进程PID)
// Value: pid_key_t (父进程PID)
// 用途: 跟踪进程的父子关系
//       当 clone/fork 发生时更新

// ------- 2.5 语言特定 Map -------

// [go_ongoing_http.h] - Go HTTP 请求跟踪
// 类型: LRU_HASH
// Key:  egress_key_t
// Value: go_addr_key_t (Go地址空间中的key)
// 用途: 专门跟踪 Go 语言的 HTTP 请求
//       因为 Go 的内存布局和 goroutine 模型需要特殊处理

// [go_ongoing_http_client_requests.h] - Go HTTP 客户端请求
// 用途: Go HTTP 客户端发出的请求

// [go_sql.h] - Go SQL 跟踪 (包含 pq_hostnames Map)
// 类型: LRU_HASH
// Key:  go_addr_key_t (goroutine key)
// Value: char[SQL_HOSTNAME_MAX_LEN] (数据库主机名)
// 用途: 跟踪 PostgreSQL (lib/pq) 连接的主机名

// [java_tasks.h] - Java 任务跟踪
// 用途: Java 应用的特定跟踪需求

// [puma_tasks.h] - Puma (Ruby) 任务跟踪
// 用途: Ruby Puma 服务器的请求跟踪

// [nodejs_fd_map.h] - Node.js 文件描述符映射
// 类型: LRU_HASH
// Key:  u64 (tid | fd)
// Value: s32 (fd)
// max_entries: 1000 (Node.js是单线程的，1000个服务足够)
// 用途: Node.js 运行时的 FD 跟踪

// ------- 2.6 内存/缓冲区类 Map -------

// [tp_info_mem.h] - Traceparent信息内存
// 使用 SCRATCH_MEM_TYPED 宏定义
// 用途: 提供 per-CPU 的临时内存（scratch memory）
//       避免在BPF栈上分配大结构体（栈限制512字节）
// 设计模式: 这是 OBI 避免栈溢出的巧妙方案

// [tp_char_buf_mem.h] - 字符缓冲区内存
// 类似 tp_info_mem.h，提供字符缓冲区的 scratch memory

// [msg_buffers.h] - 消息缓冲区
// 类型: LRU_HASH
// Key:  egress_key_t
// Value: msg_buffer_t
// max_entries: 1000
// 用途: 存储正在构建的消息数据

// [cp_support_connect_info.h] - 连接信息支持
// 用途: 辅助连接信息的处理

// ============================================================================
// 三、关键设计模式总结
// ============================================================================

// 模式 1: LRU_HASH 是默认选择
// ----------------------------------------
// OBI 几乎所有Map都使用 LRU_HASH，原因:
//   - 自动管理内存，不需要手动清理过期条目
//   - 在连接密集的场景下，旧连接自动被淘汰
//   - 避免Map满导致数据丢失

// 模式 2: Pinning 共享
// ----------------------------------------
// OBI_PIN_INTERNAL = 100 (定义在 pin_internal.h)
// 大多数Map使用此值，使多个BPF程序共享同一Map
// 例外: ongoing_http2_connections 没有 pinning（不需要跨程序共享）

// 模式 3: 双向映射
// ----------------------------------------
// fd_map (连接 -> FD) 和 fd_to_connection (FD -> 连接)
// ssl_to_conn (SSL -> 连接) 和 active_ssl_connections (连接 -> SSL)
// 这样可以从任一方向快速查找

// 模式 4: Scratch Memory（Per-CPU临时内存）
// ----------------------------------------
// tp_info_mem.h 使用 PERCPU_ARRAY 作为临时工作空间
// 因为 BPF 栈只有 512 字节，大结构体必须用这种方式

// 模式 5: 标准化的 max_entries
// ----------------------------------------
// MAX_CONCURRENT_REQUESTS = 10000 (单进程级别的Map)
// MAX_CONCURRENT_SHARED_REQUESTS = 30000 (跨进程共享的Map)
// 来源: bpf/common/map_sizing.h

// ============================================================================
// 四、学习建议
// ============================================================================
//
// 1. 先理解连接跟踪类 Map (fd_map, accepted_connections, ssl_to_conn)
//    这是 OBI 数据流的起点
//
// 2. 再理解 HTTP/追踪类 Map (ongoing_http, trace_map, server_traces)
//    这是 OBI 的核心业务逻辑
//
// 3. 最后看语言特定的 Map (go_*, java_*, nodejs_*)
//    这是针对不同运行时的适配层
//
// 4. 阅读顺序建议:
//    pin_internal.h -> map_sizing.h -> fd_map.h -> ongoing_http.h ->
//    ringbuf.h -> trace_map.h -> server_traces.h
//
// 5. 对照用户态代码 (pkg/ 目录下的 Go 代码) 理解Map的创建和读取
//
// ============================================================================
