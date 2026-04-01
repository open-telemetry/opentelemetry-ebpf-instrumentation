// ============================================================================
// Week 3 Day 4: OBI ringbuf.h 深度解析
// ============================================================================
//
// 这不是可编译的代码！这是对 OBI bpf/common/ringbuf.h 的逐行深度注解。
//
// OBI 原始文件位置: bpf/common/ringbuf.h
// 文件大小: 仅 40 行，但每一行都有深意
//
// 核心学习内容:
//   1. RingBuffer 定义和 pinning 策略
//   2. wakeup_data_bytes 优化机制
//   3. get_flags() 函数的精妙设计
//   4. OBI_PIN_INTERNAL 的含义和作用
//
// ============================================================================

// ============================================================================
// 一、OBI ringbuf.h 原文 + 逐行注解
// ============================================================================

// --- 原文开始 ---

// #pragma once                          // 防止头文件重复包含（C的标准做法）
//
// #include <bpfcore/utils.h>            // OBI的基础工具头文件
// #include <common/event_defs.h>        // 事件类型定义 (EVENT_HTTP_REQUEST 等)
// #include <common/pin_internal.h>      // OBI_PIN_INTERNAL 定义

// --- 注释说明为什么要 pinning ---
// setting here the following map definitions without pinning them to a global namespace
// would lead that services running both HTTP and GRPC server would duplicate
// the events ringbuffer and goroutines map.
//
// 翻译: 如果不 pin 这些 Map，同时运行 HTTP 和 gRPC 服务端的程序会
//       导致 events ringbuffer 和 goroutines map 被重复创建。
//
// 深入解释:
//   OBI 会为 HTTP 和 gRPC 分别加载不同的 BPF 程序。
//   如果每个程序都创建自己的 events ringbuf，用户态就需要
//   从多个 ringbuf 中读取事件，增加复杂性。
//   通过 pinning，所有 BPF 程序共享同一个 events ringbuf，
//   用户态只需要读一个 ringbuf。

// This is an edge inefficiency that allows us avoiding the gotchas of
// pinning maps to the global namespace (e.g. like not cleaning them up when
// the autoinstrumenter ends abruptly)
//
// 翻译: 这是一个小的低效性折中，让我们避免了全局 pinning 的陷阱
//       (比如当 autoinstrumenter 突然终止时无法清理 pinned maps)
//
// 深入解释:
//   全局 pinning 的问题:
//   - 如果程序崩溃，pinned 的 Map 文件会残留在 /sys/fs/bpf/
//   - 下次启动时可能与残留的旧 Map 冲突
//   - 需要额外的清理逻辑
//
//   OBI_PIN_INTERNAL 的折中:
//   - 不是全局 pin 到 /sys/fs/bpf/mymap
//   - 而是 OBI 自己管理的内部 pin 路径
//   - cilium/ebpf 库会处理清理工作

// https://ants-gitlab.inf.um.es/jorgegm/xdp-tutorial/-/blob/master/basic04-pinning-maps/README.org
// ^ 参考链接: XDP教程中关于 Map Pinning 的详细说明

// ============================================================================
// 二、RingBuffer Map 定义解析
// ============================================================================

// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);   // 环形缓冲区类型
//     __uint(max_entries, 1 << 20);          // 大小 = 1MB
//     __uint(pinning, OBI_PIN_INTERNAL);     // OBI内部pinning
// } events SEC(".maps");

// 逐字段解析:
//
// (1) BPF_MAP_TYPE_RINGBUF
//     Linux 5.8+ 引入的新型 Map，专门用于内核->用户态的事件传递
//     相比旧的 PERF_EVENT_ARRAY:
//     - 所有CPU共享一个缓冲区（不是每CPU一个）
//     - 支持 reserve/submit 零拷贝模式
//     - 保证事件的全局顺序
//
// (2) max_entries = 1 << 20 = 1,048,576 = 1MB
//     这是 ringbuf 的总大小，必须是 2 的幂次方
//     1MB 对于 OBI 的场景通常够用:
//     - 假设每个事件 ~200 字节
//     - 1MB 可以缓冲 ~5000 个事件
//     - 如果用户态每秒消费一次，可以支撑每秒 5000 个事件
//
//     如果不够用怎么办？
//     - 增大此值（比如 1<<22 = 4MB）
//     - 或者加快用户态消费速度
//     - 或者使用 get_flags() 优化唤醒频率
//
// (3) OBI_PIN_INTERNAL = 100
//     在 pin_internal.h 中定义: enum { OBI_PIN_INTERNAL = 100 };
//
//     这个值不是 Linux 内核定义的标准值!
//     标准的 pinning 值:
//       0 = LIBBPF_PIN_NONE     (不pin)
//       1 = LIBBPF_PIN_BY_NAME  (按名字pin到全局路径)
//
//     100 是 OBI/cilium-ebpf 自定义的值
//     cilium/ebpf Go 库在加载时会识别这个值，并将 Map
//     pin 到 OBI 管理的内部路径下，而不是全局 /sys/fs/bpf/
//
//     这样做的好处:
//     a) 同一 OBI 实例的多个 BPF 程序可以共享此 Map
//     b) 不同 OBI 实例之间互不干扰
//     c) OBI 退出时可以干净地清理

// ============================================================================
// 三、wakeup_data_bytes 优化解析
// ============================================================================

// volatile const u32 wakeup_data_bytes;

// 这一行看似简单，但包含几个精妙的设计:
//
// (1) volatile
//     告诉编译器: 不要优化掉对这个变量的读取!
//     因为编译器可能看到这是 const，又没有初始化，
//     就把所有读取优化为0。volatile 阻止这种优化。
//
// (2) const
//     告诉 BPF 验证器: 这个变量在运行时不会被 BPF 程序修改。
//     它是"编译时常量"，由用户态在加载时注入。
//
// (3) 没有初始化值
//     初始值为0（C的默认值）。用户态在加载 BPF 程序时，
//     通过 cilium/ebpf 的 spec.RewriteConstants() 注入实际值。
//
// (4) 注入机制 (Go用户态代码):
//     spec, _ := ebpf.LoadCollectionSpec("xxx.bpf.o")
//     spec.RewriteConstants(map[string]interface{}{
//         "wakeup_data_bytes": uint32(4096),  // 积累4KB后才唤醒
//     })
//     coll, _ := ebpf.NewCollection(spec)
//
// 这就是 eBPF 的"编译时常量注入"模式:
//   BPF 程序编译一次，但每次加载时可以注入不同的参数
//   类似于 Go 的 ldflags -X 或 Docker 的 build-arg

// ============================================================================
// 四、get_flags() 函数深度解析
// ============================================================================

// static __always_inline long get_flags() {
//     if (!wakeup_data_bytes) {
//         return 0;
//     }
//     const u64 sz = bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA);
//     return sz >= wakeup_data_bytes ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
// }

// 逐行解析:
//
// (1) static __always_inline
//     - static: 仅在当前编译单元可见
//     - __always_inline: 强制内联（BPF程序不支持函数调用*，必须内联）
//       *注: Linux 5.10+ 支持 BPF-to-BPF 函数调用，但内联更安全通用
//
// (2) if (!wakeup_data_bytes) { return 0; }
//     如果用户态没有设置阈值（或设为0），直接返回0
//     返回0 = 使用默认的 ringbuf 唤醒行为
//     默认行为: 每次 submit 都可能唤醒用户态（取决于实现）
//
// (3) bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA)
//     查询 ringbuf 中尚未被消费的数据量（字节）
//
//     想象 ringbuf 是一个水池:
//     - 生产者（BPF程序）不断往里倒水
//     - 消费者（用户态Go）不断从里抽水
//     - BPF_RB_AVAIL_DATA 就是当前水位
//
//     其他可查询的指标:
//     - BPF_RB_RING_SIZE: 水池容量
//     - BPF_RB_CONS_POS: 消费者（出水口）位置
//     - BPF_RB_PROD_POS: 生产者（进水口）位置
//
// (4) sz >= wakeup_data_bytes ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP
//
//     决策逻辑:
//     - 水位(sz) >= 阈值: 水够多了，叫消费者来抽水 (FORCE_WAKEUP)
//     - 水位(sz) < 阈值:  水还不够多，先别叫消费者 (NO_WAKEUP)
//
//     性能影响示例:
//     假设 wakeup_data_bytes = 4096, 每个事件100字节
//     - 没有优化: 每个事件都唤醒 -> 每秒1000个事件 = 1000次唤醒
//     - 有优化: 每积累~40个事件才唤醒 -> 每秒1000个事件 ≈ 25次唤醒
//     - 唤醒次数减少40倍！

// ============================================================================
// 五、完整数据流图
// ============================================================================
//
//  ┌─────────────────────────────────────────────────────────────────┐
//  │                     内核态 (BPF 程序)                            │
//  │                                                                 │
//  │  kprobe/uprobe 触发                                              │
//  │       │                                                         │
//  │       ▼                                                         │
//  │  收集事件数据 (PID, 连接信息, HTTP头, trace context)               │
//  │       │                                                         │
//  │       ▼                                                         │
//  │  evt = bpf_ringbuf_reserve(&events, size, 0)   ← 预留空间       │
//  │       │                                                         │
//  │       ▼                                                         │
//  │  填充 evt 的各个字段                                              │
//  │       │                                                         │
//  │       ▼                                                         │
//  │  bpf_ringbuf_submit(evt, get_flags())          ← 提交+智能唤醒   │
//  │       │                                                         │
//  └───────┼─────────────────────────────────────────────────────────┘
//          │  events ringbuf (1MB, pinned, 所有CPU共享)
//          │
//  ┌───────┼─────────────────────────────────────────────────────────┐
//  │       ▼                     用户态 (Go)                         │
//  │                                                                 │
//  │  reader := ringbuf.NewReader(objs.Events)                       │
//  │       │                                                         │
//  │       ▼                                                         │
//  │  for { record, _ := reader.Read() }  ← 被唤醒时读取              │
//  │       │                                                         │
//  │       ▼                                                         │
//  │  解析事件 → 生成 OpenTelemetry Span → 导出到后端                   │
//  │                                                                 │
//  └─────────────────────────────────────────────────────────────────┘

// ============================================================================
// 六、动手实验建议
// ============================================================================
//
// 实验 1: 修改 wakeup_data_bytes 观察效果
//   - 设为 0: 每个事件都立即唤醒（延迟低，CPU高）
//   - 设为 4096: 积累4KB才唤醒（延迟略高，CPU低）
//   - 设为 1<<20: 几乎不唤醒（不实用，但可以观察行为）
//
// 实验 2: 用 bpf_ringbuf_query 监控 ringbuf 状态
//   在BPF程序中添加:
//     u64 avail = bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA);
//     u64 total = bpf_ringbuf_query(&events, BPF_RB_RING_SIZE);
//     bpf_printk("ringbuf usage: %llu / %llu", avail, total);
//   然后用 cat /sys/kernel/debug/tracing/trace_pipe 查看
//
// 实验 3: 故意让 ringbuf 溢出
//   - 设很小的 max_entries (如 4096)
//   - 生成大量事件
//   - 观察 bpf_ringbuf_reserve 返回 NULL 的情况
//   - 理解"背压"(backpressure) 的概念
//
// ============================================================================
// 七、与其他 Map 类型的对比
// ============================================================================
//
// | 特性           | RINGBUF        | PERF_EVENT_ARRAY | HASH          |
// |----------------|----------------|------------------|---------------|
// | 方向           | 内核→用户       | 内核→用户         | 双向          |
// | CPU亲和性      | 共享            | 每CPU独立         | 取决于子类型  |
// | 零拷贝         | 支持            | 不支持            | N/A           |
// | 事件顺序       | 全局有序        | 每CPU有序         | N/A           |
// | 数据持久性     | 消费后丢失      | 消费后丢失        | 持久          |
// | 适用场景       | 事件流          | 事件流(旧)        | 状态存储      |
//
// OBI 的选择:
//   - events (RINGBUF): 发送事件给用户态
//   - fd_map, ongoing_http 等 (LRU_HASH): 存储状态
//   两者配合: HASH Map 存中间状态, RINGBUF 发最终事件
//
// ============================================================================
