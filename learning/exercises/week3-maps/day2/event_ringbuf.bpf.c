// ============================================================================
// Week 3 Day 2: RingBuffer - 从内核向用户空间发送事件
// ============================================================================
//
// 学习目标:
//   1. 理解 BPF_MAP_TYPE_RINGBUF 的定义和用途
//   2. 掌握 bpf_ringbuf_reserve / bpf_ringbuf_submit 模式
//   3. 理解 RingBuffer 相对于 PerfBuffer 的优势
//
// OBI 参考文件: bpf/common/ringbuf.h
//   - OBI 定义了名为 "events" 的 ringbuf，大小 1<<20 (1MB)
//   - OBI 有精心设计的 wakeup 优化（get_flags 函数）
//   - OBI 通过 ringbuf 将 HTTP/gRPC 事件发送给用户空间的 Go 程序
//
// 编译:
//   clang -O2 -g -target bpf -c event_ringbuf.bpf.c -o event_ringbuf.bpf.o
//
// 用户空间可以通过 cilium/ebpf 的 ringbuf.Reader 来接收事件 (参见 Day 6)
//
// ============================================================================

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ============================================================================
// 第一步: 定义事件结构体
// ============================================================================
//
// 这是内核态和用户态之间传递的数据格式。
// 两边必须使用完全一致的结构体定义（包括字段顺序和大小）。
//
// OBI 参考: bpf/common/event_defs.h 定义了事件类型常量
//   #define EVENT_HTTP_REQUEST    1
//   #define EVENT_GRPC_REQUEST    2
//   #define EVENT_HTTP_CLIENT     3
//   ... 等等
//
// 在实际的 OBI 项目中，事件结构体更复杂，包含连接信息、
// HTTP请求头、响应状态码、trace context 等。

// 事件类型常量
#define EVENT_TYPE_EXEC 1    // 进程执行 (execve)

struct event {
    __u32 pid;               // 进程ID
    __u32 uid;               // 用户ID
    char comm[16];           // 进程名（task_struct->comm，最长16字节）
    __u64 timestamp_ns;      // 时间戳（纳秒）
    __u32 event_type;        // 事件类型
};

// ============================================================================
// 第二步: 定义 RingBuffer Map
// ============================================================================
//
// RingBuffer 是一个环形缓冲区，用于从内核态向用户态高效传输数据。
//
// 对比 OBI 的 ringbuf 定义 (bpf/common/ringbuf.h):
//
//   struct {
//       __uint(type, BPF_MAP_TYPE_RINGBUF);
//       __uint(max_entries, 1 << 20);          // 1MB
//       __uint(pinning, OBI_PIN_INTERNAL);     // 内部pinning共享
//   } events SEC(".maps");
//
// RingBuffer vs PerfBuffer (旧方案):
//   - PerfBuffer: 每个CPU一个缓冲区，浪费内存，可能不均衡
//   - RingBuffer: 所有CPU共享一个缓冲区，内存利用率更高
//   - RingBuffer 支持 reserve/submit 模式，避免额外的内存拷贝
//   - RingBuffer 保证事件顺序（按 submit 顺序）

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);  // Map类型: 环形缓冲区
    __uint(max_entries, 256 * 1024);     // 缓冲区大小: 256KB
                                          // 必须是2的幂次方
                                          // OBI用 1<<20 = 1MB
} events SEC(".maps");

// ============================================================================
// 第三步: 实现 wakeup 优化（学习 OBI 的设计）
// ============================================================================
//
// 这个优化直接来源于 OBI 的 bpf/common/ringbuf.h
//
// 问题: 每次 bpf_ringbuf_submit 默认都会唤醒用户态进程来读取数据。
//       如果事件非常频繁（比如每秒数千个HTTP请求），频繁唤醒会导致
//       大量的上下文切换，严重影响性能。
//
// OBI 的解决方案:
//   1. 用户态设置一个阈值 wakeup_data_bytes
//   2. 内核态检查 ringbuf 中已有多少数据
//   3. 如果数据量 < 阈值，不唤醒 (BPF_RB_NO_WAKEUP)
//   4. 如果数据量 >= 阈值，强制唤醒 (BPF_RB_FORCE_WAKEUP)
//
// volatile const: 这个变量在BPF程序加载时由用户态注入
// "volatile" 防止编译器优化掉对它的读取
// "const" 表示BPF程序运行时不会修改它

volatile const __u32 wakeup_data_bytes;

// OBI 原版的 get_flags() 函数
// 完整逻辑解析:
static __always_inline long get_flags()
{
    // 如果 wakeup_data_bytes == 0，表示不启用优化
    // 返回 0 意味着使用默认行为（每次都唤醒）
    if (!wakeup_data_bytes) {
        return 0;
    }

    // bpf_ringbuf_query: 查询 ringbuf 的状态信息
    // BPF_RB_AVAIL_DATA: 查询当前已使用但未消费的数据量（字节）
    //
    // 其他可查询的值:
    //   BPF_RB_RING_SIZE: ringbuf 总大小
    //   BPF_RB_CONS_POS: 消费者位置
    //   BPF_RB_PROD_POS: 生产者位置
    const __u64 sz = bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA);

    // 如果积累的数据已经超过阈值，强制唤醒用户态来消费
    // 否则先不唤醒，等数据再多一些（减少唤醒次数，提高吞吐量）
    return sz >= wakeup_data_bytes ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

// ============================================================================
// 第四步: BPF 程序 - 捕获进程执行事件
// ============================================================================
//
// 挂载到 sched_process_exec tracepoint
// 每当有进程调用 execve() 执行新程序时触发
//
// 这类似于 OBI 中捕获 HTTP 请求的模式:
//   1. 在合适的hook点捕获事件
//   2. 收集需要的信息（PID、进程名、时间戳等）
//   3. 通过 ringbuf 发送给用户空间

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(void *ctx)
{
    // --- 收集事件信息 ---

    // 获取 PID (高32位是tgid，即PID)
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // 获取 UID
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = uid_gid & 0xFFFFFFFF;  // 低32位是UID

    // ========================================================================
    // 关键操作: bpf_ringbuf_reserve - 预留空间
    // ========================================================================
    //
    // bpf_ringbuf_reserve(&ringbuf, size, flags)
    //
    // 这是 RingBuffer 的核心操作之一。它在 ringbuf 中预留一块内存，
    // 返回指向这块内存的指针。
    //
    // 优势（对比旧的 bpf_perf_event_output）:
    //   1. 零拷贝: 直接在 ringbuf 内存中构造数据，不需要先在栈上构造再拷贝
    //   2. 灵活: 可以分步填充数据，不用一次性准备好所有字段
    //
    // 返回值:
    //   - 成功: 指向预留内存的指针
    //   - 失败: NULL (ringbuf 已满，没有足够空间)
    //
    // flags: 目前必须为 0

    struct event *evt = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);

    // 必须检查 NULL! 如果 ringbuf 满了，reserve 会失败
    // 这意味着用户态消费不够快，事件会被丢弃
    if (!evt) {
        return 0;
    }

    // --- 填充事件数据 ---
    // 直接在 ringbuf 的内存中写入数据（零拷贝！）
    evt->pid = pid;
    evt->uid = uid;
    evt->event_type = EVENT_TYPE_EXEC;

    // bpf_get_current_comm: 获取当前进程名（task_struct->comm）
    // 参数: 目标缓冲区, 缓冲区大小
    // 进程名最长 TASK_COMM_LEN = 16 字节
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    // bpf_ktime_get_ns: 获取内核单调时钟的纳秒时间戳
    // 这不是wall clock时间，而是从系统启动开始的单调递增时间
    // 用于测量时间间隔非常精确
    evt->timestamp_ns = bpf_ktime_get_ns();

    // ========================================================================
    // 关键操作: bpf_ringbuf_submit - 提交事件
    // ========================================================================
    //
    // bpf_ringbuf_submit(data, flags)
    //
    // 将之前 reserve 的数据标记为"可消费"，用户态就能读到了。
    //
    // flags:
    //   0                   - 默认行为，通知用户态有新数据
    //   BPF_RB_NO_WAKEUP   - 不唤醒用户态（攒批处理）
    //   BPF_RB_FORCE_WAKEUP - 强制唤醒用户态
    //
    // 注意: 一旦 reserve 成功，必须调用 submit 或 discard!
    //   - bpf_ringbuf_submit: 提交数据，用户态可见
    //   - bpf_ringbuf_discard: 丢弃数据，释放预留的空间
    //   如果两者都不调用，会造成 ringbuf 内存泄漏!

    bpf_ringbuf_submit(evt, get_flags());
    // 使用 get_flags() 实现 OBI 风格的 wakeup 优化

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

// ============================================================================
// 学习笔记: RingBuffer API 总结
// ============================================================================
//
// 生产者（内核态）操作:
//   1. bpf_ringbuf_reserve(&rb, size, flags) -> 预留空间
//   2. 填充数据（直接写指针）
//   3. bpf_ringbuf_submit(ptr, flags)        -> 提交
//      或 bpf_ringbuf_discard(ptr, flags)    -> 丢弃
//
// 简便方式（不推荐，有额外拷贝）:
//   bpf_ringbuf_output(&rb, data, size, flags)
//   等同于 reserve + memcpy + submit，但有内存拷贝开销
//
// 消费者（用户态）操作:
//   Go: ringbuf.NewReader(objs.Events) -> reader.Read()
//   参见 Day 6 的 Go 示例
//
// ============================================================================
// 进阶思考:
// ============================================================================
//
// Q1: RingBuffer 满了怎么办?
// A1: bpf_ringbuf_reserve 返回 NULL，事件被丢弃。
//     可以通过增大 max_entries 或加快用户态消费来缓解。
//     OBI 使用 1MB 的缓冲区，并且 Go 端有专门的 goroutine 持续消费。
//
// Q2: 为什么 OBI 要做 wakeup 优化?
// A2: 在高流量场景（如监控繁忙的Web服务器），每秒可能产生数千个事件。
//     如果每个事件都唤醒用户态，上下文切换的开销会非常大。
//     通过攒批（batch）唤醒，可以显著减少系统开销。
//
// Q3: reserve + submit 和 output 的区别?
// A3: reserve+submit 是零拷贝，直接在 ringbuf 内存中写;
//     output 需要先在栈上准备好数据，再拷贝到 ringbuf。
//     栈空间有限（512字节），大数据必须用 reserve+submit。
//
// ============================================================================
