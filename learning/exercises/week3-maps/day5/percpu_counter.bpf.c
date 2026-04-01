// ============================================================================
// Week 3 Day 5: Per-CPU Map - 无锁并发安全的计数器
// ============================================================================
//
// 学习目标:
//   1. 理解 BPF_MAP_TYPE_PERCPU_HASH 的工作原理
//   2. 理解为什么 Per-CPU 能避免锁竞争
//   3. 对比普通 HASH 和 PERCPU_HASH 的性能差异
//   4. 理解 OBI 中 scratch memory 模式与 per-CPU 的关系
//
// OBI 参考:
//   - bpf/maps/tp_info_mem.h 使用 PERCPU_ARRAY 作为 scratch memory
//   - OBI 的主要Map使用 LRU_HASH (非PERCPU)，因为需要跨CPU共享状态
//   - 但对于纯计数/临时存储场景，PERCPU 是更好的选择
//
// 编译:
//   clang -O2 -g -target bpf -c percpu_counter.bpf.c -o percpu_counter.bpf.o
//
// 加载并查看:
//   sudo bpftool prog load percpu_counter.bpf.o /sys/fs/bpf/percpu_counter
//   sudo bpftool map dump name percpu_syscall
//   (注意: bpftool 会显示每个CPU的独立值)
//
// ============================================================================

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// ============================================================================
// 第一步: 理解为什么需要 Per-CPU Map
// ============================================================================
//
// 问题场景 (以 Day 1 的 syscall_counter 为例):
//
//   CPU 0                          CPU 1
//   ─────                          ─────
//   lookup(pid=100) → count=5      lookup(pid=100) → count=5
//   count = 5 + 1 = 6              count = 5 + 1 = 6
//   update(pid=100, count=6)       update(pid=100, count=6)
//                                  ← 丢失了一次计数!
//
// 上面的竞争条件(race condition)会导致计数不准确。
//
// 解决方案:
//   方案1: 使用 __sync_fetch_and_add (原子操作) - Day 1 的做法
//          优点: 简单
//          缺点: 原子操作有CPU cache行弹跳(cache-line bouncing)的开销
//
//   方案2: 使用 PERCPU_HASH - 今天学习的方法
//          优点: 完全无锁，零竞争，最高性能
//          缺点: 用户态读取时需要汇总各CPU的值
//
//   方案3: BPF spin lock (bpf_spin_lock)
//          优点: 可以保护复杂的操作序列
//          缺点: 有锁开销，不适合高频场景

// ============================================================================
// 第二步: 定义两种Map进行对比
// ============================================================================

// --- 对比Map 1: 普通 HASH (有竞争风险) ---
// 所有CPU共享同一份数据
// 如果不用原子操作，并发更新会丢失计数
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);               // PID
    __type(value, __u64);             // 计数
    __uint(max_entries, 10240);
} regular_syscall_count SEC(".maps");

// --- 对比Map 2: PERCPU HASH (无竞争) ---
// 每个CPU有自己独立的副本!
//
// 内存布局示意（假设4个CPU）:
//
//   regular_syscall_count:           percpu_syscall_count:
//   ┌──────────────────┐            ┌──────────────────┐ CPU 0
//   │ key=100, val=42  │            │ key=100, val=10  │
//   │ key=200, val=17  │            │ key=200, val=5   │
//   └──────────────────┘            ├──────────────────┤ CPU 1
//     (所有CPU看到同一份)            │ key=100, val=12  │
//                                   │ key=200, val=4   │
//                                   ├──────────────────┤ CPU 2
//                                   │ key=100, val=11  │
//                                   │ key=200, val=3   │
//                                   ├──────────────────┤ CPU 3
//                                   │ key=100, val=9   │
//                                   │ key=200, val=5   │
//                                   └──────────────────┘
//                                   总和: key=100 → 10+12+11+9 = 42 ✓

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);  // Per-CPU 哈希表
    __type(key, __u32);                       // PID
    __type(value, __u64);                     // 该CPU上的计数
    __uint(max_entries, 10240);
} percpu_syscall_count SEC(".maps");

// ============================================================================
// 第三步: 使用普通 HASH 的程序（需要原子操作）
// ============================================================================

SEC("tracepoint/raw_syscalls/sys_enter")
int count_regular(void *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u64 *count = bpf_map_lookup_elem(&regular_syscall_count, &pid);
    if (count) {
        // 必须用原子操作! 否则会有竞争条件
        // __sync_fetch_and_add 编译为 CPU 的 LOCK XADD 指令
        // 这个指令会锁住 cache line，确保原子性
        // 但如果多个CPU同时操作同一个key，会导致 cache-line bouncing:
        //   CPU0 锁住 cache line → CPU1 等待
        //   CPU1 锁住 cache line → CPU0 等待
        //   大量的CPU间通信开销!
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&regular_syscall_count, &pid, &init, BPF_NOEXIST);
    }

    return 0;
}

// ============================================================================
// 第四步: 使用 PERCPU_HASH 的程序（无需原子操作）
// ============================================================================

SEC("tracepoint/raw_syscalls/sys_exit")
int count_percpu(void *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u64 *count = bpf_map_lookup_elem(&percpu_syscall_count, &pid);
    if (count) {
        // 不需要原子操作!
        // 因为每个CPU只会访问自己的那份副本
        // 不存在并发竞争
        //
        // 这里直接 *count += 1 就安全了
        // (即使同一个PID的线程在不同CPU上执行，
        //  每个CPU各自递增自己的计数器，互不干扰)
        *count += 1;
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&percpu_syscall_count, &pid, &init, BPF_NOEXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

// ============================================================================
// 第五步: 用户态如何读取 PERCPU Map（Go 伪代码）
// ============================================================================
//
// 普通 HASH 读取:
//   var key uint32
//   var value uint64
//   iter := objs.RegularSyscallCount.Iterate()
//   for iter.Next(&key, &value) {
//       fmt.Printf("PID %d: %d syscalls\n", key, value)
//   }
//
// PERCPU HASH 读取（需要汇总!）:
//   var key uint32
//   // 注意: value 是一个切片，每个元素对应一个CPU
//   values := make([]uint64, runtime.NumCPU())
//   iter := objs.PercpuSyscallCount.Iterate()
//   for iter.Next(&key, &values) {
//       var total uint64
//       for _, v := range values {
//           total += v        // 汇总所有CPU的计数
//       }
//       fmt.Printf("PID %d: %d syscalls\n", key, total)
//   }
//
// cilium/ebpf 库自动处理了 per-CPU 的内存布局转换

// ============================================================================
// 学习笔记: Per-CPU Map 类型家族
// ============================================================================
//
// | Map 类型                    | 说明                    |
// |-----------------------------|-------------------------|
// | BPF_MAP_TYPE_PERCPU_HASH    | Per-CPU 哈希表          |
// | BPF_MAP_TYPE_PERCPU_ARRAY   | Per-CPU 数组            |
// | BPF_MAP_TYPE_LRU_PERCPU_HASH| Per-CPU LRU 哈希表      |
//
// PERCPU_ARRAY 特别适合做 scratch memory (临时内存)
// 这正是 OBI 在 tp_info_mem.h 中的用法:
//
//   // OBI 的 SCRATCH_MEM_TYPED 宏展开后大致是:
//   struct {
//       __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//       __type(key, int);
//       __type(value, tp_info_pid_t);    // 大结构体
//       __uint(max_entries, 1);           // 只要1个条目!
//   } tp_info_mem SEC(".maps");
//
//   // 使用方式:
//   int zero = 0;
//   tp_info_pid_t *tp = bpf_map_lookup_elem(&tp_info_mem, &zero);
//   // 现在 tp 指向当前CPU专属的一块内存
//   // 可以安全地使用，不需要担心竞争
//
// 为什么要这样做？
//   BPF 栈空间只有 512 字节!
//   tp_info_pid_t 可能有几百字节大
//   放不下栈上，就用 PERCPU_ARRAY 作为替代的"堆"内存

// ============================================================================
// 进阶: 什么时候用哪种方案?
// ============================================================================
//
// 场景 1: 简单的聚合计数 (如本例)
//   推荐: PERCPU_HASH
//   原因: 最高性能，无任何竞争
//
// 场景 2: 存储请求状态（如 OBI 的 ongoing_http）
//   推荐: LRU_HASH (非 PERCPU)
//   原因: 请求可能在 CPU A 上开始，在 CPU B 上结束
//         必须用共享Map，PERCPU在这里不适用!
//
// 场景 3: 临时工作空间 (如 OBI 的 tp_info_mem)
//   推荐: PERCPU_ARRAY
//   原因: 每个CPU独立，用作安全的"堆"替代品
//
// 场景 4: 需要复杂的更新操作（read-modify-write 多字段）
//   推荐: bpf_spin_lock + 普通 HASH
//   原因: 原子操作只能保护单个值，spin_lock 可以保护整个操作序列
//
// OBI 的选择总结:
//   - 绝大多数Map: LRU_HASH（因为需要跨CPU共享连接/请求状态）
//   - scratch memory: PERCPU_ARRAY（临时工作空间）
//   - 事件传递: RINGBUF（已经是天然线程安全的）
//
// ============================================================================
