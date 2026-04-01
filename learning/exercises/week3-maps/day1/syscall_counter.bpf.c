// ============================================================================
// Week 3 Day 1: HashMap - 按进程统计系统调用次数
// ============================================================================
//
// 学习目标:
//   1. 理解 BPF_MAP_TYPE_HASH 的定义和使用
//   2. 掌握 bpf_map_lookup_elem / bpf_map_update_elem 操作
//   3. 了解 HashMap 的 key/value 设计模式
//
// OBI 参考文件: bpf/maps/fd_map.h
//   - OBI 使用 BPF_MAP_TYPE_LRU_HASH (自动淘汰旧条目的HashMap)
//   - key = connection_info_part_t (连接信息)
//   - value = fd_info_t (文件描述符信息)
//   - 本练习简化为: key = PID (u32), value = 计数器 (u64)
//
// 编译:
//   clang -O2 -g -target bpf -c syscall_counter.bpf.c -o syscall_counter.bpf.o
//
// 加载并查看:
//   sudo bpftool prog load syscall_counter.bpf.o /sys/fs/bpf/syscall_counter
//   sudo bpftool map dump name syscall_count
//
// ============================================================================

// --- 头文件说明 ---
// vmlinux.h: 包含内核所有类型定义（由 bpftool btf dump 生成）
// bpf_helpers.h: 提供 BPF helper 函数声明（如 bpf_map_lookup_elem）
// bpf_tracing.h: 提供 tracepoint/kprobe 相关的宏
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// ============================================================================
// 第一步: 定义 BPF Map
// ============================================================================
//
// 这是 eBPF 程序中最核心的数据结构定义。Map 是内核态和用户态之间共享数据的桥梁。
//
// 与 OBI 的 fd_map.h 对比:
//   OBI:  __uint(type, BPF_MAP_TYPE_LRU_HASH);   // LRU自动淘汰
//         __type(key, connection_info_part_t);     // 复杂的结构体作为key
//         __type(value, fd_info_t);                // 复杂的结构体作为value
//         __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS); // 30000
//         __uint(pinning, OBI_PIN_INTERNAL);       // 自定义pinning策略
//
//   本例:  __uint(type, BPF_MAP_TYPE_HASH);        // 基本HashMap
//         __type(key, __u32);                      // PID (简单整数)
//         __type(value, __u64);                    // 计数器 (简单整数)
//         __uint(max_entries, 10240);              // 最多跟踪10240个进程
//
// 关键概念: Map 类型选择
//   - BPF_MAP_TYPE_HASH: 基本哈希表，需要手动管理条目
//   - BPF_MAP_TYPE_LRU_HASH: 自动淘汰最久未使用的条目（OBI的选择）
//   - BPF_MAP_TYPE_PERCPU_HASH: 每个CPU一份副本，避免竞争（Day 5 学习）
//   - BPF_MAP_TYPE_ARRAY: 固定大小数组，key必须是索引

struct {
    __uint(type, BPF_MAP_TYPE_HASH);  // Map类型: 哈希表
    __type(key, __u32);               // Key类型: 进程ID (PID)
    __type(value, __u64);             // Value类型: 系统调用计数
    __uint(max_entries, 10240);       // 最大条目数: 10240
} syscall_count SEC(".maps");
// SEC(".maps") 告诉编译器这是一个 BPF Map 定义
// 加载时，内核会根据这些属性创建对应的数据结构

// ============================================================================
// 第二步: 定义 BPF 程序 - 挂载到 sys_enter tracepoint
// ============================================================================
//
// SEC("tracepoint/raw_syscalls/sys_enter") 表示:
//   - 程序类型: tracepoint
//   - 挂载点: raw_syscalls/sys_enter (所有系统调用的入口)
//   - 每次任何进程执行系统调用时，此函数都会被调用
//
// 你可以查看可用的 tracepoint:
//   sudo ls /sys/kernel/debug/tracing/events/raw_syscalls/
//
// ctx 参数: 指向 tracepoint 的上下文数据（这里我们不需要用它的字段）

SEC("tracepoint/raw_syscalls/sys_enter")
int count_syscalls(void *ctx)
{
    // --- 获取当前进程的 PID ---
    // bpf_get_current_pid_tgid() 返回一个 64 位值:
    //   高 32 位 = tgid (线程组ID，即通常说的PID)
    //   低 32 位 = pid  (线程ID，即通常说的TID)
    // 右移 32 位取高位，得到进程级别的 PID
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // --- Map 操作 1: 查找 (Lookup) ---
    // bpf_map_lookup_elem(&map, &key) 在Map中查找key对应的value
    //
    // 返回值:
    //   - 成功: 指向 value 的指针（注意：这是直接指向Map内部的指针！）
    //   - 失败: NULL (key不存在)
    //
    // 重要: 返回的指针必须先做NULL检查，否则 BPF 验证器会拒绝程序
    // 这就像 Go 里面必须检查 err != nil 一样
    //
    // OBI 示例 (fd_map.h):
    //   fd_info_t *info = bpf_map_lookup_elem(&fd_map, &part);
    //   // OBI 也是同样的模式：查找 -> 判空 -> 使用
    __u64 *count = bpf_map_lookup_elem(&syscall_count, &pid);

    if (count) {
        // --- Map 操作 2a: 原子递增 ---
        // 因为 count 是指向 Map 内部数据的指针
        // 使用 __sync_fetch_and_add 进行原子操作
        // 这保证了在多CPU并发时的安全性
        //
        // 注意: 对于简单的计数场景，PERCPU_HASH 更高效（Day 5）
        // 因为每个CPU有自己的副本，不需要原子操作
        __sync_fetch_and_add(count, 1);
    } else {
        // --- Map 操作 2b: 插入新条目 (Update/Insert) ---
        // bpf_map_update_elem(&map, &key, &value, flags)
        //
        // flags 参数说明:
        //   BPF_ANY     (0): 如果key存在则更新，不存在则创建
        //   BPF_NOEXIST (1): 仅当key不存在时创建（如果已存在则失败）
        //   BPF_EXIST   (2): 仅当key已存在时更新（如果不存在则失败）
        //
        // OBI 示例 (fd_map.h):
        //   bpf_map_update_elem(&fd_map, &part, &fdinfo, BPF_ANY);
        //   // OBI 使用 BPF_ANY，因为连接可能会被重用
        __u64 initial_count = 1;
        bpf_map_update_elem(&syscall_count, &pid, &initial_count, BPF_NOEXIST);
        // 使用 BPF_NOEXIST 避免覆盖其他CPU可能刚创建的条目
        // 在高并发场景下，两个CPU可能同时为同一个PID执行到这里
    }

    return 0;
}

// ============================================================================
// 第三步: 许可证声明
// ============================================================================
// BPF 程序必须声明许可证，否则无法使用 GPL-only 的 helper 函数
// 大多数有用的 helper（如 bpf_get_current_pid_tgid）都需要 GPL
char LICENSE[] SEC("license") = "GPL";

// ============================================================================
// 学习笔记: Map 操作 API 总结
// ============================================================================
//
// 1. bpf_map_lookup_elem(&map, &key)
//    查找。返回指向value的指针或NULL。
//    类比 Go: val, ok := myMap[key]
//
// 2. bpf_map_update_elem(&map, &key, &value, flags)
//    插入或更新。flags控制行为。
//    类比 Go: myMap[key] = value
//
// 3. bpf_map_delete_elem(&map, &key)
//    删除条目。
//    类比 Go: delete(myMap, key)
//    （本程序未使用，但这是三个基本操作之一）
//
// ============================================================================
// 进阶思考:
// ============================================================================
//
// Q1: 为什么 OBI 选择 LRU_HASH 而不是普通 HASH?
// A1: 在生产环境中，进程不断创建和销毁。普通HASH需要手动清理旧条目，
//     否则Map会满。LRU_HASH 自动淘汰最久未访问的条目，避免Map满了
//     无法插入新数据。
//
// Q2: max_entries 设多大合适?
// A2: 取决于场景。OBI使用 MAX_CONCURRENT_SHARED_REQUESTS = 30000，
//     是根据"生产环境最多同时有多少活跃连接"来估算的。
//     设太小会丢数据，设太大浪费内核内存。
//
// Q3: 为什么 OBI 的 Map 使用 __uint(pinning, OBI_PIN_INTERNAL)?
// A3: Pinning 让 Map 在 BPF 文件系统中持久化（/sys/fs/bpf/），
//     这样多个 BPF 程序可以共享同一个 Map。OBI 使用自定义的
//     OBI_PIN_INTERNAL (值=100) 来标记需要在内部共享的Map。
//     参见: bpf/common/pin_internal.h
//
// ============================================================================
