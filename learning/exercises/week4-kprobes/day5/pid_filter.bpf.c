// Week 4 - Day 5: PID 过滤机制
// 主题: 实现类似 OBI 的 valid_pid() 过滤
// OBI 参考: bpf/pid/pid.h, bpf/pid/pid_helpers.h

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// PID 过滤 Map: 存储需要追踪的目标进程 PID
// 用户态程序负责把目标 PID 写入这个 Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);       // PID
    __type(value, u8);      // 1 = 追踪
} target_pids SEC(".maps");

// 全局开关: 是否启用 PID 过滤
// 0 = 追踪所有进程, 1 = 只追踪 target_pids 中的进程
volatile const u32 filter_enabled;

// 模拟 OBI 的 valid_pid() 函数
static __always_inline int valid_pid(u64 id) {
    // 如果过滤没有开启，追踪所有进程
    if (!filter_enabled) {
        return 1;
    }

    u32 pid = id >> 32;  // 提取 PID

    // 在 Map 中查找 PID
    u8 *found = bpf_map_lookup_elem(&target_pids, &pid);
    return found != NULL;  // 找到了就追踪
}

// 使用 PID 过滤的 kprobe 示例
SEC("kprobe/tcp_sendmsg")
int trace_with_pid_filter(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    // ★ PID 过滤: OBI 中每个探针的第一步
    if (!valid_pid(id)) {
        return 0;  // 不是目标进程，跳过
    }

    u32 pid = id >> 32;
    bpf_printk("tcp_sendmsg from target pid=%d", pid);

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/*
=== OBI 的 PID 过滤架构 ===

                 Go 用户态
    ┌─────────────────────────────┐
    │  ProcessWatcher              │
    │    → 发现目标进程             │
    │    → 写入 PID 到 valid_pids  │
    │    → 进程退出时删除 PID      │
    └─────────────┬───────────────┘
                  │ bpf_map_update_elem
    ══════════════╪════════════════
                  │
    ┌─────────────┴───────────────┐
    │  eBPF 内核态                 │
    │    valid_pid(id):            │
    │      → 查找 valid_pids Map   │
    │      → 找到: 继续追踪        │
    │      → 没找到: return 0      │
    └─────────────────────────────┘

好处:
  - 零开销的进程过滤 (Map 查找是 O(1))
  - 动态更新: 用户态随时可以添加/删除目标 PID
  - 避免追踪无关进程，减少性能影响
*/
