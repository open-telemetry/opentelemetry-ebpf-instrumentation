// Week 6 - Day 7: 综合 TCP 连接追踪器
//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct conn_event {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  type;       // 0=new, 1=close
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

// 连接计数器
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} active_count SEC(".maps");

SEC("kprobe/tcp_connect")
int trace_connect(struct pt_regs *ctx) {
    struct sock *sk = (void *)PT_REGS_PARM1(ctx);
    struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->dport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
    e->type = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    // 增加计数
    u32 key = 0;
    u64 *count = bpf_map_lookup_elem(&active_count, &key);
    if (count) __sync_fetch_and_add(count, 1);
    return 0;
}

SEC("kprobe/tcp_close")
int trace_close(struct pt_regs *ctx) {
    struct sock *sk = (void *)PT_REGS_PARM1(ctx);
    struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->dport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
    e->type = 1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    // 减少计数
    u32 key = 0;
    u64 *count = bpf_map_lookup_elem(&active_count, &key);
    if (count) __sync_fetch_and_add(count, -1);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
