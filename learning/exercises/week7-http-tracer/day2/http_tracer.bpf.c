// Week 7 - Day 2: HTTP 追踪器内核态 — TCP 收发追踪
//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct conn_key {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

struct request_info {
    u64 start_ns;
    u32 pid;
    u8  method;     // 检测到的 HTTP 方法
    char path[64];
};

struct http_event {
    struct conn_key conn;
    u32 pid;
    u64 duration_ns;
    u8  method;
    u16 status;
    char path[64];
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct conn_key);
    __type(value, struct request_info);
} active_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

#include "http_detect.h"

SEC("kprobe/tcp_sendmsg")
int trace_tcp_send(struct pt_regs *ctx) {
    struct sock *sk = (void *)PT_REGS_PARM1(ctx);
    // 简化: 实际需要读取 msg 缓冲区来检测 HTTP
    // 这里只记录时间戳和连接信息
    struct conn_key key = {};
    key.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));

    struct request_info info = {};
    info.start_ns = bpf_ktime_get_ns();
    info.pid = bpf_get_current_pid_tgid() >> 32;

    bpf_map_update_elem(&active_requests, &key, &info, BPF_NOEXIST);
    return 0;
}

// TODO Day 3: 添加 HTTP 协议检测
// TODO: kprobe/tcp_recvmsg + kretprobe 来捕获响应

char LICENSE[] SEC("license") = "Dual MIT/GPL";
