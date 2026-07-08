// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/sockaddr.h>

#include <logger/bpf_dbg.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// #define WATCH_BIND 0x1
// #define WATCH_EXEC 0x2

typedef struct watch_info {
    u32 pid;
    u16 port;
} __attribute__((packed)) watch_info_t;

const watch_info_t *unused_2 __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} watch_events SEC(".maps");

SEC("kprobe/sys_bind")
int obi_kprobe_sys_bind(struct pt_regs *ctx) {
    // unwrap the args because it's a sys call
    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    void *addr;
    bpf_probe_read(&addr, sizeof(void *), (void *)&PT_REGS_PARM2(__ctx));

    if (!addr) {
        return 0;
    }

    const u16 port = get_sockaddr_port_user(addr);
    if (!port) {
        return 0;
    }

    pid_info pid;
    task_pid(&pid);

    watch_info_t *trace = bpf_ringbuf_reserve(&watch_events, sizeof(watch_info_t), 0);
    if (!trace) {
        bpf_dbg_printk(
            "watcher kprobe/sys_bind: pid=%d port=%d. Ringbuf reserve failed", pid.host_pid, port);
        return 0;
    }
    trace->pid = pid.host_pid;
    trace->port = port;
    bpf_dbg_printk("watcher kprobe/sys_bind: pid=%d port=%d", trace->pid, trace->port);
    bpf_ringbuf_submit(trace, 0);

    return 0;
}

// Send a notification every time a new process is created
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    pid_info pid;
    task_pid(&pid);

    watch_info_t *trace = bpf_ringbuf_reserve(&watch_events, sizeof(watch_info_t), 0);
    if (!trace) {
        bpf_dbg_printk(
            "watcher tracepoint/syscalls/sys_enter_execve: pid=%d. Ringbuf reserve failed",
            pid.host_pid);
        return 0;
    }
    trace->port = 0;
    trace->pid = pid.host_pid;

    // 4. Enviar el evento al espacio de usuario
    bpf_ringbuf_submit(trace, 0);

    return 0;
}