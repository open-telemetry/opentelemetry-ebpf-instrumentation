// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include "pid/types/pid_key.h"
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/connection_info.h>
#include <common/protocol_defs.h>

#include <generictracer/k_tracer_defs.h>
#include <generictracer/maps/java_tasks.h>
#include <generictracer/maps/pid_tid_to_conn.h>

#include <logger/bpf_dbg.h>

#include <pid/pid.h>

enum { k_ioctl_magic_id = 0x0b10b1 };
enum {
    k_ioctl_java_send = 1,
    k_ioctl_java_recv = 2,
    k_ioctl_java_threads = 3,
};

enum { k_ioctl_invalid_op = 0xff };

static __always_inline u8 cmd_to_op(u8 cmd) {
    switch (cmd) {
    case k_ioctl_java_send:
        return TCP_SEND;
    case k_ioctl_java_recv:
        return TCP_RECV;
    default:
        return k_ioctl_invalid_op;
    }
}

SEC("kprobe/sys_ioctl")
// unsigned int fd, unsigned int cmd, void *arg
int BPF_KPROBE(obi_kprobe_sys_ioctl) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== kprobe/sys_ioctl id=%d ===", id);

    // unwrap the syscall arguments in __ctx
    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);

    unsigned int fd = 0;
    unsigned int cmd = 0;
    void *arg = 0;

    bpf_probe_read(&fd, sizeof(unsigned int), (void *)&PT_REGS_PARM1(__ctx));
    bpf_probe_read(&cmd, sizeof(unsigned int), (void *)&PT_REGS_PARM2(__ctx));
    bpf_probe_read(&arg, sizeof(void *), (void *)&PT_REGS_PARM3(__ctx));

    // it must be fd == 0 if we are considering this request
    if (fd) {
        return 0;
    }

    // some other IOCTL by the app
    if (cmd != k_ioctl_magic_id) {
        return 0;
    }

    bpf_dbg_printk("data=%llx", arg);

    if (!arg) {
        return 0;
    }

    u8 op_cmd = 0;
    bpf_probe_read(&op_cmd, sizeof(u8), arg);

    if (op_cmd == k_ioctl_java_threads) {
        u64 parent_id = 0;
        bpf_probe_read(&parent_id, sizeof(u64), arg + 1);

        pid_key_t child = {0};
        task_tid(&child);
        pid_key_t parent = child;
        u32 parent_tid = tid_from_pid_tgid(parent_id);
        parent.tid = parent_tid;

        if (parent.tid == child.tid) {
            bpf_dbg_printk("self referencing thread %d, not recording", child.tid);
            return 0;
        }

        bpf_dbg_printk("Java thread mapping [%d] -> [%d]", parent.tid, child.tid);
        bpf_map_update_elem(&java_tasks, &child, &parent, BPF_ANY);
        return 0;
    }

    u8 op = cmd_to_op(op_cmd);

    if (op == k_ioctl_invalid_op) {
        bpf_dbg_printk("unknown cmd=%d", op_cmd);
        return 0;
    }

    bpf_dbg_printk("op=%d, cmd=%d", op, op_cmd);

    pid_connection_info_t p_conn = {0};
    bpf_probe_read(&p_conn.conn, sizeof(connection_info_t), arg + 1);
    d_print_http_connection_info(&p_conn.conn);
    u16 orig_dport = 0;
    // What we get from Java is correct, unlike the reversed information we
    // get from the kernel probes. So we need to fake the orig_dport to match
    // what the rest of the APIs expect.
    if (op == TCP_RECV) {
        orig_dport = p_conn.conn.s_port;
    } else {
        orig_dport = p_conn.conn.d_port;
    }

    sort_connection_info(&p_conn.conn);
    p_conn.pid = pid_from_pid_tgid(id);

    if (is_empty_connection_info(&p_conn.conn)) {
        ssl_pid_connection_info_t *l = bpf_map_lookup_elem(&pid_tid_to_conn, &id);
        bpf_dbg_printk("lookup for empty connection info: %llx", l);
        if (l) {
            p_conn = l->p_conn;
        }
    }

    u32 len = 0;
    bpf_probe_read(&len, sizeof(u32), arg + 1 + sizeof(connection_info_t));

    bpf_dbg_printk("payload len=%d", len);

    if (len > 0) {
        void *buf = arg + 1 + sizeof(connection_info_t) + sizeof(u32);
        handle_buf_with_connection(ctx, &p_conn, buf, len, WITH_SSL, op, orig_dport);
    }

    return 0;
}
