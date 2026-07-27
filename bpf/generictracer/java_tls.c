// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include "pid/types/pid_key.h"
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/connection_info.h>
#include <common/protocol_defs.h>
#include <common/trace_key.h>
#include <common/trace_parent.h>

#include <generictracer/k_tracer_defs.h>
#include <generictracer/maps/pid_tid_to_conn.h>

#include <logger/bpf_dbg.h>

#include <maps/active_ssl_connections.h>
#include <maps/java_tasks.h>
#include <maps/java_vt_threads.h>

#include <pid/pid.h>

#include <shared/obi_ctx.h>

enum { k_ioctl_magic_id = 0x0b10b1 };
enum {
    k_ioctl_java_send = 1,
    k_ioctl_java_recv = 2,
    k_ioctl_java_threads = 3,
    k_ioctl_java_vt_mount = 4,   // virtual thread mounted on this carrier
    k_ioctl_java_vt_unmount = 5, // virtual thread unmounted from this carrier
};

enum { k_ioctl_invalid_op = 0xff };
// Keep this ceiling aligned with the largest large-buffer capture limit in
// bpf/common/large_buffers.h.
enum { k_ioctl_max_payload_len = 1 << 16 };

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
    const u64 id = bpf_get_current_pid_tgid();

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

    unsigned char *uarg = arg;

    u8 op_cmd = 0;
    if (bpf_probe_read_user(&op_cmd, sizeof(op_cmd), uarg) != 0) {
        return 0;
    }

    // Control opcodes each handle themselves and return; the data opcodes
    // (send/recv) fall through to the connection/payload path below.
    switch (op_cmd) {
    case k_ioctl_java_vt_mount: {
        // The agent reports, on every VirtualThread.mount(), the logical
        // thread id now mounted on this carrier; the current kernel thread
        // IS the carrier.
        u64 vt_id = 0;
        if (bpf_probe_read_user(&vt_id, sizeof(vt_id), uarg + 1) != 0) {
            return 0;
        }

        pid_key_t carrier = {0};
        task_tid(&carrier);

        bpf_dbg_printk("Java VT mount carrier=%d vt=%lld", carrier.tid, vt_id);
        bpf_map_update_elem(&java_vt_threads, &carrier, &vt_id, BPF_ANY);

        return 0;
    }
    case k_ioctl_java_vt_unmount: {
        // The mounted VT left this carrier: delete the entry so a carrier
        // with no mounted VT is never translated. mount/unmount for a
        // carrier always execute ON that carrier thread, so write and
        // delete are in program order.
        pid_key_t carrier = {0};
        task_tid(&carrier);

        bpf_dbg_printk("Java VT unmount carrier=%d", carrier.tid);
        bpf_map_delete_elem(&java_vt_threads, &carrier);

        return 0;
    }
    case k_ioctl_java_threads: {
        u64 parent_id = 0;
        if (bpf_probe_read_user(&parent_id, sizeof(parent_id), uarg + 1) != 0) {
            return 0;
        }

        pid_key_t child = {0};
        task_tid(&child);
        pid_key_t parent = child;
        const u32 parent_tid = tid_from_pid_tgid(parent_id);
        parent.tid = parent_tid;

        if (parent.tid == child.tid) {
            bpf_dbg_printk("self referencing thread %d, not recording", child.tid);
            return 0;
        }

        bpf_dbg_printk("Java thread mapping [%d] -> [%d]", parent.tid, child.tid);
        bpf_map_update_elem(&java_tasks, &child, &parent, BPF_ANY);

        // Walk the java_tasks chain to find the parent's server trace and
        // refresh traces_ctx_v1 for this child thread.
        trace_key_t t_key = {.p_key = parent, .extra_id = extra_runtime_id_with_task_id(parent_id)};
        tp_info_pid_t *server_tp = find_parent_java_trace(&t_key);

        if (server_tp && server_tp->valid) {
            obi_ctx__set(id, &server_tp->tp);
        } else {
            obi_ctx__del(id);
        }

        return 0;
    }
    default:
        break;
    }

    const u8 op = cmd_to_op(op_cmd);

    if (op == k_ioctl_invalid_op) {
        bpf_dbg_printk("unknown cmd=%d", op_cmd);
        return 0;
    }

    bpf_dbg_printk("op=%d, cmd=%d", op, op_cmd);

    pid_connection_info_t p_conn = {0};
    if (bpf_probe_read_user(&p_conn.conn, sizeof(p_conn.conn), uarg + 1) != 0) {
        return 0;
    }
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
    if (bpf_probe_read_user(&len, sizeof(len), uarg + 1 + sizeof(connection_info_t)) != 0) {
        return 0;
    }

    // Bound the parser-visible payload length before we touch the payload
    // pointer or hand it to the shared protocol path.
    u32 max_len = len;
    bpf_clamp_umax(max_len, k_ioctl_max_payload_len);

    bpf_dbg_printk("payload len=%d", max_len);

    if (max_len > 0) {
        unsigned char *buf = uarg + 1 + sizeof(connection_info_t) + sizeof(u32);
        // This path consumes one flat user pointer supplied from Java. The
        // security boundary here is "user memory vs. non-user memory", not
        // full range validation. We therefore verify that the claimed payload
        // starts and ends in user-readable memory before the generic tracer
        // consumes it, while keeping the rest of the generic buffer path
        // unchanged.
        unsigned char first = 0;
        if (bpf_probe_read_user(&first, sizeof(first), buf) != 0) {
            return 0;
        }
        unsigned char last = 0;
        if (bpf_probe_read_user(&last, sizeof(last), buf + max_len - 1) != 0) {
            return 0;
        }

        const u64 zero = 0;
        bpf_map_update_elem(&active_ssl_connections, &p_conn, &zero, BPF_ANY);
        handle_buf_with_connection(ctx, &p_conn, buf, max_len, WITH_SSL, op, orig_dport);
    }

    return 0;
}
