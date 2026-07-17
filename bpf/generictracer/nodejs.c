// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/event_defs.h>
#include <common/ringbuf.h>
#include <common/strings.h>
#include <common/tracing.h>

#include <generictracer/types/nodejs.h>

#include <logger/bpf_dbg.h>

#include <maps/fd_to_connection.h>
#include <maps/nodejs_fd_map.h>

#include <pid/pid.h>

#include <shared/obi_ctx.h>

volatile const u64 nodejs_runtime_metrics_enabled = 0;

struct nodejs_eventloop_event _nodejs_eventloop_event = {};

enum {
    k_delim_offset = 13,
    k_fd1_offset = 14,
    k_fd2_offset = 18,
    k_ctx_fd_offset = 18,
    k_max_fd_digits = 4
};

enum {
    k_rt_kind_offset = 14,    // 'r' of "-rt/", 'c' of "-ctx/"
    k_rt_payload_offset = 17, // first hex char after "/dev/null/obi-rt/"
    k_rt_field_hex_len = 16,  // one u64 as fixed-width lowercase hex
    k_rt_field_count = 10,
};

static __always_inline int handle_async_switch(char *buf, const u64 pid_tgid) {
    u32 fd = 0;
    for (u8 i = 0; i < k_max_fd_digits; ++i) {
        fd *= 10;
        fd += buf[k_ctx_fd_offset + i] - '0';
    }

    bpf_dbg_printk("nodejs_async_switch: %s, pid_tgid = %llx, fd = %u", buf, pid_tgid, fd);

    const fd_key fkey = {.pid_tgid = pid_tgid, .fd = (s32)fd};
    const connection_info_t *conn = bpf_map_lookup_elem(&fd_to_connection, &fkey);
    if (!conn) {
        obi_ctx__del(pid_tgid);
        return 0;
    }

    const tp_info_pid_t *tp = trace_info_for_connection(conn, TRACE_TYPE_SERVER);
    if (tp && tp->valid) {
        obi_ctx__set(pid_tgid, &tp->tp);
    } else {
        obi_ctx__del(pid_tgid);
    }

    return 0;
}

// Decodes the fixed-width runtime-metrics payload emitted by fdextractor.js:
// /dev/null/obi-rt/<10 x 16 lowercase hex chars> (field order and semantics
// in types/nodejs.h). Any non-hex character aborts the parse — a short or
// malformed path never produces an event.
static __always_inline int handle_runtime_metrics(const char *path, const u64 pid_tgid) {
    if (!nodejs_runtime_metrics_enabled) {
        return 0;
    }

    // Read one byte past the payload and require the path to end exactly
    // there. The pid fields come from the kernel, so a foreign process
    // calling fs.access() on a path that happens to share the obi-rt prefix
    // could otherwise get residual heap bytes decoded into a plausible but
    // wrong event attributed to itself; the exact-length check turns that
    // into a dropped event.
    unsigned char payload[k_rt_field_count * k_rt_field_hex_len + 1];
    if (bpf_probe_read_user(payload, sizeof(payload), path + k_rt_payload_offset) != 0) {
        return 0;
    }
    if (payload[sizeof(payload) - 1] != '\0') {
        return 0;
    }

    u64 vals[k_rt_field_count];
    for (u8 f = 0; f < k_rt_field_count; ++f) {
        u64 v = 0;
        for (u8 i = 0; i < k_rt_field_hex_len; ++i) {
            const unsigned char c = payload[f * k_rt_field_hex_len + i];
            u8 digit;
            if (c >= '0' && c <= '9') {
                digit = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                digit = c - 'a' + 10;
            } else {
                return 0;
            }
            v = (v << 4) | digit;
        }
        vals[f] = v;
    }

    struct nodejs_eventloop_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    bpf_memset(e, 0, sizeof(*e));
    e->type = EVENT_NODEJS_EVENTLOOP;
    e->timestamp = bpf_ktime_get_ns();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int ns_pid = 0;
    int ns_ppid = 0;
    u32 pid_ns_id = 0;
    ns_pid_ppid(task, &ns_pid, &ns_ppid, &pid_ns_id);

    e->global_pid = pid_from_pid_tgid(pid_tgid);
    e->global_tid = tid_from_pid_tgid(pid_tgid);
    e->ns_pid = (u32)ns_pid;
    e->ns_tid = get_task_tid();
    e->pid_ns_id = pid_ns_id;

    e->elu_idle_ns = vals[0];
    e->elu_active_ns = vals[1];
    e->delay_min_ns = vals[2];
    e->delay_max_ns = vals[3];
    e->delay_mean_ns = vals[4];
    e->delay_stddev_ns = vals[5];
    e->delay_p50_ns = vals[6];
    e->delay_p90_ns = vals[7];
    e->delay_p99_ns = vals[8];
    e->delay_count = vals[9];

    bpf_dbg_printk("nodejs_runtime_metrics: pid_tgid=%llx idle=%llu active=%llu",
                   pid_tgid,
                   e->elu_idle_ns,
                   e->elu_active_ns);

    bpf_ringbuf_submit(e, get_flags());
    return 0;
}

static __always_inline int handle_fd_correlation(char *buf, const u64 pid_tgid) {
    u32 fd1 = 0;
    u32 fd2 = 0;

    for (u8 i = 0; i < k_max_fd_digits; ++i) {
        fd1 *= 10;
        fd1 += buf[k_fd1_offset + i] - '0';
        fd2 *= 10;
        fd2 += buf[k_fd2_offset + i] - '0';
    }

    bpf_dbg_printk("nodejs_fd_correlation: %s, fd1 = %u, fd2 = %u", buf, fd1, fd2);

    const u64 key = (pid_tgid << 32) | fd2;

    bpf_map_update_elem(&nodejs_fd_map, &key, &fd1, BPF_ANY);

    return 0;
}

SEC("uprobe/node:uv_fs_access")
int BPF_KPROBE(obi_uv_fs_access, void *loop, void *req, const char *path) {
    (void)ctx;
    (void)loop;
    (void)req;

    // the obi nodejs agent (fdextractor.js) passes signals to the ebpf layer
    // by invoking uv_fs_access() with a fake path. Three formats are used:
    //
    // 1. fd pair correlation (outgoing -> incoming):
    //    /dev/null/obi/<fd1><fd2>  — each fd is a left-zero-padded 4-digit number
    //
    // 2. async context switch (before-hook fires before each JS callback):
    //    /dev/null/obi-ctx/<fd>    — 4-digit incoming fd for the current async context
    //
    // 3. runtime metrics (1s sampling interval in the agent):
    //    /dev/null/obi-rt/<10 x 16 hex chars> — eventloop metrics payload
    //
    // All paths share the prefix "/dev/null/obi" (13 chars). The character at
    // position 13 distinguishes format 1 ('/') from formats 2 and 3 ('-');
    // position 14 then distinguishes format 2 ('c') from format 3 ('r').
    static const char prefix[] = "/dev/null/obi";
    static const u8 prefix_size = sizeof(prefix) - 1;

    // Sized for formats 1 and 2 (both exactly 22 characters + null
    // terminator); format 3 is longer and is re-read from the original user
    // pointer in handle_runtime_metrics.
    char buf[] = "/dev/null/obi/00000000";

    if (bpf_probe_read_user(buf, sizeof(buf), path) != 0) {
        return 0;
    }

    if (obi_bpf_memcmp(prefix, buf, prefix_size) != 0) {
        return 0;
    }

    const u64 pid_tgid = bpf_get_current_pid_tgid();

    // Async context switch: /dev/null/obi-ctx/XXXX
    // Fires from the async_hooks 'before' callback in fdextractor.js to refresh
    // traces_ctx_v1 before each JS callback.
    // Runtime metrics: /dev/null/obi-rt/<payload> — needs the original user
    // pointer because the payload extends past the 23-byte prefix buffer.
    if (buf[k_delim_offset] == '-') {
        if (buf[k_rt_kind_offset] == 'r') {
            return handle_runtime_metrics(path, pid_tgid);
        }
        return handle_async_switch(buf, pid_tgid);
    }
    // fd pair correlation: /dev/null/obi/<fd1><fd2>
    return handle_fd_correlation(buf, pid_tgid);
}
