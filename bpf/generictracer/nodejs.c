// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/strings.h>
#include <common/tracing.h>

#include <logger/bpf_dbg.h>

#include <maps/fd_to_connection.h>
#include <maps/nodejs_fd_map.h>

#include <shared/obi_ctx.h>

enum {
    k_delim_offset = 13,
    k_fd1_offset = 14,
    k_fd2_offset = 18,
    k_ctx_fd_offset = 18,
    k_max_fd_digits = 4
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
    // by invoking uv_fs_access() with a fake path. Two formats are used:
    //
    // 1. fd pair correlation (outgoing -> incoming):
    //    /dev/null/obi/<fd1><fd2>  — each fd is a left-zero-padded 4-digit number
    //
    // 2. async context switch (before-hook fires before each JS callback):
    //    /dev/null/obi-ctx/<fd>    — 4-digit incoming fd for the current async context
    //
    // Both paths share the prefix "/dev/null/obi" (13 chars). The character at
    // position 13 distinguishes the two formats:
    //   '/'  -> format 1 (fd pair)
    //   '-'  -> format 2 (context switch, "-ctx/" follows)
    static const char prefix[] = "/dev/null/obi";
    static const u8 prefix_size = sizeof(prefix) - 1;

    // Buffer sized to hold the longest path + null terminator.
    // Both formats are exactly 22 characters long.
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
    if (buf[k_delim_offset] == '-') {
        return handle_async_switch(buf, pid_tgid);
    }
    // fd pair correlation: /dev/null/obi/<fd1><fd2>
    return handle_fd_correlation(buf, pid_tgid);
}
