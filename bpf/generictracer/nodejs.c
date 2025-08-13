// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/strings.h>

#include <logger/bpf_dbg.h>

#include <maps/nodejs_fd_map.h>

SEC("uprobe/node:uv_fs_access")
int BPF_KPROBE(obi_uv_fs_access, void *loop, void *req, const char *path) {
    (void)ctx;
    (void)loop;
    (void)req;

    // the obi nodejs agent (fdextractor.js) passes the file descriptor pair
    // to the ebpf layer by invoking uv_fs_access() with an invalid path:
    // /dev/null/obi/<fd1><fd2> where each fd is a left-zero-padded 4 digit
    // number
    static const char prefix[] = "/dev/null/obi";
    static const u8 prefix_size = sizeof(prefix) - 1;

    char buf[] = "/dev/null/obi/00000000";

    enum { k_fd1_offset = 14, k_fd2_offset = 18, k_max_fd_digits = 4 };

    if (bpf_probe_read_user(buf, sizeof(buf), path) != 0) {
        return 0;
    }

    if (obi_bpf_memcmp(prefix, buf, prefix_size) != 0) {
        return 0;
    }

    u32 fd1 = 0;
    u32 fd2 = 0;

    for (u8 i = 0; i < k_max_fd_digits; ++i) {
        fd1 *= 10;
        fd1 += buf[k_fd1_offset + i] - '0';
        fd2 *= 10;
        fd2 += buf[k_fd2_offset + i] - '0';
    }

    bpf_dbg_printk("nodejs_correlation: %s, fd1 = %u, fd2 = %u", buf, fd1, fd2);

    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const u64 key = (pid_tgid << 32) | fd2;

    bpf_map_update_elem(&nodejs_fd_map, &key, &fd1, BPF_ANY);

    return 0;
}
