// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Context for future maintainers: this code was added to mitigate a bug in the Linux kernel that
// was fixed a few weeks after being reported (July 2026), but had already reached some users'
// production environments from version 6.x onwards (via backports). This mitigation code will be
// kept here for an undetermined, long period of time, until it is safe to assume that no trace of
// the buggy kernel versions remains.
// Original report impacting OBI users: https://github.com/grafana/beyla/issues/2941
// Kernel bug fix and merge notification thread:
// https://lore.kernel.org/bpf/20260708-fionread-no-verdict-v3-0-b4ee31b3af53@coralogix.com/

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>

#include <logger/bpf_dbg.h>

#include <maps/tracked_sock_cookies.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// Kernels with commit 929e30f93125 report FIONREAD=0 for sockets in a
// sockhash without a verdict program; rewrite the user-visible result with
// the real queue length (tcp_inq) after the kernel's put_user
enum { k_fionread = 0x541B };

typedef struct fionread_fix {
    u64 arg;
    struct sock *sk;
} fionread_fix_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(fionread_fix_t));
} fionread_inflight SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_ioctl")
int obi_fionread_fixup_enter(struct trace_event_raw_sys_enter *ctx) {
    if ((u32)ctx->args[1] != k_fionread) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
    const u32 fd = (u32)ctx->args[0];

    if (fd >= BPF_CORE_READ(fdt, max_fds)) {
        return 0;
    }

    struct file **fd_arr = BPF_CORE_READ(fdt, fd);
    struct file *file = NULL;
    bpf_probe_read_kernel(&file, sizeof(file), fd_arr + fd);

    if (!file) {
        return 0;
    }

    struct socket *sock = BPF_CORE_READ(file, private_data);
    if (!sock) {
        return 0;
    }

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk) {
        return 0;
    }

    // a non-socket file's private_data cannot yield a tracked cookie
    const u64 cookie = BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);

    if (!bpf_map_lookup_elem(&tracked_sock_cookies, &cookie)) {
        return 0;
    }

    const u64 id = bpf_get_current_pid_tgid();
    fionread_fix_t fix = {.arg = ctx->args[2], .sk = sk};
    bpf_map_update_elem(&fionread_inflight, &id, &fix, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ioctl")
int obi_fionread_fixup_exit(struct trace_event_raw_sys_exit *ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const fionread_fix_t *fix = bpf_map_lookup_elem(&fionread_inflight, &id);

    if (!fix) {
        return 0;
    }

    struct sock *sk = fix->sk;
    void *arg = (void *)fix->arg;

    bpf_map_delete_elem(&fionread_inflight, &id);

    if (ctx->ret != 0) {
        return 0;
    }

    // mirrors tcp_inq(); the fd is held for the whole syscall so sk is live
    const u8 state = BPF_CORE_READ(sk, __sk_common.skc_state);

    if (state == TCP_SYN_SENT || state == TCP_SYN_RECV) {
        return 0;
    }

    struct tcp_sock *tp = (struct tcp_sock *)sk;
    const u32 rcv_nxt = BPF_CORE_READ(tp, rcv_nxt);
    const u32 copied_seq = BPF_CORE_READ(tp, copied_seq);
    int inq = (int)(rcv_nxt - copied_seq);

    const unsigned long flags = BPF_CORE_READ(sk, __sk_common.skc_flags);

    if (inq > 0 && (flags & (1UL << SOCK_DONE))) {
        inq--;
    }

    if (inq < 0) {
        inq = 0;
    }

    const long err = bpf_probe_write_user(arg, &inq, sizeof(inq));
    bpf_dbg_printk("fionread fix inq=%d err=%ld", inq, err);

    return 0;
}
