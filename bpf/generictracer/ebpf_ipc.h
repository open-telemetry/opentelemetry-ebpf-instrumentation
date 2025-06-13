#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>

#include <logger/bpf_dbg.h>

#include <maps/nodejs_fd_map.h>

static const char k_otel_ipc_sock_prefix[] = "otel-ebpf-ipc";

enum { k_ebpf_ipc_magic = 0xbe14be14 };

struct hdr_t {
    u32 marker;
    u32 fd1; // fd of the server call
    u32 fd2; // fd of the client call
};

static __always_inline int is_ebpf_ipc(const struct sock *sk) {
    struct unix_sock *u_sock = (struct unix_sock *)sk;

    struct unix_sock *peer;

    if (bpf_probe_read_kernel(&peer, sizeof(peer), &u_sock->peer) != 0) {
        bpf_dbg_printk("reading peer failed");
        return 0;
    }

    struct unix_address *u_addr;

    if (bpf_probe_read_kernel(&u_addr, sizeof(u_addr), &peer->addr) != 0) {
        bpf_dbg_printk("reading peer address failed");
        return 0;
    }

    struct sockaddr_un *sunaddr = &u_addr->name[0];

    char path[sizeof(k_otel_ipc_sock_prefix)];

    if (bpf_probe_read_kernel(path, sizeof(path), &sunaddr->sun_path) != 0) {
        bpf_dbg_printk("failed to read peer unix sock path");

        return 0;
    }

    const u8 is_ipc =
        __builtin_memcmp(k_otel_ipc_sock_prefix, &path[1], sizeof(k_otel_ipc_sock_prefix)) == 0;

    if (is_ipc) {
        bpf_dbg_printk("found otel-ebpf_ipc");
    }

    return is_ipc;
}

// at the moment, this is only used by the nodejs agent (fdextractor) to
// communicate the file descriptors of the incoming and outgoing calls - this
// could be extended in the future (and potentially become a tail call target)
static __always_inline int
handle_ebpf_ipc(const struct sock *sk, const void *buf, size_t buf_size) {
    if (!is_ebpf_ipc(sk)) {
        return 0;
    }

    if (buf_size < sizeof(struct hdr_t)) {
        return 0;
    }

    const struct hdr_t *hdr = (const struct hdr_t *)buf;

    const u32 marker = bpf_ntohl(hdr->marker);
    const s32 fd1 = bpf_ntohl(hdr->fd1);
    const s32 fd2 = bpf_ntohl(hdr->fd2);

    if (marker != k_ebpf_ipc_magic) {
        return 0;
    }

    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const u64 key = (pid_tgid << 32) | fd2;
    bpf_map_update_elem(&nodejs_fd_map, &key, &fd1, BPF_ANY);

    bpf_dbg_printk("[ebpf_ipc] pid=%u, fd1=%d, fd2=%d", pid_tgid, fd1, fd2);

    return 1;
}
