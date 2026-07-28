// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/connection_info.h>
#include <common/fd_info.h>
#include <common/strings.h>

#include <logger/bpf_dbg.h>

#include <maps/nodejs_deno_map.h>

#include <pid/pid.h>

// The injected Deno agent (fdextractor_deno.js) signals the eBPF layer by
// calling fs.accessSync() on a magic path, which in Deno issues a statx(2)
// syscall (Deno has no libuv, so the uv_fs_access uprobe used for Node cannot
// attach). The path encodes the outgoing (client) and incoming (server)
// connection endpoints so that trace_parent can resolve the parent server
// trace of a client call:
//
//   /dev/null/obi-dn/<clientPart><serverPart>
//
// Each part is 36 lowercase-hex chars: a 16-byte address (IPv4 stored as a
// v4-in-v6 mapped address, matching connection_info) followed by a 2-byte port.
enum {
    k_deno_prefix_len = 17, // "/dev/null/obi-dn/"
    k_deno_addr_hex = 32,   // 16 bytes
    k_deno_port_hex = 4,    // 2 bytes
    k_deno_part_hex = 36,   // addr + port
    k_deno_buf_len = 90,    // prefix(17) + payload(72) + null terminator
    k_deno_client_off = k_deno_prefix_len,
    k_deno_server_off = k_deno_prefix_len + k_deno_part_hex,
};

static __always_inline u8 hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return (u8)(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return (u8)(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
        return (u8)(c - 'A' + 10);
    }
    return 0;
}

// Decode a 36-hex-char endpoint (32 addr + 4 port) at buf[off] into part.
static __always_inline void
decode_deno_part(const char *buf, u32 off, u32 pid, u8 type, connection_info_part_t *part) {
    for (u8 i = 0; i < IP_V6_ADDR_LEN; ++i) {
        const u32 h = off + ((u32)i * 2);
        part->addr[i] = (u8)((hex_nibble(buf[h]) << 4) | hex_nibble(buf[h + 1]));
    }

    u16 port = 0;
    const u32 p = off + k_deno_addr_hex;
    for (u8 i = 0; i < k_deno_port_hex; ++i) {
        port = (u16)((port << 4) | hex_nibble(buf[p + i]));
    }

    part->port = port;
    part->pid = pid;
    part->type = type;
}

SEC("kprobe/sys_statx")
// int statx(int dirfd, const char *pathname, int flags, unsigned mask, struct statx *buf)
int BPF_KPROBE(obi_kprobe_sys_statx) {
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    // unwrap the syscall arguments in __ctx
    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);

    const char *path = 0;
    bpf_probe_read(&path, sizeof(path), (void *)&PT_REGS_PARM2(__ctx));

    if (!path) {
        return 0;
    }

    char buf[k_deno_buf_len];

    // This kprobe fires for every statx of every instrumented process. Read only
    // the prefix first so a non-Deno path is rejected after copying 17 bytes
    // instead of the full path payload.
    if (bpf_probe_read_user(buf, k_deno_prefix_len, path) != 0) {
        return 0;
    }

    static const char prefix[] = "/dev/null/obi-dn/";

    if (obi_bpf_memcmp(prefix, buf, k_deno_prefix_len) != 0) {
        return 0;
    }

    // Prefix matched: copy the endpoint payload that follows.
    if (bpf_probe_read_user(buf + k_deno_prefix_len,
                            k_deno_buf_len - k_deno_prefix_len,
                            path + k_deno_prefix_len) != 0) {
        return 0;
    }

    const u32 pid = pid_from_pid_tgid(id);

    connection_info_part_t client_part = {};
    connection_info_part_t server_part = {};

    decode_deno_part(buf, k_deno_client_off, pid, FD_CLIENT, &client_part);
    decode_deno_part(buf, k_deno_server_off, pid, FD_SERVER, &server_part);

    bpf_dbg_printk("deno_correlate: pid=%d, client_port=%d, server_port=%d",
                   pid,
                   client_part.port,
                   server_part.port);

    bpf_map_update_elem(&nodejs_deno_map, &client_part, &server_part, BPF_ANY);

    return 0;
}
