// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_endian.h>

#include <common/protocol_defs.h>

#include <logger/bpf_dbg.h>

#include <maps/sock_dir.h>

// max IPv6+port: "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535" = 48 chars
enum { k_addr_buf_len = 48 };

static __always_inline void format_in_addr(__be32 addr, u16 port, char buf[k_addr_buf_len]) {
    BPF_SNPRINTF(buf,
                 k_addr_buf_len,
                 "%u.%u.%u.%u:%u",
                 (addr) & 0xFF,
                 (addr >> 8) & 0xFF,
                 (addr >> 16) & 0xFF,
                 (addr >> 24) & 0xFF,
                 port);
}

static __always_inline void format_sock_addrs_v4(struct sock_common *skc,
                                                 char src_buf[k_addr_buf_len],
                                                 char dst_buf[k_addr_buf_len],
                                                 u16 src_port,
                                                 __be16 dst_port) {
    format_in_addr(BPF_CORE_READ(skc, skc_rcv_saddr), src_port, src_buf);
    format_in_addr(BPF_CORE_READ(skc, skc_daddr), bpf_ntohs(dst_port), dst_buf);
}

static __always_inline void
format_in6_addr(const struct in6_addr *addr, u16 port, char buf[k_addr_buf_len]) {
    BPF_SNPRINTF(buf,
                 k_addr_buf_len,
                 "[%x:%x:%x:%x:%x:%x:%x:%x]:%u",
                 bpf_ntohs(addr->in6_u.u6_addr16[0]),
                 bpf_ntohs(addr->in6_u.u6_addr16[1]),
                 bpf_ntohs(addr->in6_u.u6_addr16[2]),
                 bpf_ntohs(addr->in6_u.u6_addr16[3]),
                 bpf_ntohs(addr->in6_u.u6_addr16[4]),
                 bpf_ntohs(addr->in6_u.u6_addr16[5]),
                 bpf_ntohs(addr->in6_u.u6_addr16[6]),
                 bpf_ntohs(addr->in6_u.u6_addr16[7]),
                 port);
}

static __always_inline void format_sock_addrs_v6(struct sock_common *skc,
                                                 char src_buf[k_addr_buf_len],
                                                 char dst_buf[k_addr_buf_len],
                                                 u16 src_port,
                                                 __be16 dst_port) {
    struct in6_addr src6;
    struct in6_addr dst6;

    BPF_CORE_READ_INTO(&src6, skc, skc_v6_rcv_saddr);
    BPF_CORE_READ_INTO(&dst6, skc, skc_v6_daddr);

    format_in6_addr(&src6, src_port, src_buf);
    format_in6_addr(&dst6, bpf_ntohs(dst_port), dst_buf);
}

static __always_inline void format_sock_addrs(struct sock_common *skc,
                                              char src_buf[k_addr_buf_len],
                                              char dst_buf[k_addr_buf_len]) {
    const u16 family = BPF_CORE_READ(skc, skc_family);
    const __be16 dst_port = BPF_CORE_READ(skc, skc_dport);
    const u16 src_port = BPF_CORE_READ(skc, skc_num);

    if (family == AF_INET) {
        format_sock_addrs_v4(skc, src_buf, dst_buf, src_port, dst_port);
    } else {
        format_sock_addrs_v6(skc, src_buf, dst_buf, src_port, dst_port);
    }
}

SEC("iter/tcp")
int obi_sk_iter_tcp(struct bpf_iter__tcp *ctx) {
    struct sock_common *skc = ctx->sk_common;

    if (!skc) {
        return 0;
    }

    const u64 cookie = bpf_get_socket_cookie(skc);

    char src_buf[k_addr_buf_len] = {};
    char dst_buf[k_addr_buf_len] = {};

    format_sock_addrs(skc, src_buf, dst_buf);

    struct seq_file *seq = ctx->meta->seq;

    BPF_SEQ_PRINTF(seq, "Tracking socket cookie=%llu src=%s dst=%s\n", cookie, src_buf, dst_buf);

    bpf_d_printk("Tracking socket cookie=%llu src=%s dst=%s", cookie, src_buf, dst_buf);

    if (bpf_map_update_elem(&sock_dir, &cookie, skc, BPF_NOEXIST) != 0) {
        bpf_dbg_printk("Failed to track sock cookie=%llu", cookie);
    }

    return 0;
}
