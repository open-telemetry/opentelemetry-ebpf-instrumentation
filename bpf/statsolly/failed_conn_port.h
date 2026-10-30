// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>

#include <common/connection_info.h>
#include <common/sockaddr.h>

// A connect() that fails before sending its SYN may not own a local port in
// this attempt: after connect(AF_UNSPEC), inet_sport still holds the port of
// the previous connection. tcp_disconnect() resets segs_out and the SYN
// increments it, so such an attempt keeps the zeroed skc_num.
static __always_inline bool failed_connect_owns_inet_sport(const int oldstate, const u32 segs_out) {
    return oldstate != TCP_SYN_SENT || segs_out > 0;
}

static __always_inline bool
parse_failed_sock_info(struct sock *sk, const int oldstate, connection_info_t *conn) {
    const u32 segs_out = BPF_CORE_READ((struct tcp_sock *)sk, segs_out);
    if (!failed_connect_owns_inet_sport(oldstate, segs_out)) {
        return parse_sock_info(sk, conn);
    }

    return parse_full_sock_info(sk, conn);
}
