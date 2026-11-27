// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/protocol_defs.h>

// tcp_rcv_state_process() aborts sockets in these states on data after a read shutdown
static __always_inline bool tcp_abort_on_data_state(const u8 state) {
    switch (state) {
    case TCP_FIN_WAIT1:
    case TCP_FIN_WAIT2:
    case TCP_CLOSE_WAIT:
    case TCP_CLOSING:
    case TCP_LAST_ACK:
        return true;
    default:
        return false;
    }
}

// a pure ACK carries no RST and cannot trigger the abort, which needs end_seq != seq
static __always_inline bool
segment_can_reset(const u8 tcp_flags, const u32 seq, const u32 end_seq) {
    return (tcp_flags & TCPHDR_RST) || end_seq != seq;
}

static __always_inline bool received_reset_is_local_abort(const u8 state, const u8 *seg_rst) {
    return tcp_abort_on_data_state(state) && seg_rst && !*seg_rst; // no RST on the wire
}
