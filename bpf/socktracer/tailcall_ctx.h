// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>
#include <common/egress_key.h>
#include <common/scratch_mem.h>
#include <common/tp_info.h>

typedef struct tailcall_ctx {
    u64 sock_cookie;
    pid_connection_info_t p_conn;
    u32 tp_write_off;
    egress_key_t e_key;
    u32 h2_frame_offset;     // start of the HEADERS frame in msg
    u32 h2_payload_len;      // HEADERS payload length
    u32 h2_hpack_offset;     // start of HPACK bytes (after PADDED/PRIORITY prefix)
    u32 h2_hpack_len;        // HPACK length (payload minus prefix and trailing pad)
    u32 h2_scan_pos;         // detect_h2 resume offset across tail calls
    u32 h2_tp_candidate_pos; // HPACK candidate offset (>= k_h2_max_hpack_scan = none)
    u16 tp_val_off;
    u8 niter;
    u8 h2_frames; // H2 HEADERS frames already processed this packet (capped)
    u8 _pad[8];
} tailcall_ctx;

SCRATCH_MEM(tailcall_ctx);
