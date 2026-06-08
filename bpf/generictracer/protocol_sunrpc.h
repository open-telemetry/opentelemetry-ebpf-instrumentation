// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>

#include <generictracer/maps/protocol_cache.h>

enum {
    k_sunrpc_rm_last_frag = 0x80000000,
    k_sunrpc_rm_frag_len_mask = 0x7fffffff,
    k_sunrpc_max_record = 1 << 20,
    // Smallest valid RPC message: REPLY denied with AUTH_ERROR (xid, msg_type, reply_stat,
    // reject_stat, auth_stat). CALL and other replies enforce larger bounds in their parsers.
    k_sunrpc_min_record = 20,
    k_sunrpc_rpc_version = 2,
    k_sunrpc_msg_call = 0,
    k_sunrpc_msg_reply = 1,
    k_sunrpc_reply_accepted = 0,
    k_sunrpc_reply_denied = 1,
    k_sunrpc_reject_rpc_mismatch = 0,
    k_sunrpc_reject_auth_error = 1,
    k_sunrpc_max_auth_stat = 13,
};

// auth_flavor_t values from RFC 5531 / IANA RPC Authentication Numbers.
enum sunrpc_auth_flavor : u8 {
    k_sunrpc_auth_null = 0,
    k_sunrpc_auth_unix = 1,
    k_sunrpc_auth_short = 2,
    k_sunrpc_auth_des = 3,
    k_sunrpc_auth_kerb = 4,
    k_sunrpc_auth_rsa = 5,
    k_sunrpc_auth_rpcsec_gss = 6,
};

static __always_inline u32 sunrpc_read_u32_be(const unsigned char *p) {
    u32 v = 0;
    bpf_probe_read(&v, sizeof(v), p);
    return bpf_ntohl(v);
}

static __always_inline u8 sunrpc_valid_program(u32 prog) {
    if (prog >= 100000 && prog <= 101000) {
        return 1;
    }
    if (prog >= 0x20000000 && prog <= 0x2fffffff) {
        return 1;
    }
    return 0;
}

static __always_inline u8 sunrpc_valid_auth_flavor(u32 flavor) {
    switch (flavor) {
    case k_sunrpc_auth_null:
    case k_sunrpc_auth_unix:
    case k_sunrpc_auth_short:
    case k_sunrpc_auth_des:
    case k_sunrpc_auth_kerb:
    case k_sunrpc_auth_rsa:
    case k_sunrpc_auth_rpcsec_gss:
        return 1;
    default:
        return 0;
    }
}

// Validate opaque_auth at data[*off] and advance *off past flavor, length, and padded body.
// For CALL, this validates cred then verf (same opaque_auth layout, 2 function calls); for REPLY,
// this validates verf only (1 function call).
static __always_inline int
sunrpc_skip_opaque_auth(const unsigned char *data, u32 data_len, u32 *off) {
    if (*off > data_len || data_len - *off < 8) {
        return -1;
    }

    const u32 flavor = sunrpc_read_u32_be(data + *off);
    const u32 length = sunrpc_read_u32_be(data + *off + 4);
    if (!sunrpc_valid_auth_flavor(flavor)) {
        return -1;
    }

    const u32 remaining = data_len - *off - 8;
    if (length > remaining) {
        return -1;
    }

    const u32 padded = (length + 3) & ~3U;
    if (padded > remaining) {
        return -1;
    }

    *off += 8 + padded;
    return 0;
}

static __always_inline u8 sunrpc_parse_call_msg(const unsigned char *rpc, u32 rpc_len) {
    if (rpc_len < 32) {
        return 0;
    }

    if (sunrpc_read_u32_be(rpc + 4) != k_sunrpc_msg_call) {
        return 0;
    }
    if (sunrpc_read_u32_be(rpc + 8) != k_sunrpc_rpc_version) {
        return 0;
    }

    const u32 prog = sunrpc_read_u32_be(rpc + 12);
    const u32 vers = sunrpc_read_u32_be(rpc + 16);
    const u32 proc = sunrpc_read_u32_be(rpc + 20);
    if (!sunrpc_valid_program(prog) || vers == 0 || proc > 0xffff) {
        return 0;
    }

    // CALL: cred then verf (same opaque_auth layout); off walks rpc, each skip checks
    // rpc+off and advances off.
    u32 off = 24;
    if (sunrpc_skip_opaque_auth(rpc, rpc_len, &off) != 0) {
        return 0;
    }
    if (sunrpc_skip_opaque_auth(rpc, rpc_len, &off) != 0) {
        return 0;
    }

    return 1;
}

static __always_inline u8 sunrpc_validate_rejected_reply(const unsigned char *body, u32 body_len) {
    if (body_len < 4) {
        return 0;
    }

    const u32 reject_stat = sunrpc_read_u32_be(body);
    switch (reject_stat) {
    case k_sunrpc_reject_rpc_mismatch:
        return body_len >= 12;
    case k_sunrpc_reject_auth_error: {
        if (body_len < 8) {
            return 0;
        }
        const u32 auth_stat = sunrpc_read_u32_be(body + 4);
        return auth_stat <= k_sunrpc_max_auth_stat;
    }
    default:
        return 0;
    }
}

static __always_inline u8 sunrpc_parse_reply_msg(const unsigned char *rpc, u32 rpc_len) {
    if (rpc_len < 16) {
        return 0;
    }

    if (sunrpc_read_u32_be(rpc + 4) != k_sunrpc_msg_reply) {
        return 0;
    }

    const u32 reply_stat = sunrpc_read_u32_be(rpc + 8);
    if (reply_stat > k_sunrpc_reply_denied) {
        return 0;
    }
    if (reply_stat == k_sunrpc_reply_denied) {
        if (rpc_len < 12) {
            return 0;
        }
        return sunrpc_validate_rejected_reply(rpc + 12, rpc_len - 12);
    }

    // ACCEPTED reply: reply verf only, then accept_stat at the advanced off.
    u32 off = 12;
    if (sunrpc_skip_opaque_auth(rpc, rpc_len, &off) != 0) {
        return 0;
    }
    if (off + 4 > rpc_len) {
        return 0;
    }

    const u32 accept_stat = sunrpc_read_u32_be(rpc + off);
    return accept_stat <= 5;
}

static __always_inline u8 sunrpc_record_looks_valid(const unsigned char *data, u32 data_len) {
    if (data_len < 4) {
        return 0;
    }

    const u32 rm = sunrpc_read_u32_be(data);
    if (!(rm & k_sunrpc_rm_last_frag)) {
        return 0;
    }

    const u32 rec_len = rm & k_sunrpc_rm_frag_len_mask;
    if (rec_len < k_sunrpc_min_record || rec_len > k_sunrpc_max_record) {
        return 0;
    }
    if (data_len < 4 + rec_len) {
        return 0;
    }

    const unsigned char *rpc = data + 4;
    switch (sunrpc_read_u32_be(rpc + 4)) {
    case k_sunrpc_msg_call:
        return sunrpc_parse_call_msg(rpc, rec_len);
    case k_sunrpc_msg_reply:
        return sunrpc_parse_reply_msg(rpc, rec_len);
    default:
        return 0;
    }
}

static __always_inline u8 is_sunrpc(connection_info_t *conn_info,
                                    const unsigned char *data,
                                    u32 data_len,
                                    enum protocol_type *protocol_type) {
    if (*protocol_type == k_protocol_type_sunrpc) {
        return 1;
    }
    if (*protocol_type != k_protocol_type_unknown) {
        return 0;
    }
    if (!sunrpc_record_looks_valid(data, data_len)) {
        bpf_dbg_printk("is_sunrpc: not a valid SunRPC record");
        return 0;
    }

    *protocol_type = k_protocol_type_sunrpc;
    bpf_map_update_elem(&protocol_cache, conn_info, protocol_type, BPF_ANY);
    bpf_dbg_printk("Found SunRPC connection");
    return 1;
}
