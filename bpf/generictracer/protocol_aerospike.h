// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>

#include <generictracer/maps/protocol_cache.h>

#include <logger/bpf_dbg.h>

// Aerospike native client protocol ("proto" version 2).
//
// Every message starts with an 8-byte proto header:
//   version(1) = 2, type(1), size(6, big-endian) = body length
// Only type-3 AS_MSG data frames produce spans. Their body begins with a fixed
// 22-byte as_msg header whose first byte is its own size (22), which makes the
// (version, type, header_sz) triple a strong classification signature for both
// requests and responses. Parsing happens in userspace:
// pkg/ebpf/common/aerospike_detect_transform.go.

enum {
    k_aerospike_proto_header_len = 8,
    k_aerospike_proto_version = 2,
    k_aerospike_msg_type_as_msg = 3,
    k_aerospike_as_msg_header_len = 22,
    // largest declared proto body we treat as plausibly Aerospike;
    // matches asMaxBodyLen in the userspace parser
    k_aerospike_max_body_len = 128 * 1024 * 1024,
};

static __always_inline u64 aerospike_body_len(const unsigned char *hdr) {
    return ((u64)hdr[2] << 40) | ((u64)hdr[3] << 32) | ((u64)hdr[4] << 24) | ((u64)hdr[5] << 16) |
           ((u64)hdr[6] << 8) | (u64)hdr[7];
}

static __always_inline u8 is_aerospike(connection_info_t *conn_info,
                                       const unsigned char *data,
                                       u32 data_len,
                                       enum protocol_type *protocol_type) {
    if (*protocol_type == k_protocol_type_aerospike) {
        return 1;
    }
    if (*protocol_type != k_protocol_type_unknown) {
        return 0;
    }

    // require the full proto + as_msg headers so the signature check below is meaningful
    if (data_len < k_aerospike_proto_header_len + k_aerospike_as_msg_header_len) {
        return 0;
    }

    unsigned char hdr[k_aerospike_proto_header_len + 1];
    if (bpf_probe_read(hdr, sizeof(hdr), data) != 0) {
        return 0;
    }

    if (hdr[0] != k_aerospike_proto_version || hdr[1] != k_aerospike_msg_type_as_msg ||
        hdr[8] != k_aerospike_as_msg_header_len) {
        return 0;
    }

    const u64 body_len = aerospike_body_len(hdr);
    if (body_len < k_aerospike_as_msg_header_len || body_len > k_aerospike_max_body_len) {
        return 0;
    }

    *protocol_type = k_protocol_type_aerospike;
    bpf_map_update_elem(&protocol_cache, conn_info, protocol_type, BPF_ANY);
    return 1;
}
