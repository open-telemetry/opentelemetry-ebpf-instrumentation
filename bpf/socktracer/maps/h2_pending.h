// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/common.h>
#include <common/pin_internal.h>

// Identifies an in-flight HTTP/2 stream awaiting its response. Keyed by the
// socket cookie (a stable socket identity, so no tuple normalization is needed)
// plus the stream id, so concurrent multiplexed streams on one connection map to
// distinct entries. _pad zeroes the tail of the key struct so the hash never
// reads uninitialized bytes.
typedef struct h2_pending_key {
    u64 cookie;
    u32 stream_id;
    u32 _pad;
} h2_pending_key_t;

// Holds the request half of an HTTP/2 exchange until its response arrives on the
// same socket. The request side stores the tcp_req_t here; the response side
// looks it up, fills rbuf, and emits one combined event (see emit_http2_buffer).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, h2_pending_key_t);
    __type(value, tcp_req_t);
    __uint(max_entries, 4096);
    __uint(pinning, OBI_PIN_INTERNAL);
} h2_pending SEC(".maps");
