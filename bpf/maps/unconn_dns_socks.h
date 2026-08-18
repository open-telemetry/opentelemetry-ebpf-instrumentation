// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

// The most recent DNS query sent over an unconnected UDP socket, keyed by
// (u64)struct sock *. The local endpoint is recorded alongside the timestamp so
// that a recycled struct sock * address cannot inherit the classification of
// the socket that previously occupied it.
//
// There is deliberately no outstanding-query counter. A resolver may have
// several queries in flight on one socket (musl sends A and AAAA in parallel),
// and a counter decremented per answer would leave the later answers
// unclassified. The timestamp bounds how long the socket stays eligible, and it
// is a single aligned store, so concurrent sends cannot corrupt it.
typedef struct unconn_dns_sock {
    u64 last_query_ns;
    u8 s_addr[IP_V6_ADDR_LEN];
    u16 s_port;
    u8 _pad[6];
} unconn_dns_sock_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, unconn_dns_sock_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} unconn_dns_socks SEC(".maps");
