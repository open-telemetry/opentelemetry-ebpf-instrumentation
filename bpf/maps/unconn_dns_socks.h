// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

// Outstanding DNS queries sent over an unconnected UDP socket, keyed by
// (u64)struct sock *. The local endpoint is recorded alongside the outstanding
// query count so that a recycled struct sock * address cannot inherit the
// classification of the socket that previously occupied it.
typedef struct unconn_dns_sock {
    u64 last_query_ns;
    u8 s_addr[IP_V6_ADDR_LEN];
    u16 s_port;
    u16 pending;
    u8 _pad[4];
} unconn_dns_sock_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, unconn_dns_sock_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} unconn_dns_socks SEC(".maps");
