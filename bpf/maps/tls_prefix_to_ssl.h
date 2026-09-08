// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tls_record.h>

// Leading bytes of a TLS record mapped to the SSL that produced it.
//
// Entries span only the gap between the BIO write and the socket send, and only
// for connections whose peer is still unknown, so the population is one entry
// per connection currently being bound. Unmatched entries are reclaimed by LRU.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, tls_prefix_key_t);
    __type(value, tls_prefix_val_t);
    __uint(max_entries, MAX_CONCURRENT_TLS_CONNECTIONS);
    __uint(pinning, OBI_PIN_INTERNAL);
} tls_prefix_to_ssl SEC(".maps");
