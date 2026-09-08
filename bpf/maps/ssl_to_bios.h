// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/tls_record.h>
#include <common/pin_internal.h>

// Reverse of bio_to_ssl, so that an SSL going away can remove the BIO entries
// it owns.
//
// Allocators reuse BIO pointers across connections, and a reused pointer may
// next serve as an internal BIO that SSL_set_bio never names.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_ptr_key_t); // the SSL pointer, scoped to its process
    __type(value, ssl_bios_t);
    __uint(max_entries, MAX_CONCURRENT_TLS_CONNECTIONS);
    __uint(pinning, OBI_PIN_INTERNAL);
} ssl_to_bios SEC(".maps");
