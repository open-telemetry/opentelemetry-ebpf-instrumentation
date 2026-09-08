// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/tls_record.h>
#include <common/pin_internal.h>

// Maps a BIO to the SSL connection that owns it, populated from SSL_set_bio.
//
// OpenSSL stages the same record through several BIOs on its way out, so this
// map identifies the ones SSL_set_bio named - the endpoints of a connection -
// and each record is registered once.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_ptr_key_t); // the BIO pointer, scoped to its process
    __type(value, bio_ssl_info_t);
    __uint(max_entries, MAX_CONCURRENT_TLS_BIOS);
    __uint(pinning, OBI_PIN_INTERNAL);
} bio_to_ssl SEC(".maps");
