// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>

#include <generictracer/http2_client_lifecycle.h>

struct {
    __uint(type, k_http2_client_lifecycle_map_type);
    __type(key, http2_client_lifecycle_key_t);
    __type(value, http2_client_trace_upgrade_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} h2c_upgrades SEC(".maps");

struct {
    __uint(type, k_http2_client_lifecycle_map_type);
    __type(key, http2_client_lifecycle_key_t);
    __type(value, http2_client_terminal_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} h2c_terminals SEC(".maps");

struct {
    __uint(type, k_http2_client_lifecycle_map_type);
    __type(key, http2_client_lifecycle_key_t);
    __type(value, u8);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} h2c_completed SEC(".maps");
