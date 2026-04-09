// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/go_addr_key.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, bool); // placeholder, we check if it exists
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} handled_by_go_conn SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);
    __type(value, bool); // placeholder, we check if it exists
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} handled_by_go SEC(".maps");

static __always_inline void store_go_handled_connection_info(const connection_info_t *conn) {
    if (conn) {
        connection_info_t sorted_conn = *conn;
        sort_connection_info(&sorted_conn);
        bpf_map_update_elem(&handled_by_go_conn, &sorted_conn, &(bool){true}, BPF_ANY);
    }
}

static __always_inline void store_go_handled_goroutine(const go_addr_key_t *goaddr) {
    if (goaddr) {
        bpf_map_update_elem(&handled_by_go, goaddr, &(bool){true}, BPF_ANY);
    }
}

static __always_inline void remove_go_handled_goroutine(const go_addr_key_t *goaddr) {
    bpf_map_delete_elem(&handled_by_go, goaddr);
}