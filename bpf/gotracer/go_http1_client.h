// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/go_addr_key.h>

#include <gotracer/types/nethttp.h>

static __always_inline u8
go_http1_header_request_key(http1_header_request_key_t *header_key,
                            const go_exact_process_addr_key_t *request_key,
                            u64 header_addr,
                            u64 persist_conn_addr) {
    if (!header_key || !request_key || !request_key->process_start_time || !header_addr ||
        !persist_conn_addr || request_key->address.pid != (u64)(u32)request_key->address.pid) {
        return 0;
    }
    *header_key = (http1_header_request_key_t){
        .process_start_time = request_key->process_start_time,
        .header_addr = header_addr,
        .persist_conn_addr = persist_conn_addr,
        .pid = (u32)request_key->address.pid,
    };
    return 1;
}

static __always_inline u8
go_http1_stage_header_request(void *locator_map,
                              u64 header_addr,
                              u64 persist_conn_addr,
                              const go_exact_process_addr_key_t *request_key) {
    http1_header_request_key_t header_key = {};
    return locator_map &&
           go_http1_header_request_key(&header_key, request_key, header_addr, persist_conn_addr) &&
           bpf_map_update_elem(locator_map, &header_key, request_key, BPF_ANY) == 0;
}

static __always_inline u8 go_http1_take_header_request(void *locator_map,
                                                       u32 pid,
                                                       u64 process_start_time,
                                                       u64 header_addr,
                                                       u64 persist_conn_addr,
                                                       go_exact_process_addr_key_t *request_key) {
    const go_exact_process_addr_key_t current =
        go_exact_process_addr_key(pid, process_start_time, 0);
    http1_header_request_key_t header_key = {};
    if (!locator_map || !request_key ||
        !go_http1_header_request_key(&header_key, &current, header_addr, persist_conn_addr)) {
        return 0;
    }
    const go_exact_process_addr_key_t *located = bpf_map_lookup_elem(locator_map, &header_key);
    if (!located) {
        return 0;
    }
    const go_exact_process_addr_key_t exact = *located;
    bpf_map_delete_elem(locator_map, &header_key);
    if (exact.address.pid != pid || exact.process_start_time != process_start_time) {
        return 0;
    }
    *request_key = exact;
    return 1;
}

static __always_inline void
go_http1_begin_write_subset(void *invocation_map, const go_exact_process_addr_key_t *writer_key) {
    if (invocation_map && writer_key) {
        bpf_map_delete_elem(invocation_map, writer_key);
    }
}
