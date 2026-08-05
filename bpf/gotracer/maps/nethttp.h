// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/common.h>
#include <common/connection_info.h>
#include <common/go_addr_key.h>
#include <common/map_sizing.h>
#include <common/scratch_mem.h>

#include <gotracer/types/nethttp.h>
#include <gotracer/types/stream_key.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_exact_process_addr_key_t);
    __type(value, http_client_data_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http_client_requests_data SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, http2_server_stream_key_t);
    __type(value, http2_server_request_state_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} http2_server_requests_tp SEC(".maps");

struct {
    // processHeaders must retain its exact process-incarnation key until its
    // return probe decides whether the provisional per-stream state was
    // accepted. A regular hash fails a new insertion instead of evicting an
    // in-flight invocation.
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, go_exact_process_addr_key_t);
    __type(value, http2_process_headers_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} http2_process_headers_invocations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, server_http_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http_server_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: goroutine handing a parsed HTTP/1 request to ServeHTTP
    __type(value, http1_server_handoff_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} http1_server_handoffs SEC(".maps");

SCRATCH_MEM_TYPED(http_server_invocation_scratch, server_http_invocation_scratch_t);
SCRATCH_MEM_TYPED(http1_server_handoff, http1_server_handoff_t);
SCRATCH_MEM_TYPED(http2_process_headers, http2_process_headers_invocation_t);
SCRATCH_MEM_TYPED(http2_client_framer, framer_func_invocation_t);

static __always_inline server_http_func_invocation_t *http_server_invocation_mem() {
    server_http_invocation_scratch_t *scratch = http_server_invocation_scratch_mem();
    return scratch ? &scratch->invocation : NULL;
}

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, unsigned char[k_http_header_max_len]);
    __uint(max_entries, 1);
} temp_header_mem_store SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, http1_header_request_key_t);
    __type(value, go_exact_process_addr_key_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} header_req_map SEC(".maps");

// HTTP 2.0 client support
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_exact_process_stream_key_t); // exact process + framer + stream id
    __type(value, go_exact_process_addr_key_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} http2_req_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);
    __type(value, framer_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} framer_invocation_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: the net/http (*conn).serve goroutine handling the request
    __type(value, u64);         // the *bufio.Reader buffering the request
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_server_bufr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, bool);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} go_http2_client_connections SEC(".maps");
