// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/go_addr_key.h>
#include <common/map_sizing.h>

#include <gotracer/types/grpc.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, u16);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_request_status SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, grpc_client_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_client_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, grpc_srv_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_server_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pid + pointer to the transport
    __type(value, connection_info_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} cached_grpc_client_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, stream_key_t);                    // key: conn_ptr + stream id
    __type(value, grpc_client_func_invocation_t); // stored info for the client request
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_streams SEC(".maps");

// TODO: use go_addr_key_t as key
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, grpc_client_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_header_writes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, transport_new_client_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} transport_new_client_invocations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: goroutine doing framer write headers
    __type(
        value,
        grpc_framer_func_invocation_t); // the goroutine of the round trip request, which is the key for our traceparent info
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} grpc_framer_invocation_map SEC(".maps");

// net.Conn* → connection_info. Populated in NewStream, read in WriteHeaders.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // key: conn_ptr
    __type(value, connection_info_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} grpc_conn_ptr_to_conn SEC(".maps");

// hdr_ptr → {invocation, conn_ptr}. executeAndPut stashes on the NewStream
// goroutine; originateStream reads on the loopyWriter goroutine once the
// stream_id is assigned, then builds {conn_ptr, stream_id} for ongoing_streams
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // hdr pointer
    __type(value, pending_h2_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} pending_h2_invocations SEC(".maps");

// Per-stream tp (Go gRPC server). operateHeaders writes, handleStream reads.
// Avoids the last-writer-wins race on the transport-keyed ongoing_grpc_transports
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, stream_key_t);
    __type(value, tp_info_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_server_stream_tps SEC(".maps");
