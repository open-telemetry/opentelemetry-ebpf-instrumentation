// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/go_addr_key.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

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
    __type(value, grpc_client_invocation_stack_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} ongoing_grpc_client_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pid + pointer to the clientStream
    __type(value, grpc_client_stream_state_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} ongoing_grpc_client_streams SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pid + pointer to the clientStream
    __type(value, grpc_client_early_finish_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} early_grpc_client_finishes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pid + pointer to the clientStream
    __type(value, u8);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} completed_grpc_client_streams SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pid + pointer to the clientStream
    __type(value, u8);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} tracked_grpc_client_streams SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, grpc_srv_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_server_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pid + pointer to the transport
    __type(value, grpc_connection_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} cached_grpc_client_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, grpc_stream_key_t);               // key: pid + conn_ptr + stream id
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

// net.Conn* → connection and socket identity. Populated in NewStream.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pid + conn_ptr
    __type(value, grpc_connection_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} grpc_conn_ptr_to_conn SEC(".maps");

// hdr_ptr → request state. executeAndPut stashes on the NewStream goroutine;
// the active grpc-go layout's header handler consumes it once stream_id is set.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // pid + hdr pointer
    __type(value, pending_h2_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} pending_h2_invocations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // original ClientConn invocation goroutine
    __type(value, u64);         // queued header pointer
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} grpc_pending_header_by_request SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // goroutine encoding the request headers
    __type(value, grpc_h2_header_observation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} grpc_h2_header_observations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // goroutine encoding the request headers
    __type(value, u32);         // application-owned stream ID
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} grpc_app_owned_writes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);   // original ClientConn invocation goroutine
    __type(value, go_addr_key_t); // loopyWriter goroutine
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} grpc_owned_writer_by_request SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // original ClientConn invocation goroutine
    __type(value, grpc_h2_owned_stream_key_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} grpc_owned_stream_by_request SEC(".maps");

// Per-stream tp (Go gRPC server). operateHeaders writes, handleStream reads.
// Avoids the last-writer-wins race on the transport-keyed ongoing_grpc_transports
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, stream_key_t);
    __type(value, tp_info_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_server_stream_tps SEC(".maps");
