// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <maps/rust_tasks.h>
#include <common/connection_info.h>

enum rust_message_layout : u8 {
    k_rust_message_callback = 1,
    k_rust_message_list = 2,
    k_rust_message_request = 4,
};

typedef struct rust_protocol_config {
    u32 vec_ptr;
    u32 vec_len;
    u32 vec_cap;
    u32 bytes_ptr;
    u32 bytes_len;
    u32 bytes_cap;
    u32 limit_inner;
    u32 limit_remaining;
    u32 h2_stream_id;
    u32 h2_fields;
    u32 h2_method;
    u32 request_headers;
    u32 header_entries;
    u32 header_count;
    u32 bucket_size;
    u32 name_ptr;
    u32 name_len;
    u32 value_ptr;
    u32 value_len;
    u32 reader_buffer;
    u32 tls_common;
    u32 tls_client_deframer;
    u32 tls_server_deframer;
    u32 tls_deframer_pointer;
    u32 tls_deframer_used;
    u32 tls_plaintext;
    u32 tls_decrypter;
    u32 tls_encrypter;
    u32 tls_sendable;
    u32 h2_store_stream_id;
    u32 h2_stream_ref_id;
    u32 h2_prioritize;
    u32 list_head;
    u32 list_index;
    u32 slot_mask;
    u32 message_tx_tag;
    u32 message_tx_some;
    u32 message_tx_pointer;
    u32 message_rx_tag;
    u32 message_rx_some;
    u32 message_rx_pointer;
    u32 message_rx_headers;
    u8 http1;
    u8 http2;
    u8 rustls;
    u8 inject;
    u8 h2_server;
    u8 message;
    u8 tls_external_deframer;
    u8 h2_hpack;
} rust_protocol_config_t;

typedef struct rust_wire_key {
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
    u32 pid;
} rust_wire_key_t;

typedef struct rust_h2_key {
    u64 sender;
    u32 stream_id;
    u32 pid;
} rust_h2_key_t;

enum rust_injection_result : u8 {
    k_rust_injection_none = 0,
    k_rust_injection_succeeded = 1,
    k_rust_injection_skipped = 2,
    k_rust_injection_application_owned = 3,
};

typedef struct rust_http_request {
    tp_info_t wire;
    tp_info_pid_t parent;
    u8 inject;
    u8 injection_result;
    u8 observed;
    u8 _pad;
    s32 payload_write_error;
} rust_http_request_t;

typedef struct rust_http1_failure {
    unsigned char parent_span_id[SPAN_ID_SIZE_BYTES];
    s32 payload_write_error;
} rust_http1_failure_t;

typedef struct rust_tls_flush {
    u64 common;
    ssl_pid_connection_info_t connection;
} rust_tls_flush_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, rust_tls_flush_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_tls_flushes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, rust_wire_key_t);
    __type(value, rust_http1_failure_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_http1_failures SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, rust_task_key_t);
    __type(value, rust_http_request_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_http1_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, rust_h2_key_t);
    __type(value, rust_http_request_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_h2_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, rust_task_key_t);
    __type(value, u64);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_h2_tasks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, rust_protocol_config_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_protocol_configs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, rust_wire_key_t);
    __type(value, tp_info_pid_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_wire_parents SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, rust_task_key_t);
    __type(value, ssl_pid_connection_info_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_io_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_h2_senders SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, rust_task_key_t);
    __type(value, ssl_pid_connection_info_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_tls_reads SEC(".maps");
