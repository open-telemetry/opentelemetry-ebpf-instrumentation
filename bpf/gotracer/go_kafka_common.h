// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build obi_bpf_ignore

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/ringbuf.h>

#include <gotracer/go_common.h>
#include <gotracer/go_kafka_def.h>

#include <logger/bpf_dbg.h>

typedef struct produce_req {
    u64 msg_ptr;
    u64 conn_ptr;
    u64 start_monotime_ns;
} produce_req_t;

typedef struct topic {
    char name[MAX_TOPIC_NAME_LEN];
    tp_info_t tp;
} topic_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // msg ptr
    __type(value, topic_t);     // topic info
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_produce_messages SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);    // goroutine
    __type(value, kafka_go_req_t); // rw ptr + start time
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} fetch_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: correlation id
    __type(value, kafka_client_req_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} kafka_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: goroutine id
    __type(value, u32);         // correlation id
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_kafka_requests SEC(".maps");

static __always_inline u8 handled_kafka_request(go_addr_key_t *g_key) {
    void *r = bpf_map_lookup_elem(&ongoing_produce_messages, g_key);
    if (r) {
        return 1;
    }

    r = bpf_map_lookup_elem(&fetch_requests, g_key);
    if (r) {
        return 1;
    }

    r = bpf_map_lookup_elem(&kafka_requests, g_key);
    if (r) {
        return 1;
    }

    r = bpf_map_lookup_elem(&ongoing_kafka_requests, g_key);
    if (r) {
        return 1;
    }

    return 0;
}