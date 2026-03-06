// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/common.h>
#include <common/go_addr_key.h>
#include <common/map_sizing.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);        // key: goroutine id
    __type(value, redis_client_req_t); // the request
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_redis_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: goroutine id
    __type(value, void *);      // the *Conn
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} redis_writes SEC(".maps");
