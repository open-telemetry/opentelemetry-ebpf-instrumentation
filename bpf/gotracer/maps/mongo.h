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
    __type(key, go_addr_key_t);           // key: goroutine id
    __type(value, mongo_go_client_req_t); // the request
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_mongo_requests SEC(".maps");
