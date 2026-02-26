// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/common.h>
#include <common/go_addr_key.h>
#include <common/map_sizing.h>

#include <gotracer/types/kafka.h>

// Kafka Go

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // goroutine
    __type(value, tp_info_t);   // traceparent
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} produce_traceparents_by_goroutine SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // w_ptr
    __type(value, tp_info_t);   // traceparent
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} produce_traceparents SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // goroutine
    __type(value, topic_t);     // topic info
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_produce_topics SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // msg ptr
    __type(value, topic_t);     // topic info
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_produce_messages SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);   // goroutine
    __type(value, produce_req_t); // rw ptr + start time
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} produce_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);    // goroutine
    __type(value, kafka_go_req_t); // rw ptr + start time
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} fetch_requests SEC(".maps");

// Sarama

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
