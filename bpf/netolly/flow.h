// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
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

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

#pragma once

#include <bpfcore/vmlinux.h>

typedef struct flow_metrics_t {
    u64 bytes;

    u32 packets;

    u8 iface_direction;
    u8 initiator;
    u8 pad[2];
} flow_metrics;

// Attributes that uniquely identify a flow
// TODO: remove attributes that won't be used in Beyla (e.g. MAC, maybe protocol...)
typedef struct flow_id_t {
    // L3 network layer
    // IPv4 addresses are encoded as IPv6 addresses with prefix ::ffff/96
    // as described in https://datatracker.ietf.org/doc/html/rfc4038#section-4.2
    struct in6_addr src_ip; // keep these aligned
    struct in6_addr dst_ip;
    // OS interface index
    u32 if_index;

    u16 eth_protocol;

    // L4 transport layer
    u16 src_port;
    u16 dst_port;
    u8 transport_protocol;
    u8 _pad[1];
} flow_id;

// Flow record is a tuple containing both flow identifier and metrics. It is used to send
// a complete flow via ring buffer when only when the accounting hashmap is full.
// Contents in this struct must match byte-by-byte with Go's pkc/flow/Record struct
typedef struct flow_record_t {
    flow_metrics metrics;
    flow_id id;
    u32 pad;
} flow_record;

typedef struct flow_ctx_t {
    struct in6_addr local_ip;
    struct in6_addr remote_ip;

    u64 start_mono_time_ns;
    u64 end_mono_time_ns;

    u64 tx_bytes;
    u64 rx_bytes;

    u32 tx_packets;
    u32 rx_packets;

    u16 local_port;
    u16 remote_port;

    u32 ingress_if_index;
    u32 egress_if_index;

    u32 egress_submitted_iface;

    u8 transport_protocol;
    u8 start_direction;
    u8 pad[6];
} flow_ctx;

typedef struct socket_data_t {
    struct bpf_spin_lock lock;

    u8 ignore;
    u8 initialized;
    u8 _pad[2];

    flow_ctx ctx;
} flow_socket_data;
