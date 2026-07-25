// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <gotracer/go_common.h>
#include <gotracer/maps/grpc.h>
#include <gotracer/maps/kafka.h>
#include <gotracer/maps/mongo.h>
#include <gotracer/maps/nethttp.h>
#include <gotracer/maps/redis.h>
#include <gotracer/types/grpc.h>
#include <gotracer/types/nethttp.h>
#include <shared/obi_ctx.h>

// Copies the innermost still-ongoing invocation's trace context into out;
// clients before servers, SQL last of the clients
static __always_inline u8 obi_ctx__innermost_tp(const go_addr_key_t *g_key, tp_info_t *out) {
    const tp_info_t *kafka_tp = bpf_map_lookup_elem(&produce_traceparents_by_goroutine, g_key);
    if (kafka_tp) {
        *out = *kafka_tp;
        return 1;
    }
    const mongo_go_client_req_t *mongo = bpf_map_lookup_elem(&ongoing_mongo_requests, g_key);
    if (mongo) {
        *out = mongo->tp;
        return 1;
    }
    const redis_client_req_t *redis = bpf_map_lookup_elem(&ongoing_redis_requests, g_key);
    if (redis) {
        *out = redis->tp;
        return 1;
    }
    const grpc_client_func_invocation_t *grpc_client =
        bpf_map_lookup_elem(&ongoing_grpc_client_requests, g_key);
    if (grpc_client) {
        *out = grpc_client->tp;
        return 1;
    }
    const sql_func_invocation_t *sql = bpf_map_lookup_elem(&ongoing_sql_queries, g_key);
    if (sql) {
        *out = sql->tp;
        return 1;
    }
    const grpc_srv_func_invocation_t *grpc_server =
        bpf_map_lookup_elem(&ongoing_grpc_server_requests, g_key);
    if (grpc_server) {
        *out = grpc_server->tp;
        return 1;
    }
    const server_http_func_invocation_t *http_server =
        bpf_map_lookup_elem(&ongoing_http_server_requests, g_key);
    if (http_server) {
        *out = http_server->tp;
        return 1;
    }
    return 0;
}

// Hands traces_ctx_v1 to the enclosing invocation, or deletes it when none
static __always_inline void obi_ctx__restore(u64 pid_tgid, const go_addr_key_t *g_key) {
    tp_info_t tp;
    if (obi_ctx__innermost_tp(g_key, &tp)) {
        obi_ctx__set(pid_tgid, &tp);
        return;
    }
    obi_ctx__del(pid_tgid);
}
