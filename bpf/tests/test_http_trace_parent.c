// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

static inline u32 bpf_get_prandom_u32(void) {
    return 0;
}
static inline long bpf_loop(u32 n, void *cb, void *ctx, u64 flags) {
    return 0;
}

static long update_index(void *map, const void *key, const void *val, u64 flags);
static long delete_index(void *map, const void *key);
#define bpf_map_update_elem update_index
#define bpf_map_delete_elem delete_index
#include <common/http_trace_parent.h>
#undef bpf_map_delete_elem
#undef bpf_map_update_elem

enum { k_test_entries = 4 };
static http_server_trace_key_t keys[k_test_entries];
static http_server_trace_ref_t refs[k_test_entries];
static unsigned int entries;
static http_info_t http_server;
static http2_grpc_request_t h2_server;
static http2_conn_stream_t h2_stream;
static tp_info_pid_t scratch;
static http2_conn_info_data_t h2_connection;
static bool h2_connection_exists;
static bool connection_exists;

static int find_entry(const void *key) {
    for (unsigned int i = 0; i < entries; i++) {
        if (memcmp(key, &keys[i], sizeof(keys[i])) == 0) {
            return i;
        }
    }
    return -1;
}

static long update_index(void *map, const void *key, const void *val, u64 flags) {
    assert(map == &http_server_trace_index && (flags == BPF_NOEXIST || flags == BPF_ANY));
    const int i = find_entry(key);
    if (i >= 0) {
        if (flags == BPF_NOEXIST) {
            return -1;
        }
        refs[i] = *(const http_server_trace_ref_t *)val;
        return 0;
    }
    assert(entries < k_test_entries);
    keys[entries] = *(const http_server_trace_key_t *)key;
    refs[entries++] = *(const http_server_trace_ref_t *)val;
    return 0;
}

static long delete_index(void *map, const void *key) {
    assert(map == &http_server_trace_index);
    const int i = find_entry(key);
    if (i < 0) {
        return -1;
    }
    entries--;
    keys[i] = keys[entries];
    refs[i] = refs[entries];
    return 0;
}

static void *lookup(void *map, const void *key) {
    if (map == &http_server_trace_index) {
        const int i = find_entry(key);
        return i >= 0 ? &refs[i] : NULL;
    }
    if (map == &ongoing_http && connection_exists &&
        memcmp(key, &h2_stream.pid_conn, sizeof(pid_connection_info_t)) == 0) {
        return &http_server;
    }
    if (map == &ongoing_http2_grpc && connection_exists &&
        memcmp(key, &h2_stream, sizeof(h2_stream)) == 0) {
        return &h2_server;
    }
    if (map == &ongoing_http2_connections && h2_connection_exists &&
        memcmp(key, &h2_stream.pid_conn, sizeof(h2_stream.pid_conn)) == 0) {
        return &h2_connection;
    }
    if (map == &tp_info_backup_storage) {
        return &scratch;
    }
    return NULL;
}

static void index_server(bool h2) {
    if (h2) {
        index_http_server_context(&h2_stream, &h2_server.tp);
    } else {
        index_http_server_trace(&h2_stream.pid_conn, &http_server);
    }
}

static tp_info_t setup(bool h2) {
    entries = 0;
    connection_exists = true;
    h2_connection_exists = true;
    h2_connection.id = 77;
    bpf_map_lookup_elem_hook = lookup;
    http_server = (http_info_t){.type = k_event_type_http_request, .start_monotime_ns = 100};
    http_server.tp.trace_id[0] = 1;
    http_server.tp.span_id[0] = 2;
    http_server.tp.ts = 100;
    h2_stream =
        (http2_conn_stream_t){.pid_conn = {.pid = 42, .conn.s_port = 12345}, .stream_id = 3};
    h2_server = (http2_grpc_request_t){
        .type = k_event_type_http_request, .start_monotime_ns = 100, .tp = http_server.tp};
    h2_server.new_conn_id = h2_connection.id;
    bpf_current_pid_tgid_value = ((u64)42 << 32) | 1001;
    index_server(h2);
    tp_info_t client = {.ts = 200, .flags = k_flag_sampled};
    client.trace_id[0] = 1;
    client.span_id[0] = 3;
    return client;
}

static tp_info_pid_t *parent(u32 pid, const tp_info_t *client) {
    return find_http_server_trace(pid, client);
}

static void test_thread_switch_preserves_native_context(bool h2) {
    tp_info_t client = setup(h2);
    const tp_info_t original = client;
    bpf_current_pid_tgid_value = ((u64)42 << 32) | 2002;
    const tp_info_pid_t *p = parent(42, &client);
    assert(p && p->valid && p->pid == 42 && p->tp.span_id[0] == 2);
    assert(memcmp(&client, &original, sizeof(client)) == 0);
    index_server(h2);
    assert(parent(42, &client));
}

static void test_other_trace_and_process_cannot_parent(bool h2) {
    tp_info_t client = setup(h2);
    client.trace_id[0] = 9;
    assert(!parent(42, &client));
    client.trace_id[0] = 1;
    assert(!parent(43, &client));
}

static void test_ended_or_reused_request_is_rejected(bool h2) {
    tp_info_t client = setup(h2);
    if (h2) {
        h2_connection_exists = false;
        assert(!parent(42, &client));
        h2_connection_exists = true;
        h2_connection.id++;
        assert(!parent(42, &client));
        h2_connection.id--;
        h2_server.end_monotime_ns = 150;
        assert(!parent(42, &client));
        h2_server.end_monotime_ns = 0;
        h2_server.tp.span_id[0] = 9;
        assert(!parent(42, &client));
        h2_server.tp.span_id[0] = 2;
        h2_stream.stream_id = 5;
        assert(!parent(42, &client));
    } else {
        http_server.status = 200;
        assert(!parent(42, &client));
        http_server.status = 0;
        http_server.submitted = 1;
        assert(!parent(42, &client));
        http_server.submitted = 0;
        http_server.tp.span_id[0] = 9;
        assert(!parent(42, &client));
    }
    connection_exists = false;
    assert(!parent(42, &client));
}

static void test_finished_request_entry_is_replaced(bool h2) {
    tp_info_t client = setup(h2);
    if (h2) {
        h2_stream.stream_id = 5;
        h2_server.tp.span_id[0] = 4;
    } else {
        // the next request on a keep-alive connection replaces the record
        http_server.tp.span_id[0] = 4;
    }
    index_server(h2);
    assert(entries == 1 && !refs[0].ambiguous && refs[0].span_id[0] == 4);
    assert(parent(42, &client)->tp.span_id[0] == 4);
}

static void unindex_server(bool h2, unsigned char span) {
    tp_info_t tp = h2 ? h2_server.tp : http_server.tp;
    tp.span_id[0] = span;
    unindex_http_server_trace(h2_stream.pid_conn.pid, &tp);
}

static void test_unindex_removes_only_own_entry(bool h2) {
    tp_info_t client = setup(h2);
    unindex_server(h2, 9);
    assert(entries == 1 && parent(42, &client));
    unindex_server(h2, 2);
    assert(entries == 0 && !parent(42, &client));
}

// Indexes a request on another stream or connection while the live request keeps running.
static void index_concurrent_request(bool h2, unsigned char span) {
    if (h2) {
        http2_conn_stream_t stream = h2_stream;
        stream.stream_id += 2;
        tp_info_t tp = h2_server.tp;
        tp.span_id[0] = span;
        index_http_server_context(&stream, &tp);
    } else {
        pid_connection_info_t pid_conn = h2_stream.pid_conn;
        pid_conn.conn.s_port++;
        http_info_t info = http_server;
        info.tp.span_id[0] = span;
        index_http_server_trace(&pid_conn, &info);
    }
}

// Replaces the live request with a new one on its own stream or connection.
static void start_next_request(bool h2, unsigned char span) {
    if (h2) {
        h2_stream.stream_id += 4;
        h2_server.tp.span_id[0] = span;
    } else {
        h2_stream.pid_conn.conn.s_port += 2;
        http_server.tp.span_id[0] = span;
    }
    index_server(h2);
}

// A overlaps B in one trace, A ends, then C starts. The index can't tell that B still
// runs, so C must not become the trace's parent, whether or not A's end was observed.
static void test_ambiguity_outlives_first_request(bool h2, bool a_unindexed) {
    const tp_info_t b_client = setup(h2);
    index_concurrent_request(h2, 4);
    if (a_unindexed) {
        unindex_server(h2, 2);
    }
    start_next_request(h2, 6);
    assert(entries == 1 && refs[0].ambiguous);
    assert(!parent(42, &b_client));
}

static void test_same_trace_streams_are_ambiguous(void) {
    tp_info_t client = setup(true);
    http2_conn_stream_t second = h2_stream;
    second.stream_id = 5;
    tp_info_t other = h2_server.tp;
    other.span_id[0] = 4;
    index_http_server_context(&second, &other);
    assert(entries == 1 && refs[0].ambiguous);
    assert(!parent(42, &client));
}

static void test_distinct_traces_on_one_connection_are_isolated(void) {
    tp_info_t client = setup(true);
    http2_conn_stream_t second = h2_stream;
    second.stream_id = 5;
    tp_info_t other = h2_server.tp;
    other.trace_id[0] = 9;
    other.span_id[0] = 4;
    index_http_server_context(&second, &other);
    assert(entries == 2 && !refs[0].ambiguous && !refs[1].ambiguous);
    assert(parent(42, &client)->tp.span_id[0] == 2);
    h2_server.tp = other;
    h2_stream = second;
    assert(!parent(42, &client));
    client.trace_id[0] = 9;
    assert(parent(42, &client)->tp.span_id[0] == 4);
}

int main(void) {
    for (unsigned int h2 = 0; h2 <= 1; h2++) {
        test_thread_switch_preserves_native_context(h2);
        test_other_trace_and_process_cannot_parent(h2);
        test_ended_or_reused_request_is_rejected(h2);
        test_finished_request_entry_is_replaced(h2);
        test_unindex_removes_only_own_entry(h2);
        test_ambiguity_outlives_first_request(h2, true);
        test_ambiguity_outlives_first_request(h2, false);
    }
    test_same_trace_streams_are_ambiguous();
    test_distinct_traces_on_one_connection_are_isolated();
    puts("HTTP/1 and HTTP/2 trace parent tests passed");
    return 0;
}
