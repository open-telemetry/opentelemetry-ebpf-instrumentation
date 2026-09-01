// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// msg_buffer_mem is per CPU and nothing clears it between messages, so after
// fill_msg_buffers bails it still holds whichever message that CPU filled it
// from last. protocol_detector reads that buffer, so its answer describes this
// message only when the fill that precedes it succeeded.
//
// The bail that matters is the SSL one: the message on the wire is a TLS
// record, the resident message is a plaintext HTTP request from another
// connection, and a caller that acts on the match splices a 'Traceparent:'
// header into the middle of the record. test_stale_buffer_still_matches_http
// establishes that the match happens; test_guarded_read_refuses_a_stale_buffer
// is the regression - it fails if the reader stops being gated on the fill.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

enum { BPF_ANY = 0, BPF_NOEXIST = 1 };

// One entry holds the whole per-CPU msg_buffer_mem slab.
enum { k_max_entries = 4, k_max_key = 64, k_max_val = 8192 };

typedef struct mock_entry {
    int used;
    unsigned char key[k_max_key];
    unsigned char val[k_max_val];
} mock_entry_t;

struct bpf_test_map {
    const char *name;
    unsigned int key_size;
    unsigned int val_size;
    mock_entry_t entries[k_max_entries];
};

static void *test_map_lookup(void *map, const void *key);
static long test_map_update(void *map, const void *key, const void *val, unsigned long long flags);
static long test_probe_read(void *dst, unsigned int size, const void *src);

#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_probe_read test_probe_read
#define bpf_probe_read_kernel test_probe_read

#include <tpinjector/msg_buffers.h>

#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#undef bpf_probe_read
#undef bpf_probe_read_kernel

// The macros above are scoped to the code under test. Test code reaches the
// mock maps directly, since the real helpers are no-op stubs on the host.
#define map_get test_map_lookup
#define map_put(m, k, v) test_map_update((m), (k), (v), 0)

_Static_assert(k_max_val == k_msg_buffer_size_max, "one entry must hold the whole slab");

struct bpf_test_map msg_buffer_mem = {
    .name = "msg_buffer_mem", .key_size = sizeof(u32), .val_size = k_msg_buffer_size_max};
struct bpf_test_map msg_buffers = {
    .name = "msg_buffers", .key_size = sizeof(egress_key_t), .val_size = sizeof(msg_buffer_t)};
struct bpf_test_map active_ssl_connections = {.name = "active_ssl_connections",
                                              .key_size = sizeof(pid_connection_info_t),
                                              .val_size = sizeof(u64)};
struct bpf_test_map ongoing_http = {
    .name = "ongoing_http", .key_size = sizeof(pid_connection_info_t), .val_size = sizeof(u64)};
struct bpf_test_map ongoing_tcp_req = {
    .name = "ongoing_tcp_req", .key_size = sizeof(pid_connection_info_t), .val_size = sizeof(u64)};
struct bpf_test_map ongoing_http2_connections = {.name = "ongoing_http2_connections",
                                                 .key_size = sizeof(pid_connection_info_t),
                                                 .val_size = sizeof(u64)};

static int failures;

static void check(int ok, const char *message) {
    if (!ok) {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

static void *test_map_lookup(void *map, const void *key) {
    struct bpf_test_map *m = map;

    for (int i = 0; i < k_max_entries; i++) {
        if (m->entries[i].used && memcmp(m->entries[i].key, key, m->key_size) == 0) {
            return m->entries[i].val;
        }
    }

    return NULL;
}

static long test_map_update(void *map, const void *key, const void *val, unsigned long long flags) {
    struct bpf_test_map *m = map;
    (void)flags;

    int free_slot = -1;

    for (int i = 0; i < k_max_entries; i++) {
        if (!m->entries[i].used) {
            if (free_slot < 0) {
                free_slot = i;
            }
            continue;
        }
        if (memcmp(m->entries[i].key, key, m->key_size) == 0) {
            // fill_msg_buffers writes the slab back over itself; a memcpy of a
            // region onto itself is undefined, and the copy is a no-op anyway.
            if (val != m->entries[i].val) {
                memcpy(m->entries[i].val, val, m->val_size);
            }
            return 0;
        }
    }

    if (free_slot < 0) {
        return -1;
    }

    m->entries[free_slot].used = 1;
    memcpy(m->entries[free_slot].key, key, m->key_size);
    memcpy(m->entries[free_slot].val, val, m->val_size);

    return 0;
}

static long test_probe_read(void *dst, unsigned int size, const void *src) {
    if (!src) {
        return -1;
    }
    memcpy(dst, src, size);
    return 0;
}

// The kernel hands sk_msg programs a linear region; a message here is a fixed
// slab so that fill_msg_buffers' 256-byte fallback read is always in bounds.
typedef struct test_msg {
    unsigned char bytes[k_msg_buffer_size_max];
    struct sk_msg_md md;
} test_msg_t;

static const u64 k_id = 0x0000029a00000cafULL; // pid 666
static const u32 k_cpu = 3;

static void build_msg(test_msg_t *m, const void *payload, u32 len) {
    memset(m->bytes, 0, sizeof(m->bytes));
    memcpy(m->bytes, payload, len);
    m->md.data = m->bytes;
    m->md.data_end = m->bytes + sizeof(m->bytes);
    m->md.size = len;
}

// A plaintext HTTP/1.1 client request, the shape protocol_detector matches.
static void build_http_request(test_msg_t *m, const char *line) {
    char buf[256];
    const int n = snprintf(buf, sizeof(buf), "%s\r\nHost: upstream:8080\r\n\r\n", line);
    build_msg(m, buf, (u32)n);
}

// A TLS 1.2+ application_data record. The 0x0a is what write_msg_traceparent
// would find and split the record at.
static void build_tls_record(test_msg_t *m) {
    unsigned char rec[512];
    memset(rec, 0xab, sizeof(rec));
    rec[0] = 0x17; // application_data
    rec[1] = 0x03;
    rec[2] = 0x03;
    rec[3] = 0x01;
    rec[4] = 0xfb;
    rec[64] = '\n';
    build_msg(m, rec, sizeof(rec));
}

static pid_connection_info_t make_conn(u16 s_port, u16 d_port) {
    pid_connection_info_t p_conn = {};

    p_conn.conn.s_addr[15] = 10;
    p_conn.conn.d_addr[15] = 20;
    p_conn.conn.s_port = s_port;
    p_conn.conn.d_port = d_port;
    p_conn.pid = pid_from_pid_tgid(k_id);

    sort_connection_info(&p_conn.conn);

    return p_conn;
}

static egress_key_t make_key(u16 s_port, u16 d_port) {
    egress_key_t e_key = {.s_port = s_port, .d_port = d_port, .stream_id = 0};

    return e_key;
}

static void reset(void) {
    memset(msg_buffer_mem.entries, 0, sizeof(msg_buffer_mem.entries));
    memset(msg_buffers.entries, 0, sizeof(msg_buffers.entries));
    memset(active_ssl_connections.entries, 0, sizeof(active_ssl_connections.entries));
    memset(ongoing_http.entries, 0, sizeof(ongoing_http.entries));
    memset(ongoing_tcp_req.entries, 0, sizeof(ongoing_tcp_req.entries));
    memset(ongoing_http2_connections.entries, 0, sizeof(ongoing_http2_connections.entries));

    bpf_smp_processor_id_value = k_cpu;

    // the per-CPU array always has its single slot
    unsigned char zero_slab[k_msg_buffer_size_max] = {0};
    map_put(&msg_buffer_mem, &(u32){0}, zero_slab);
}

static const unsigned char *cpu_slab(void) {
    return map_get(&msg_buffer_mem, &(u32){0});
}

// A plaintext send fills the slab from this message and reports it did.
static void test_plaintext_fill_refreshes_the_buffer(void) {
    reset();

    test_msg_t plain;
    build_http_request(&plain, "GET /catalog HTTP/1.1");
    const pid_connection_info_t conn = make_conn(40000, 8080);
    const egress_key_t key = make_key(40000, 8080);

    check(fill_msg_buffers(&plain.md, &conn, &key), "a plaintext send fills the buffer");
    check(memcmp(cpu_slab(), "GET /catalog HTTP/1.1", 21) == 0,
          "the slab holds this message's request line");
    check(protocol_detector(&plain.md, k_id, &conn.conn) == 1,
          "the detector reports the request it was just filled from");

    const msg_buffer_t *m_buf = map_get(&msg_buffers, &key);
    check(m_buf != NULL, "the kprobe's msg_buffers entry is published");
    check(m_buf && m_buf->cpu_id == k_cpu, "the entry records the CPU that filled the slab");
}

// An SSL connection bails without touching the slab, so the previous
// connection's request is still resident and still matches.
static void test_stale_buffer_still_matches_http(void) {
    reset();

    test_msg_t plain;
    build_http_request(&plain, "POST /documents HTTP/1.1");
    const pid_connection_info_t plain_conn = make_conn(40000, 8080);
    const egress_key_t plain_key = make_key(40000, 8080);

    check(fill_msg_buffers(&plain.md, &plain_conn, &plain_key), "the plaintext send fills first");

    // the same CPU now handles a connection the SSL uprobes have bound
    test_msg_t cipher;
    build_tls_record(&cipher);
    const pid_connection_info_t tls_conn = make_conn(40001, 8443);
    const egress_key_t tls_key = make_key(40001, 8443);
    map_put(&active_ssl_connections, &tls_conn, &(u64){0xdeadbeef});

    check(!fill_msg_buffers(&cipher.md, &tls_conn, &tls_key),
          "a known SSL connection reports the buffer was not filled");
    check(map_get(&msg_buffers, &tls_key) == NULL,
          "and publishes no msg_buffers entry for this connection");
    check(memcmp(cpu_slab(), "POST /documents HTTP/1.1", 24) == 0,
          "the slab still holds the previous connection's request");
    check(protocol_detector(&cipher.md, k_id, &tls_conn.conn) == 1,
          "so an ungated detector reports this TLS record as an HTTP request");
}

// The regression: the reader is gated on the fill, so the stale match above
// never reaches the caller.
static void test_guarded_read_refuses_a_stale_buffer(void) {
    reset();

    test_msg_t plain;
    build_http_request(&plain, "POST /documents HTTP/1.1");
    const pid_connection_info_t plain_conn = make_conn(40000, 8080);
    const egress_key_t plain_key = make_key(40000, 8080);

    check(fill_msg_buffers(&plain.md, &plain_conn, &plain_key), "the plaintext send fills first");

    test_msg_t cipher;
    build_tls_record(&cipher);
    const pid_connection_info_t tls_conn = make_conn(40001, 8443);
    const egress_key_t tls_key = make_key(40001, 8443);
    map_put(&active_ssl_connections, &tls_conn, &(u64){0xdeadbeef});

    check(!msg_buffer_holds_http_request(&cipher.md, k_id, &tls_conn, &tls_key),
          "a bailed fill never reports an HTTP request");
}

// A zero-length send bails on the same path and must be gated the same way.
static void test_guarded_read_refuses_an_empty_message(void) {
    reset();

    test_msg_t plain;
    build_http_request(&plain, "GET /catalog HTTP/1.1");
    const pid_connection_info_t plain_conn = make_conn(40000, 8080);
    const egress_key_t plain_key = make_key(40000, 8080);

    check(fill_msg_buffers(&plain.md, &plain_conn, &plain_key), "the plaintext send fills first");

    test_msg_t empty;
    build_msg(&empty, "", 0);
    const pid_connection_info_t other_conn = make_conn(40002, 8080);
    const egress_key_t other_key = make_key(40002, 8080);

    check(!msg_buffer_holds_http_request(&empty.md, k_id, &other_conn, &other_key),
          "an empty send never reports an HTTP request");
}

// The gate must not suppress a genuine match.
static void test_guarded_read_accepts_a_fresh_request(void) {
    reset();

    test_msg_t plain;
    build_http_request(&plain, "GET /catalog HTTP/1.1");
    const pid_connection_info_t conn = make_conn(40000, 8080);
    const egress_key_t key = make_key(40000, 8080);

    check(msg_buffer_holds_http_request(&plain.md, k_id, &conn, &key),
          "a filled buffer holding this message's request is reported");
}

// A plaintext send that is not a request must not be reported either, whichever
// message the slab happened to hold before it.
static void test_guarded_read_rejects_a_non_request(void) {
    reset();

    test_msg_t plain;
    build_http_request(&plain, "GET /catalog HTTP/1.1");
    const pid_connection_info_t first = make_conn(40000, 8080);
    const egress_key_t first_key = make_key(40000, 8080);

    check(fill_msg_buffers(&plain.md, &first, &first_key), "the plaintext request fills first");

    test_msg_t response;
    build_msg(&response, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 37);
    const pid_connection_info_t second = make_conn(40003, 8080);
    const egress_key_t second_key = make_key(40003, 8080);

    check(!msg_buffer_holds_http_request(&response.md, k_id, &second, &second_key),
          "a response refreshes the slab and is not reported as a request");
}

int main(void) {
    bpf_current_pid_tgid_value = k_id;

    test_plaintext_fill_refreshes_the_buffer();
    test_stale_buffer_still_matches_http();
    test_guarded_read_refuses_a_stale_buffer();
    test_guarded_read_refuses_an_empty_message();
    test_guarded_read_accepts_a_fresh_request();
    test_guarded_read_rejects_a_non_request();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }

    printf("bpf_tpinjector_msg_buffers: all checks passed\n");
    return 0;
}
