// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// End to end behaviour of the memory BIO correlation.
//
// An outbound TLS write on an event loop is attributed to the connection that
// carried it, even though the ciphertext reaches the socket in a different
// callback from the SSL_write that produced it.
//
// test_uncorrelated_write_takes_the_inbound_guess covers the unchanged
// handle_ssl_buf, where no correlation is available. That is what gives the
// passing assertions in the other direction their meaning.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

enum { BPF_ANY = 0, BPF_NOEXIST = 1 };

enum { k_max_entries = 32, k_max_key = 48, k_max_val = 128 };

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
static long test_map_delete(void *map, const void *key);
static long test_probe_read(void *dst, unsigned int size, const void *src);

#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete
#define bpf_probe_read test_probe_read
#define bpf_probe_read_user test_probe_read

#include <generictracer/tls_prefix.h>
#include <generictracer/ssl_defs.h>

#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#undef bpf_map_delete_elem
#undef bpf_probe_read
#undef bpf_probe_read_user

// The macros above are scoped to the code under test. Test code reaches the
// mock maps directly, since the real helpers are no-op stubs on the host.
#define map_get test_map_lookup
#define map_put(m, k, v) test_map_update((m), (k), (v), 0)

struct bpf_test_map ssl_to_conn = {.name = "ssl_to_conn",
                                   .key_size = sizeof(void *),
                                   .val_size = sizeof(ssl_pid_connection_info_t)};
struct bpf_test_map pid_tid_to_conn = {.name = "pid_tid_to_conn",
                                       .key_size = sizeof(u64),
                                       .val_size = sizeof(ssl_pid_connection_info_t)};
struct bpf_test_map ssl_to_pid_tid = {
    .name = "ssl_to_pid_tid", .key_size = sizeof(u64), .val_size = sizeof(u64)};
struct bpf_test_map ongoing_http = {
    .name = "ongoing_http", .key_size = sizeof(pid_connection_info_t), .val_size = sizeof(u64)};
struct bpf_test_map active_ssl_connections = {.name = "active_ssl_connections",
                                              .key_size = sizeof(pid_connection_info_t),
                                              .val_size = sizeof(u64)};
struct bpf_test_map bio_to_ssl = {
    .name = "bio_to_ssl", .key_size = sizeof(pid_ptr_key_t), .val_size = sizeof(bio_ssl_info_t)};
struct bpf_test_map ssl_to_bios = {
    .name = "ssl_to_bios", .key_size = sizeof(pid_ptr_key_t), .val_size = sizeof(ssl_bios_t)};
struct bpf_test_map tls_prefix_to_ssl = {.name = "tls_prefix_to_ssl",
                                         .key_size = sizeof(tls_prefix_key_t),
                                         .val_size = sizeof(tls_prefix_val_t)};

tls_prefix_scratch_t test_tls_prefix_scratch;

// Consumed by the k_tracer_defs test stub.
int test_parser_call_count;
int test_last_parser_bytes_len;
u8 test_last_ssl;
u8 test_last_direction;
u16 test_last_orig_dport;
void *test_last_sock;
int test_finish_http_count;
u8 test_http_will_complete;

static int failures;

static void check(int ok, const char *message) {
    if (!ok) {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

static void check_u16(u16 expected, u16 actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %u, got %u\n", message, expected, actual);
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

    for (int i = 0; i < k_max_entries; i++) {
        if (m->entries[i].used && memcmp(m->entries[i].key, key, m->key_size) == 0) {
            memcpy(m->entries[i].val, val, m->val_size);
            return 0;
        }
    }

    for (int i = 0; i < k_max_entries; i++) {
        if (!m->entries[i].used) {
            m->entries[i].used = 1;
            memcpy(m->entries[i].key, key, m->key_size);
            memcpy(m->entries[i].val, val, m->val_size);
            return 0;
        }
    }

    fprintf(stderr, "FAIL: mock map %s is full\n", m->name);
    exit(1);
}

static long test_map_delete(void *map, const void *key) {
    struct bpf_test_map *m = map;

    for (int i = 0; i < k_max_entries; i++) {
        if (m->entries[i].used && memcmp(m->entries[i].key, key, m->key_size) == 0) {
            // Free the slot but leave the value bytes alone. A kernel hash map
            // frees the element under RCU, so a pointer handed out by an
            // earlier lookup stays readable for the rest of the program - and
            // handle_ssl_buf does read one after deleting it.
            m->entries[i].used = 0;
            memset(m->entries[i].key, 0, sizeof(m->entries[i].key));
            return 0;
        }
    }

    return 0;
}

static long test_probe_read(void *dst, unsigned int size, const void *src) {
    if (!dst || !src) {
        return -1;
    }
    memcpy(dst, src, size);
    return 0;
}

static int map_count(struct bpf_test_map *m) {
    int n = 0;
    for (int i = 0; i < k_max_entries; i++) {
        n += m->entries[i].used;
    }
    return n;
}

static void reset(void) {
    memset(ssl_to_conn.entries, 0, sizeof(ssl_to_conn.entries));
    memset(pid_tid_to_conn.entries, 0, sizeof(pid_tid_to_conn.entries));
    memset(ssl_to_pid_tid.entries, 0, sizeof(ssl_to_pid_tid.entries));
    memset(ongoing_http.entries, 0, sizeof(ongoing_http.entries));
    memset(active_ssl_connections.entries, 0, sizeof(active_ssl_connections.entries));
    memset(bio_to_ssl.entries, 0, sizeof(bio_to_ssl.entries));
    memset(ssl_to_bios.entries, 0, sizeof(ssl_to_bios.entries));
    memset(tls_prefix_to_ssl.entries, 0, sizeof(tls_prefix_to_ssl.entries));
    memset(&test_tls_prefix_scratch, 0, sizeof(test_tls_prefix_scratch));

    test_parser_call_count = 0;
    test_last_orig_dport = 0;
    test_last_ssl = 0;
    test_last_direction = 0;
    bpf_ktime_ns_value = 1000000;
    bpf_current_pid_tgid_value = 0x2a0000002aULL; // tgid 42
}

// The pid the correlation compares against is the upper half of pid_tgid.
static const u64 k_id = 0x2a0000002aULL;
static const u32 k_pid = 42;

// A second process, whose allocator happens to hand out the same addresses.
static const u64 k_other_id = 0x630000002aULL;
static const u32 k_other_pid = 99;

static void *const k_ssl = (void *)0x5500;
static void *const k_rbio = (void *)0x6600;
static void *const k_wbio = (void *)0x7700;
static void *const k_internal_bio = (void *)0x8800;

static unsigned char client_hello[1605];
static unsigned int client_hello_len;

static void build_client_hello(void) {
    // A ClientHello far longer than the key width.
    client_hello_len = sizeof(client_hello);
    client_hello[0] = k_tls_ct_handshake;
    client_hello[1] = 0x03;
    client_hello[2] = 0x01;
    client_hello[3] = 0x06;
    client_hello[4] = 0x40;
    client_hello[5] = 0x01; // Handshake type: client_hello

    for (unsigned int i = 6; i < client_hello_len; i++) {
        client_hello[i] = (unsigned char)(i * 31u);
    }
}

// The outbound peer this SSL really talks to.
static pid_connection_info_t upstream_conn(void) {
    pid_connection_info_t c = {0};
    c.pid = 42;
    c.conn.d_port = 8443;
    c.conn.s_port = 51000;
    c.conn.s_addr[15] = 10;
    c.conn.d_addr[15] = 20;
    return c;
}

// The inbound request the event loop happens to be serving.
static void seed_inbound_guess(void) {
    ssl_pid_connection_info_t inbound = {0};
    inbound.p_conn.pid = 42;
    inbound.orig_dport = 8080;
    inbound.p_conn.conn.d_port = 8080;
    inbound.p_conn.conn.s_port = 44000;
    map_put(&pid_tid_to_conn, &k_id, &inbound);
}

static ssl_args_t ssl_args(void) {
    ssl_args_t a = {0};
    a.ssl = (u64)k_ssl;
    a.buf = (u64)client_hello;
    return a;
}

// Drives one full handshake: the connection names its BIOs, OpenSSL writes the
// ClientHello out through the write BIO, and the socket carries those bytes.
static void run_handshake_egress(void) {
    pid_connection_info_t conn = upstream_conn();

    ssl_bios_track(k_pid, k_ssl, k_rbio, k_wbio);
    tls_prefix_register_egress(k_wbio, client_hello, (int)client_hello_len);

    check(tls_prefix_try_bind(
              k_id, client_hello, k_tls_prefix_max, client_hello_len, &conn, 8443) == 1,
          "the socket carrying the ClientHello binds the SSL");
}

static void test_client_hello_binds_ssl_to_its_real_peer(void) {
    reset();
    run_handshake_egress();

    ssl_pid_connection_info_t *bound = map_get(&ssl_to_conn, &k_ssl);

    check(bound != NULL, "the SSL is bound after the ClientHello reaches the socket");
    if (bound) {
        check_u16(8443, bound->orig_dport, "the SSL is bound to the upstream peer");
    }

    check(map_count(&tls_prefix_to_ssl) == 0, "the prefix entry is consumed once it has matched");
}

// OpenSSL writes the same record into several BIOs on its way out, so only the
// one SSL_set_bio named may register a key.
static void test_internal_bio_writes_are_ignored(void) {
    reset();
    ssl_bios_track(k_pid, k_ssl, k_rbio, k_wbio);

    tls_prefix_register_egress(k_internal_bio, client_hello, (int)client_hello_len);

    check(map_count(&tls_prefix_to_ssl) == 0,
          "a BIO no SSL named does not register a correlation key");
}

// Ciphertext also arrives as BIO_write into the read BIO, where it is the
// application pushing received bytes in.
static void test_read_bio_write_is_not_egress(void) {
    reset();
    ssl_bios_track(k_pid, k_ssl, k_rbio, k_wbio);

    tls_prefix_register_egress(k_rbio, client_hello, (int)client_hello_len);

    check(map_count(&tls_prefix_to_ssl) == 0, "a write into the read BIO is not treated as egress");
}

// BIO pointers are recycled: a pointer that was one connection's BIO can later
// be another's, so teardown clears the entry.
static void test_recycled_bio_is_not_attributed_to_the_dead_ssl(void) {
    reset();

    ssl_bios_track(k_pid, k_ssl, k_rbio, k_wbio);
    check(map_get(&bio_to_ssl, &(pid_ptr_key_t){.ptr = (u64)k_wbio, .pid = k_pid}) != NULL,
          "the write BIO is tracked");

    // The connection goes away; the allocator is free to hand its BIO out again.
    ssl_bios_forget(k_pid, k_ssl);

    check(map_get(&bio_to_ssl, &(pid_ptr_key_t){.ptr = (u64)k_wbio, .pid = k_pid}) == NULL,
          "the write BIO is forgotten on teardown");
    check(map_get(&bio_to_ssl, &(pid_ptr_key_t){.ptr = (u64)k_rbio, .pid = k_pid}) == NULL,
          "the read BIO is forgotten on teardown");

    // The same pointer now serves as an internal BIO of a different connection.
    tls_prefix_register_egress(k_wbio, client_hello, (int)client_hello_len);

    check(map_count(&tls_prefix_to_ssl) == 0,
          "a recycled BIO pointer does not register against the freed SSL");
}

// bio_to_ssl and ssl_to_bios are independent LRUs of different sizes, so one
// side of a pair can be evicted on its own. The BIO address the orphaned
// forward entry names will be handed out again, and nothing else would correct
// it, so it may not be trusted.
static void test_orphaned_bio_entry_is_discarded(void) {
    reset();

    ssl_bios_track(k_pid, k_ssl, k_rbio, k_wbio);

    // ssl_to_bios holds half as many entries as bio_to_ssl, so it is the side
    // that gives way under pressure.
    test_map_delete(&ssl_to_bios, &(pid_ptr_key_t){.ptr = (u64)k_ssl, .pid = k_pid});

    tls_prefix_register_egress(k_wbio, client_hello, (int)client_hello_len);

    check(map_count(&tls_prefix_to_ssl) == 0,
          "a BIO its SSL no longer claims does not register a correlation key");
    check(map_get(&bio_to_ssl, &(pid_ptr_key_t){.ptr = (u64)k_wbio, .pid = k_pid}) == NULL,
          "the orphaned entry is dropped rather than left for a reused address");
}

// Validating ownership must not cost the recycled BIO its own correlation: the
// connection that now names it still binds normally.
static void test_recycled_bio_after_eviction_binds_its_own_ssl(void) {
    reset();

    ssl_bios_track(k_pid, k_ssl, k_rbio, k_wbio);
    test_map_delete(&ssl_to_bios, &(pid_ptr_key_t){.ptr = (u64)k_ssl, .pid = k_pid});

    // The allocator hands the write BIO to a new connection, which names it.
    void *const new_ssl = (void *)0x5700;
    ssl_bios_track(k_pid, new_ssl, k_rbio, k_wbio);

    tls_prefix_register_egress(k_wbio, client_hello, (int)client_hello_len);

    pid_connection_info_t conn = upstream_conn();

    check(tls_prefix_try_bind(
              k_id, client_hello, k_tls_prefix_max, client_hello_len, &conn, 8443) == 1,
          "the recycled BIO correlates for the connection that now owns it");
    check(map_get(&ssl_to_conn, &k_ssl) == NULL, "the evicted SSL is not bound to the new socket");
    check(map_get(&ssl_to_conn, &new_ssl) != NULL, "the owning SSL is the one bound");
}

// bio_to_ssl and ssl_to_bios are pinned and shared by every instrumented
// process, and nothing removes a dead process's entries. Two processes are
// therefore expected to allocate objects at the same address, and neither may
// see the other's.
static void test_bio_tracking_is_scoped_to_the_process(void) {
    reset();

    ssl_bios_track(k_pid, k_ssl, k_rbio, k_wbio);

    check(map_get(&bio_to_ssl, &(pid_ptr_key_t){.ptr = (u64)k_wbio, .pid = k_other_pid}) == NULL,
          "another process does not see this process's BIO");
    check(map_get(&ssl_to_bios, &(pid_ptr_key_t){.ptr = (u64)k_ssl, .pid = k_other_pid}) == NULL,
          "another process does not see this process's SSL");

    // The other process writes the same ciphertext through a BIO that happens
    // to sit at the same address.
    bpf_current_pid_tgid_value = k_other_id;
    tls_prefix_register_egress(k_wbio, client_hello, (int)client_hello_len);
    bpf_current_pid_tgid_value = k_id;

    check(map_count(&tls_prefix_to_ssl) == 0,
          "a BIO address reused by another process does not register against this SSL");

    // ...and that process tearing down its own SSL leaves ours intact.
    ssl_bios_forget(k_other_pid, k_ssl);

    check(map_get(&bio_to_ssl, &(pid_ptr_key_t){.ptr = (u64)k_wbio, .pid = k_pid}) != NULL,
          "another process's teardown does not drop this process's BIO");

    tls_prefix_register_egress(k_wbio, client_hello, (int)client_hello_len);

    check(map_count(&tls_prefix_to_ssl) == 1, "this process still correlates normally");
}

static void test_stale_prefix_is_not_matched(void) {
    reset();
    pid_connection_info_t conn = upstream_conn();

    ssl_bios_track(k_pid, k_ssl, k_rbio, k_wbio);
    tls_prefix_register_egress(k_wbio, client_hello, (int)client_hello_len);

    // The record was never flushed; an unrelated send arrives much later.
    bpf_ktime_ns_value += 2 * k_tls_prefix_max_age_ns;

    check(tls_prefix_try_bind(
              k_id, client_hello, k_tls_prefix_max, client_hello_len, &conn, 8443) == 0,
          "a prefix older than the matching window is not used");
    check(map_get(&ssl_to_conn, &k_ssl) == NULL, "no binding is made from a stale key");
}

static void test_other_process_does_not_match(void) {
    reset();
    pid_connection_info_t conn = upstream_conn();

    ssl_bios_track(k_pid, k_ssl, k_rbio, k_wbio);
    tls_prefix_register_egress(k_wbio, client_hello, (int)client_hello_len);

    check(tls_prefix_try_bind(
              k_other_id, client_hello, k_tls_prefix_max, client_hello_len, &conn, 8443) == 0,
          "a matching prefix from another process is not used");
}

// With no correlation available, the SSL takes whatever connection the thread
// touched most recently.
static void test_uncorrelated_write_takes_the_inbound_guess(void) {
    reset();
    seed_inbound_guess();

    ssl_args_t args = ssl_args();
    handle_ssl_buf(NULL, k_id, &args, 16, TCP_SEND);

    check(test_parser_call_count == 1, "the write is reported");
    check_u16(8080,
              test_last_orig_dport,
              "without correlation the outbound write is attributed to the inbound socket");
}

// The same event loop situation, with the handshake having bound the SSL, so
// the write reports the peer it connected to.
static void test_bound_ssl_survives_the_event_loop_write(void) {
    reset();
    build_client_hello();
    run_handshake_egress();

    // The event loop moves on and serves an inbound request before the
    // application data write happens, exactly as it does under concurrency.
    seed_inbound_guess();

    ssl_args_t args = ssl_args();
    handle_ssl_buf(NULL, k_id, &args, 16, TCP_SEND);

    check(test_parser_call_count == 1, "the write is reported");
    check_u16(8443, test_last_orig_dport, "a bound SSL reports the peer it connected to");
}

// Mirror the two uprobe call sites in libssl.c, so the split between SSL-keyed
// and thread-keyed teardown is asserted the way the probes actually use it.
static void ssl_shutdown_probe(u64 id, void *ssl) {
    ssl_release_connection_state(id, ssl);
    ssl_release_thread_state(id);
}

static void ssl_free_probe(u64 id, void *ssl) {
    ssl_release_connection_state(id, ssl);
}

// SSL_free must leave pid_tid_to_conn alone. It is keyed on the thread, and an
// event loop routinely frees one connection while another is still in flight on
// the same thread.
static void test_free_keeps_the_threads_fallback_binding(void) {
    reset();
    run_handshake_egress();
    seed_inbound_guess();

    ssl_free_probe(k_id, k_ssl);

    check(map_get(&pid_tid_to_conn, &k_id) != NULL,
          "freeing an SSL does not drop the thread's fallback binding");

    // A second, uncorrelated SSL on the same thread still resolves through it.
    void *const other_ssl = (void *)0x5600;
    ssl_args_t args = ssl_args();
    args.ssl = (u64)other_ssl;
    handle_ssl_buf(NULL, k_id, &args, 16, TCP_SEND);

    check_u16(8080,
              test_last_orig_dport,
              "an in-flight SSL on the same thread still resolves after another is freed");
}

// SSL_shutdown still releases the thread's binding.
static void test_shutdown_clears_the_threads_fallback_binding(void) {
    reset();
    run_handshake_egress();
    seed_inbound_guess();

    ssl_shutdown_probe(k_id, k_ssl);

    check(map_get(&pid_tid_to_conn, &k_id) == NULL,
          "shutting an SSL down drops the thread's fallback binding");
}

// A second connection whose SSL pointer is the address a previous one used.
// Runs the same handshake against a different peer and reports which peer the
// SSL ends up bound to.
static u16 recycled_pointer_binds_to(int tear_down_first) {
    reset();
    run_handshake_egress(); // first connection, upstream:8443

    if (tear_down_first) {
        ssl_free_probe(k_id, k_ssl);
    }

    // The allocator hands the same address to a new connection talking to a
    // different peer.
    pid_connection_info_t other = upstream_conn();
    other.conn.d_port = 9443;
    other.conn.s_port = 51001;

    ssl_bios_track(k_pid, k_ssl, k_rbio, k_wbio);
    tls_prefix_register_egress(k_wbio, client_hello, (int)client_hello_len);
    tls_prefix_try_bind(k_id, client_hello, k_tls_prefix_max, client_hello_len, &other, 9443);

    ssl_pid_connection_info_t *bound = map_get(&ssl_to_conn, &k_ssl);
    return bound ? bound->orig_dport : 0;
}

// A binding that survives its SSL reads as a good one, so the correlation is
// skipped and the new connection inherits the dead connection's peer.
static void test_recycled_pointer_without_teardown_inherits_the_old_peer(void) {
    check_u16(8443,
              recycled_pointer_binds_to(0),
              "a stale binding suppresses correlation and the old peer is inherited");
}

// Releasing the SSL on SSL_free clears the binding, so the next connection to
// receive that address correlates normally.
static void test_freed_ssl_lets_a_recycled_pointer_recorrelate(void) {
    check_u16(9443,
              recycled_pointer_binds_to(1),
              "a recycled pointer binds to its own peer once the SSL was freed");
}

// Any TLS record registers a key while the SSL still has no peer, which is what
// a connection predating attachment depends on, since its handshake is long
// gone.
static void test_application_data_record_also_correlates(void) {
    reset();

    unsigned char app_data[64];
    // 5 byte header + content type + short payload + 16 byte AEAD tag.
    const unsigned int fragment = 26;
    app_data[0] = k_tls_ct_app_data;
    app_data[1] = 0x03;
    app_data[2] = 0x03;
    app_data[3] = (unsigned char)(fragment >> 8);
    app_data[4] = (unsigned char)(fragment & 0xff);
    for (unsigned int i = 5; i < k_tls_hdr_len + fragment; i++) {
        app_data[i] = (unsigned char)(0x40 + i * 7u);
    }
    const unsigned int record_len = k_tls_hdr_len + fragment;

    pid_connection_info_t conn = upstream_conn();

    ssl_bios_track(k_pid, k_ssl, k_rbio, k_wbio);
    tls_prefix_register_egress(k_wbio, app_data, (int)record_len);

    check(map_count(&tls_prefix_to_ssl) == 1,
          "an application data record registers a correlation key");

    check(tls_prefix_try_bind(k_id, app_data, record_len, record_len, &conn, 8443) == 1,
          "an application data record binds the SSL");

    ssl_pid_connection_info_t *bound = map_get(&ssl_to_conn, &k_ssl);
    check(bound != NULL, "the SSL is bound from application data alone");
    if (bound) {
        check_u16(8443, bound->orig_dport, "bound to the upstream peer");
    }
}

// Two connections handshaking at once, neither bound yet. A TLS 1.3
// ChangeCipherSpec is the same six bytes on every connection, so keying it would
// have both register one key, the second displacing the first, and the first
// connection's socket send would then bind the second's SSL.
static void test_concurrent_unbound_connections_do_not_cross_bind(void) {
    reset();

    static void *const k_ssl_b = (void *)0x5501;
    static void *const k_rbio_b = (void *)0x6601;
    static void *const k_wbio_b = (void *)0x7701;

    const unsigned char change_cipher_spec[] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
    const unsigned int len = sizeof(change_cipher_spec);

    ssl_bios_track(k_pid, k_ssl, k_rbio, k_wbio);
    ssl_bios_track(k_pid, k_ssl_b, k_rbio_b, k_wbio_b);

    tls_prefix_register_egress(k_wbio, change_cipher_spec, (int)len);
    tls_prefix_register_egress(k_wbio_b, change_cipher_spec, (int)len);

    check(map_count(&tls_prefix_to_ssl) == 0,
          "neither connection registers a key for a ChangeCipherSpec");

    // The first connection's flush. Pre-fix this bound k_ssl_b, the SSL that
    // overwrote the shared key.
    pid_connection_info_t conn = upstream_conn();

    check(tls_prefix_try_bind(k_id, change_cipher_spec, len, len, &conn, 8443) == 0,
          "a ChangeCipherSpec send correlates nothing");
    check(map_get(&ssl_to_conn, &k_ssl_b) == NULL,
          "the other connection's SSL is not bound to this connection's peer");
    check(map_get(&ssl_to_conn, &k_ssl) == NULL, "no SSL is bound from a ChangeCipherSpec");

    // Each connection still binds on its own application data, which carries
    // ciphertext unique to it.
    unsigned char app_a[32];
    unsigned char app_b[32];
    const unsigned int fragment = 26;
    const unsigned int record_len = k_tls_hdr_len + fragment;

    for (unsigned int i = 0; i < record_len; i++) {
        app_a[i] = (unsigned char)(0x40 + i * 7u);
        app_b[i] = (unsigned char)(0x90 + i * 11u);
    }
    for (unsigned int i = 0; i < 2; i++) {
        unsigned char *r = i == 0 ? app_a : app_b;
        r[0] = k_tls_ct_app_data;
        r[1] = 0x03;
        r[2] = 0x03;
        r[3] = (unsigned char)(fragment >> 8);
        r[4] = (unsigned char)(fragment & 0xff);
    }

    tls_prefix_register_egress(k_wbio, app_a, (int)record_len);
    tls_prefix_register_egress(k_wbio_b, app_b, (int)record_len);

    check(map_count(&tls_prefix_to_ssl) == 2, "both connections register distinct keys");

    check(tls_prefix_try_bind(k_id, app_b, record_len, record_len, &conn, 9443) == 1,
          "the second connection's record binds a connection");

    ssl_pid_connection_info_t *bound_b = map_get(&ssl_to_conn, &k_ssl_b);

    check(bound_b != NULL, "the second connection's SSL is bound by its own ciphertext");
    if (bound_b) {
        check_u16(9443, bound_b->orig_dport, "and to the peer that carried it");
    }
    check(map_get(&ssl_to_conn, &k_ssl) == NULL, "the first connection's SSL is untouched");
}

// ...but only while bio_to_ssl knows the BIO. A connection whose SSL_set_bio
// happened before the uprobes were attached has no such entry, and nothing
// downstream can recover it.
static void test_unknown_bio_never_correlates(void) {
    reset();

    // No ssl_bios_track: this is the pre-existing-connection case.
    tls_prefix_register_egress(k_wbio, client_hello, (int)client_hello_len);

    check(map_count(&tls_prefix_to_ssl) == 0,
          "a connection whose BIOs were never seen cannot register a key");
}

int main(void) {
    build_client_hello();

    test_client_hello_binds_ssl_to_its_real_peer();
    test_internal_bio_writes_are_ignored();
    test_read_bio_write_is_not_egress();
    test_recycled_bio_is_not_attributed_to_the_dead_ssl();
    test_orphaned_bio_entry_is_discarded();
    test_recycled_bio_after_eviction_binds_its_own_ssl();
    test_bio_tracking_is_scoped_to_the_process();
    test_stale_prefix_is_not_matched();
    test_other_process_does_not_match();
    test_uncorrelated_write_takes_the_inbound_guess();
    test_bound_ssl_survives_the_event_loop_write();
    test_free_keeps_the_threads_fallback_binding();
    test_shutdown_clears_the_threads_fallback_binding();
    test_recycled_pointer_without_teardown_inherits_the_old_peer();
    test_freed_ssl_lets_a_recycled_pointer_recorrelate();
    test_application_data_record_also_correlates();
    test_concurrent_unbound_connections_do_not_cross_bind();
    test_unknown_bio_never_correlates();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }

    printf("bpf_tls_prefix_bind: all checks passed\n");
    return 0;
}
