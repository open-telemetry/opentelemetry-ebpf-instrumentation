// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Unconnected-UDP DNS classification in generictracer/dns.h: obi_msg_name_port,
// is_dns_msg and the unconn_dns_socks helpers. An unconnected resolver socket
// carries no peer in its tuple (d_port == 0), so :53 is only in msg_name.
//
// Run from repo root:
//   make -C bpf/tests bpf_dns_unconnected && bpf/tests/bpf_dns_unconnected

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

// Called by the dns.h include chain, omitted by the shared stub
#define BPF_ANY 0

static inline u64 bpf_ktime_get_ns(void) {
    return 0;
}

static inline u32 bpf_get_prandom_u32(void) {
    return 0;
}

static inline long bpf_loop(u32 nr_loops, void *cb, void *ctx, u64 flags) {
    return 0;
}

static inline long bpf_skb_load_bytes(const void *skb, u32 offset, void *to, u32 len) {
    return 0;
}

// The shared stubs no-op every read and map lookup, so the classifier is given
// live mocks below and they are macro-shadowed over the include.

// Host-resident structs, so a direct field access stands in for the CO-RE read
#define BPF_CORE_READ_INTO(dst, src, field) (*(dst) = (src)->field)

// Returns an error on a NULL source rather than faulting the test process
static long test_probe_read_kernel(void *dst, u32 size, const void *src) {
    if (!src) {
        return -1;
    }
    memcpy(dst, src, size);
    return 0;
}

// Stands in for the unconn_dns_socks LRU map; membership only, no eviction
enum { k_mock_map_capacity = 8 };

static struct {
    u64 keys[k_mock_map_capacity];
    u8 values[k_mock_map_capacity];
    bool used[k_mock_map_capacity];
} test_map;

static void mock_map_reset(void) {
    memset(&test_map, 0, sizeof(test_map));
}

static void *test_map_lookup(void *map, const void *key) {
    (void)map;
    const u64 k = *(const u64 *)key;

    for (int i = 0; i < k_mock_map_capacity; i++) {
        if (test_map.used[i] && test_map.keys[i] == k) {
            return &test_map.values[i];
        }
    }

    return NULL;
}

static long test_map_update(void *map, const void *key, const void *value, u64 flags) {
    (void)map;
    (void)flags;
    const u64 k = *(const u64 *)key;

    for (int i = 0; i < k_mock_map_capacity; i++) {
        if (test_map.used[i] && test_map.keys[i] == k) {
            test_map.values[i] = *(const u8 *)value;
            return 0;
        }
    }

    for (int i = 0; i < k_mock_map_capacity; i++) {
        if (!test_map.used[i]) {
            test_map.used[i] = true;
            test_map.keys[i] = k;
            test_map.values[i] = *(const u8 *)value;
            return 0;
        }
    }

    return -1;
}

#define bpf_probe_read_kernel test_probe_read_kernel
#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update

#include <generictracer/dns.h>

#undef bpf_probe_read_kernel
#undef bpf_map_lookup_elem
#undef bpf_map_update_elem

// obi_msg_name_port rejects a shorter msg_namelen, so a stub disagreeing with
// the kernel layout would move the boundary the msg_namelen cases pin
_Static_assert(sizeof(struct sockaddr_in) == 16, "sockaddr_in must match the kernel layout");

// Test harness

static int failures = 0;

static void check_u16(const char *name, u16 expected, u16 actual) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %u, got %u\n", name, expected, actual);
        failures++;
        return;
    }
    printf("ok: %s\n", name);
}

static void check_u8(const char *name, u8 expected, u8 actual) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %u, got %u\n", name, expected, actual);
        failures++;
        return;
    }
    printf("ok: %s\n", name);
}

// msg_name as the kernel presents it: the sockaddr passed to sendto(), or the
// source address filled in on recvmsg() return
static struct msghdr msg_with_addr(struct sockaddr_in *sa, int namelen) {
    struct msghdr msg = {
        .msg_name = sa,
        .msg_namelen = namelen,
    };
    return msg;
}

static struct sockaddr_in inet_addr_port(u16 family, u16 port) {
    struct sockaddr_in sa = {0};
    sa.sin_family = family;
    sa.sin_port = bpf_htons(port);
    return sa;
}

// obi_msg_name_port

static void test_msg_name_port_reads_ipv4_peer_port(void) {
    struct sockaddr_in sa = inet_addr_port(AF_INET, 53);
    struct msghdr msg = msg_with_addr(&sa, sizeof(sa));

    check_u16("msg_name port is read in host order", 53, obi_msg_name_port(&msg));
}

static void test_msg_name_port_reads_non_dns_port_unchanged(void) {
    struct sockaddr_in sa = inet_addr_port(AF_INET, 8080);
    struct msghdr msg = msg_with_addr(&sa, sizeof(sa));

    check_u16("a non-DNS peer port is reported as-is", 8080, obi_msg_name_port(&msg));
}

static void test_msg_name_port_rejects_null_msghdr(void) {
    check_u16("a NULL msghdr yields no port", 0, obi_msg_name_port(NULL));
}

static void test_msg_name_port_rejects_absent_name(void) {
    // empty recv-side msg_name, as Netty leaves it; the socket-identity tier
    // covers this case
    struct msghdr msg = msg_with_addr(NULL, sizeof(struct sockaddr_in));

    check_u16("an absent msg_name yields no port", 0, obi_msg_name_port(&msg));
}

static void test_msg_name_port_rejects_short_namelen(void) {
    struct sockaddr_in sa = inet_addr_port(AF_INET, 53);
    struct msghdr msg = msg_with_addr(&sa, (int)sizeof(sa) - 1);

    check_u16("a short msg_namelen yields no port", 0, obi_msg_name_port(&msg));
}

static void test_msg_name_port_rejects_negative_namelen(void) {
    struct sockaddr_in sa = inet_addr_port(AF_INET, 53);
    struct msghdr msg = msg_with_addr(&sa, -1);

    check_u16("a negative msg_namelen yields no port", 0, obi_msg_name_port(&msg));
}

static void test_msg_name_port_rejects_non_ipv4_family(void) {
    // stated scope limit: IPv6 DNS transport is not handled
    struct sockaddr_in sa = inet_addr_port(AF_INET6, 53);
    struct msghdr msg = msg_with_addr(&sa, sizeof(sa));

    check_u16("a non-AF_INET msg_name yields no port", 0, obi_msg_name_port(&msg));
}

// is_dns_msg

static void test_is_dns_msg_uses_tuple_fast_path(void) {
    connection_info_t conn = {.s_port = 40100, .d_port = 53};

    // tuple already names :53, so msg_name is never consulted
    check_u8("a connected socket is classified from the tuple", 1, is_dns_msg(&conn, NULL));
}

static void test_is_dns_msg_classifies_unconnected_query(void) {
    // musl's resolver: bind() + sendto(), so :53 is only in msg_name
    connection_info_t conn = {.s_port = 40100, .d_port = 0};
    struct sockaddr_in sa = inet_addr_port(AF_INET, 53);
    struct msghdr msg = msg_with_addr(&sa, sizeof(sa));

    check_u8("an unconnected DNS query is classified via msg_name", 1, is_dns_msg(&conn, &msg));
}

static void test_is_dns_msg_classifies_mdns_port(void) {
    connection_info_t conn = {.s_port = 40100, .d_port = 0};
    struct sockaddr_in sa = inet_addr_port(AF_INET, 5353);
    struct msghdr msg = msg_with_addr(&sa, sizeof(sa));

    check_u8("port 5353 is classified as DNS", 1, is_dns_msg(&conn, &msg));
}

static void test_is_dns_msg_rejects_unconnected_non_dns(void) {
    connection_info_t conn = {.s_port = 40100, .d_port = 0};
    struct sockaddr_in sa = inet_addr_port(AF_INET, 8125);
    struct msghdr msg = msg_with_addr(&sa, sizeof(sa));

    check_u8("unconnected non-DNS UDP is not classified", 0, is_dns_msg(&conn, &msg));
}

static void test_is_dns_msg_ignores_msg_name_when_peer_is_known(void) {
    // a connected socket, so :53 in msg_name must not override the tuple
    connection_info_t conn = {.s_port = 40100, .d_port = 8080};
    struct sockaddr_in sa = inet_addr_port(AF_INET, 53);
    struct msghdr msg = msg_with_addr(&sa, sizeof(sa));

    check_u8("msg_name is not consulted for a connected socket", 0, is_dns_msg(&conn, &msg));
}

static void test_is_dns_msg_rejects_unconnected_without_msg_name(void) {
    connection_info_t conn = {.s_port = 40100, .d_port = 0};

    check_u8("an unclassifiable answer falls through", 0, is_dns_msg(&conn, NULL));
}

// unconn_dns_socks

static void test_unconn_sock_is_not_recorded_by_default(void) {
    mock_map_reset();

    check_u8("an unseen socket is not a DNS socket", 0, obi_is_unconn_dns_sock((void *)0x1000));
}

static void test_unconn_sock_round_trips(void) {
    mock_map_reset();
    obi_note_unconn_dns_sock((void *)0x1000);

    check_u8("a noted socket is recognized", 1, obi_is_unconn_dns_sock((void *)0x1000));
}

static void test_unconn_sock_does_not_match_other_sockets(void) {
    // the recv-side tier keys on socket identity, so a second resolver socket
    // must not inherit the first one's classification
    mock_map_reset();
    obi_note_unconn_dns_sock((void *)0x1000);

    check_u8("a different socket is unaffected", 0, obi_is_unconn_dns_sock((void *)0x2000));
}

static void test_unconn_sock_note_is_idempotent(void) {
    mock_map_reset();
    obi_note_unconn_dns_sock((void *)0x1000);
    obi_note_unconn_dns_sock((void *)0x1000);

    check_u8("re-noting a socket keeps it recognized", 1, obi_is_unconn_dns_sock((void *)0x1000));
}

int main(void) {
    test_msg_name_port_reads_ipv4_peer_port();
    test_msg_name_port_reads_non_dns_port_unchanged();
    test_msg_name_port_rejects_null_msghdr();
    test_msg_name_port_rejects_absent_name();
    test_msg_name_port_rejects_short_namelen();
    test_msg_name_port_rejects_negative_namelen();
    test_msg_name_port_rejects_non_ipv4_family();

    test_is_dns_msg_uses_tuple_fast_path();
    test_is_dns_msg_classifies_unconnected_query();
    test_is_dns_msg_classifies_mdns_port();
    test_is_dns_msg_rejects_unconnected_non_dns();
    test_is_dns_msg_ignores_msg_name_when_peer_is_known();
    test_is_dns_msg_rejects_unconnected_without_msg_name();

    test_unconn_sock_is_not_recorded_by_default();
    test_unconn_sock_round_trips();
    test_unconn_sock_does_not_match_other_sockets();
    test_unconn_sock_note_is_idempotent();

    if (failures > 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("all unconnected DNS classification tests passed\n");
    return 0;
}
