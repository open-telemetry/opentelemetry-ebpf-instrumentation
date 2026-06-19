// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The following code is copied from bpf/generictracer/protocol_postgres.h and
 * adapted to run as a host unit test. The function under test is:
 *
 *   static __always_inline u8 is_postgres(connection_info_t *conn_info,
 *                                         const unsigned char *data,
 *                                         u32 data_len,
 *                                         enum protocol_type *protocol_type);
 *
 * Together with its helper postgres_parse_hdr(). The BPF-only helpers
 * (bpf_probe_read, bpf_ntohl, bpf_dbg_printk, bpf_map_update_elem and the
 * protocol_cache map) are mocked below. The real header cannot be #included
 * directly on a non-BPF target because its map definitions use SEC(".maps").
 *
 * These tests reproduce https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1464
 * where request segments that concatenate several Postgres messages, exceed the
 * per-segment message limit, or end with a message split across TCP segments
 * were rejected because the parser required message_size == data_len.
 */

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

// ---------------------------------------------------------------------------
// Mocks for the BPF runtime helpers used by is_postgres / postgres_parse_hdr.
// ---------------------------------------------------------------------------

typedef struct connection_info {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
} connection_info_t;

enum protocol_type {
    k_protocol_type_unknown = 0,
    k_protocol_type_http,
    k_protocol_type_postgres,
};

#define BPF_ANY 0

#ifndef __always_inline
#define __always_inline inline
#endif

static void bpf_probe_read(void *dst, u32 size, const void *src) {
    memcpy(dst, src, size);
}

#define bpf_ntohl(x) ntohl(x)

// Discard the formatted debug output, mirroring bpf_dbg_printk when BPF debug
// is disabled.
#define bpf_dbg_printk(...) ((void)0)

// protocol_cache and bpf_map_update_elem are irrelevant to the classification
// decision, so they are reduced to no-ops here.
static int protocol_cache;
static long bpf_map_update_elem(void *map, const void *key, const void *value, u64 flags) {
    (void)map;
    (void)key;
    (void)value;
    (void)flags;
    return 0;
}

// ---------------------------------------------------------------------------
// Code under test (copied verbatim from protocol_postgres.h).
// ---------------------------------------------------------------------------

struct postgres_hdr {
    u32 message_len;
    u8 message_type;
    u8 _pad[3];
};

enum {
    k_pg_hdr_size = 5,
    k_pg_messages_in_packet_max = 10,

    k_pg_msg_bind = 'B',
    k_pg_msg_execute = 'E',
    k_pg_msg_parse = 'P',
    k_pg_msg_query = 'Q',
};

static __always_inline struct postgres_hdr postgres_parse_hdr(const unsigned char *data) {
    struct postgres_hdr hdr = {};

    u8 header[k_pg_hdr_size] = {};
    bpf_probe_read(header, k_pg_hdr_size, data);

    u32 message_len_le;
    __builtin_memcpy(&message_len_le, header + 1, sizeof(message_len_le));

    hdr.message_type = header[0];
    hdr.message_len = bpf_ntohl(message_len_le);

    return hdr;
}

static __always_inline u8 is_postgres(connection_info_t *conn_info,
                                      const unsigned char *data,
                                      u32 data_len,
                                      enum protocol_type *protocol_type) {
    if (*protocol_type != k_protocol_type_postgres && *protocol_type != k_protocol_type_unknown) {
        return 0;
    }

    if (data_len < k_pg_hdr_size) {
        bpf_dbg_printk("is_postgres: data_len is too short: %d", data_len);
        return 0;
    }

    size_t message_size = 0;
    struct postgres_hdr hdr;
    bool includes_known_command = false;
    bool malformed = false;

    for (u8 i = 0; i < k_pg_messages_in_packet_max; i++) {
        if (message_size + k_pg_hdr_size > data_len) {
            break;
        }

        hdr = postgres_parse_hdr(data + message_size);

        if (hdr.message_len < 4) {
            malformed = true;
            break;
        }

        const size_t full_message_size = (size_t)hdr.message_len + 1;

        if (message_size + full_message_size > data_len) {
            break;
        }

        message_size += full_message_size;

        switch (hdr.message_type) {
        case k_pg_msg_query:
        case k_pg_msg_parse:
        case k_pg_msg_bind:
        case k_pg_msg_execute:
            includes_known_command = true;
            break;
        default:
            break;
        }
    }

    if (malformed || !includes_known_command) {
        bpf_dbg_printk("is_postgres: not postgres (malformed=%d, known_command=%d)",
                       malformed,
                       includes_known_command);
        return 0;
    }

    *protocol_type = k_protocol_type_postgres;
    bpf_map_update_elem(&protocol_cache, conn_info, protocol_type, BPF_ANY);

    bpf_dbg_printk("is_postgres: postgres! message_type=%u", hdr.message_type);
    return 1;
}

// ---------------------------------------------------------------------------
// Test harness.
// ---------------------------------------------------------------------------

static int failures = 0;

static void check(const char *name, u8 expected, u8 actual) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected is_postgres=%u, got %u\n", name, expected, actual);
        failures++;
    } else {
        printf("ok: %s\n", name);
    }
}

// Appends a Postgres v3 message (1 type byte + 4-byte big-endian length that
// counts itself + body) to buf at *off. body_len is the number of payload bytes
// after the header. Returns the total bytes written.
static u32 put_msg(unsigned char *buf, u32 *off, u8 type, u32 body_len) {
    buf[*off] = type;
    u32 declared = body_len + 4; // length field counts itself but not the type byte
    u32 be = htonl(declared);
    memcpy(buf + *off + 1, &be, sizeof(be));
    for (u32 i = 0; i < body_len; i++) {
        buf[*off + k_pg_hdr_size + i] = (unsigned char)('a' + (i % 26));
    }
    u32 total = k_pg_hdr_size + body_len;
    *off += total;
    return total;
}

static u8 classify(const unsigned char *data, u32 len) {
    connection_info_t conn = {0};
    enum protocol_type pt = k_protocol_type_unknown;
    return is_postgres(&conn, data, len, &pt);
}

static void test_simple_query_exact_fill(void) {
    unsigned char buf[64] = {0};
    u32 off = 0;
    put_msg(buf, &off, k_pg_msg_query, 9); // "SELECT 1\0"
    check("simple query, exact fill", 1, classify(buf, off));
}

static void test_extended_protocol_multi_message(void) {
    unsigned char buf[256] = {0};
    u32 off = 0;
    put_msg(buf, &off, k_pg_msg_parse, 20);
    put_msg(buf, &off, k_pg_msg_bind, 30);
    put_msg(buf, &off, 'D', 10); // Describe (not a known frontend command)
    put_msg(buf, &off, k_pg_msg_execute, 6);
    put_msg(buf, &off, 'S', 0); // Sync (len == 4, empty body)
    check("extended protocol, multiple complete messages", 1, classify(buf, off));
}

static void test_more_than_loop_limit(void) {
    unsigned char buf[512] = {0};
    u32 off = 0;
    put_msg(buf, &off, k_pg_msg_query, 8); // known command in the first slot
    for (int i = 0; i < 15; i++) {
        put_msg(buf, &off, 'S', 0); // many small Sync messages, exceeding the limit
    }
    check("more than k_pg_messages_in_packet_max messages", 1, classify(buf, off));
}

static void test_trailing_partial_message(void) {
    unsigned char buf[128] = {0};
    u32 off = 0;
    put_msg(buf, &off, k_pg_msg_query, 10); // complete query
    // Now a Bind whose declared body extends past the captured buffer.
    buf[off] = k_pg_msg_bind;
    u32 be = htonl(4 + 200); // declares a 200-byte body we will not fully include
    memcpy(buf + off + 1, &be, sizeof(be));
    off += k_pg_hdr_size + 8; // include only 8 bytes of the partial Bind body
    check("trailing message split across segments", 1, classify(buf, off));
}

static void test_http_post_rejected(void) {
    const char *http = "POST /v1/data HTTP/1.1\r\nHost: example\r\n\r\n{\"k\":1}";
    check("HTTP POST request is not postgres",
          0,
          classify((const unsigned char *)http, (u32)strlen(http)));
}

static void test_startup_message_rejected(void) {
    // StartupMessage: Int32 length + Int32 protocol(0x00030000) + params. No type byte.
    unsigned char buf[32] = {0};
    u32 len = htonl(20);
    u32 proto = htonl(0x00030000);
    memcpy(buf, &len, 4);
    memcpy(buf + 4, &proto, 4);
    memcpy(buf + 8, "user\0x\0", 7);
    check("startup message is not classified", 0, classify(buf, 20));
}

static void test_response_only_segment_rejected(void) {
    // Backend response messages carry no frontend command, so a response-only
    // segment must not classify the connection from this side.
    unsigned char buf[256] = {0};
    u32 off = 0;
    put_msg(buf, &off, 'T', 30); // RowDescription
    put_msg(buf, &off, 'D', 40); // DataRow
    put_msg(buf, &off, 'C', 12); // CommandComplete
    put_msg(buf, &off, 'Z', 1);  // ReadyForQuery
    check("response-only segment has no frontend command", 0, classify(buf, off));
}

static void test_too_short_rejected(void) {
    unsigned char buf[4] = {'Q', 0, 0, 0};
    check("buffer shorter than a header", 0, classify(buf, sizeof(buf)));
}

static void test_malformed_length_rejected(void) {
    // A message that declares a length < 4 cannot be valid Postgres.
    unsigned char buf[16] = {0};
    buf[0] = k_pg_msg_query;
    u32 be = htonl(2); // invalid: smaller than the 4-byte length field
    memcpy(buf + 1, &be, sizeof(be));
    check("message length below minimum is rejected", 0, classify(buf, 12));
}

static void test_multi_message_not_exact_fill(void) {
    // Reproduces the reported case: several complete frontend messages followed
    // by the start of another message, so message_size != data_len.
    unsigned char buf[256] = {0};
    u32 off = 0;
    put_msg(buf, &off, k_pg_msg_parse, 40);
    put_msg(buf, &off, k_pg_msg_bind, 50);
    put_msg(buf, &off, k_pg_msg_execute, 12);
    off += 3; // a few trailing bytes of a following, not-yet-complete message
    check("concatenated messages not filling the segment", 1, classify(buf, off));
}

int main(void) {
    test_simple_query_exact_fill();
    test_extended_protocol_multi_message();
    test_more_than_loop_limit();
    test_trailing_partial_message();
    test_http_post_rejected();
    test_startup_message_rejected();
    test_response_only_segment_rejected();
    test_too_short_rejected();
    test_malformed_length_rejected();
    test_multi_message_not_exact_fill();

    if (failures > 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("all postgres detection tests passed\n");
    return 0;
}
