// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The following code is copied from bpf/generictracer/protocol_mssql.h and
 * adapted to run as a host unit test. The functions under test are
 * mssql_response_eom(), mssql_capture_response_start() and
 * mssql_append_response_chunk(), together with mssql_parse_hdr(). The BPF-only
 * helpers are mocked below and tcp_req_t is reduced to the fields these
 * functions use.
 *
 * The tests check that, without large buffers, rbuf holds the start of the
 * response (TDS header included) whether the client reads the whole response at
 * once or in pieces of any size, such as the 8-byte packet header on its own
 * before the payload.
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

#ifndef __always_inline
#define __always_inline inline
#endif

// ---------------------------------------------------------------------------
// Mocks for the BPF runtime helpers and types.
// ---------------------------------------------------------------------------

enum { k_tcp_res_len = 128 };

typedef struct tcp_req {
    u32 resp_len;
    unsigned char rbuf[k_tcp_res_len];
} tcp_req_t;

static void bpf_probe_read(void *dst, u32 size, const void *src) {
    memcpy(dst, src, size);
}

#define bpf_ntohs(x) ntohs(x)
#define bpf_dbg_printk(...) ((void)0)
#define barrier_var(var) ((void)(var))

// ---------------------------------------------------------------------------
// Code under test (copied from protocol_mssql.h).
// ---------------------------------------------------------------------------

struct mssql_hdr {
    u8 type;
    u8 status;
    u16 length; // big-endian
    u16 spid;   // big-endian
    u8 packet_id;
    u8 window;
};

enum {
    k_mssql_hdr_size = 8,
    k_mssql_messages_in_packet_max = 10,
    k_mssql_status_eom = 0x01,
    k_mssql_msg_response = 0x04,
};

static __always_inline struct mssql_hdr mssql_parse_hdr(const unsigned char *data) {
    struct mssql_hdr hdr = {};

    bpf_probe_read(&hdr, sizeof(hdr), (const void *)data);

    // Length and SPID are big-endian
    hdr.length = bpf_ntohs(hdr.length);
    hdr.spid = bpf_ntohs(hdr.spid);

    return hdr;
}

static __always_inline u32 mssql_append_response_chunk(unsigned char *rbuf,
                                                       const u32 captured,
                                                       const unsigned char *src,
                                                       const u32 len,
                                                       const u32 chunk) {
    // keep the compiler from folding the bound checks the verifier relies on
    u64 off = captured;
    barrier_var(off);
    u64 n = len;
    barrier_var(n);

    if (n == 0 || off > k_tcp_res_len - chunk) {
        return 0;
    }
    if (n > chunk) {
        n = chunk;
    }

    bpf_probe_read(rbuf + off, n, src);

    return n;
}

static __always_inline void
mssql_capture_response_start(tcp_req_t *req, const unsigned char *u_buf, const u32 bytes_len) {
    u32 captured = req->resp_len;
    u32 consumed = 0;

#pragma unroll
    for (u32 chunk = k_tcp_res_len; chunk > 0; chunk /= 2) {
        if (captured >= k_tcp_res_len || consumed >= bytes_len) {
            return;
        }

        const u32 n = mssql_append_response_chunk(
            req->rbuf, captured, u_buf + consumed, bytes_len - consumed, chunk);
        captured += n;
        consumed += n;
    }
}

static __always_inline int mssql_response_eom(tcp_req_t *req, const void *u_buf, u32 bytes_len) {
    mssql_capture_response_start(req, u_buf, bytes_len);

    req->resp_len += bytes_len;

    // Scan complete TDS packets in the current recv buffer for the EOM bit.
    // A response may arrive as: (a) one or more complete packets in a single
    // recv, or (b) a single packet split across multiple recvs (header first,
    // then payload). Handle both by falling back to accumulated-length tracking
    // when the current buffer does not start at a TDS packet boundary.
    bool eom = false;
    bool found_complete_packet = false;
    u32 offset = 0;
    for (u8 i = 0; i < k_mssql_messages_in_packet_max; i++) {
        if (offset + k_mssql_hdr_size > bytes_len) {
            break;
        }
        const struct mssql_hdr hdr = mssql_parse_hdr((const unsigned char *)u_buf + offset);
        if (hdr.length < k_mssql_hdr_size || offset + hdr.length > bytes_len) {
            break;
        }
        found_complete_packet = true;
        if (hdr.status & k_mssql_status_eom) {
            eom = true;
        }
        offset += hdr.length;
    }

    if (eom) {
        return 0;
    } else if (found_complete_packet) {
        // Complete packets present but no EOM: more packets expected.
        bpf_dbg_printk("mssql response: waiting for EOM, acc=%d", req->resp_len);
        return -1;
    }

    // Could not parse a complete TDS packet (partial recv or payload
    // continuation). Fall back to length tracking using the saved header.
    if (req->resp_len < k_mssql_hdr_size) {
        return -1;
    }
    const struct mssql_hdr first_hdr = mssql_parse_hdr(req->rbuf);
    if (first_hdr.length >= k_mssql_hdr_size) {
        const u32 prev_resp_len = req->resp_len - bytes_len;
        // Wait while packet 1 is still completing, or if it just finished
        // in this recv with no EOM (more packets follow; the next recv
        // will start at a TDS boundary where the main loop detects EOM).
        if (prev_resp_len < first_hdr.length &&
            (req->resp_len < first_hdr.length || !(first_hdr.status & k_mssql_status_eom))) {
            bpf_dbg_printk(
                "mssql response: partial, acc=%d exp=%d", req->resp_len, first_hdr.length);
            return -1;
        }
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Test harness.
// ---------------------------------------------------------------------------

static int failures = 0;

static void check_int(const char *name, int expected, int actual) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %d, got %d\n", name, expected, actual);
        failures++;
    } else {
        printf("ok: %s\n", name);
    }
}

static void
check_bytes(const char *name, const unsigned char *expected, const unsigned char *actual, u32 len) {
    if (memcmp(expected, actual, len) != 0) {
        fprintf(stderr, "FAIL: %s\n  rbuf does not hold the expected bytes\n", name);
        failures++;
    } else {
        printf("ok: %s\n", name);
    }
}

// Writes one TDS packet of total length pkt_len at buf with a recognizable
// payload (payload byte i is seed + i) and returns pkt_len.
static u32 put_packet(unsigned char *buf, u8 status, u16 pkt_len, u8 seed) {
    buf[0] = k_mssql_msg_response;
    buf[1] = status;
    buf[2] = (u8)(pkt_len >> 8);
    buf[3] = (u8)pkt_len;
    buf[4] = buf[5] = 0;
    buf[6] = 1;
    buf[7] = 0;
    for (u32 i = k_mssql_hdr_size; i < pkt_len; i++) {
        buf[i] = (u8)(seed + i);
    }
    return pkt_len;
}

static void test_whole_response_in_one_read(void) {
    unsigned char resp[64];
    const u32 len = put_packet(resp, k_mssql_status_eom, sizeof(resp), 0x10);
    tcp_req_t req = {0};

    check_int("one read: response complete", 0, mssql_response_eom(&req, resp, len));
    check_bytes("one read: rbuf holds the response", resp, req.rbuf, len);
}

static void test_header_read_before_payload(void) {
    unsigned char resp[200];
    put_packet(resp, k_mssql_status_eom, sizeof(resp), 0x20);
    tcp_req_t req = {0};

    check_int("header first: waits for the payload",
              -1,
              mssql_response_eom(&req, resp, k_mssql_hdr_size));
    check_int("header first: payload completes the response",
              0,
              mssql_response_eom(&req, resp + k_mssql_hdr_size, sizeof(resp) - k_mssql_hdr_size));
    check_bytes("header first: rbuf holds header and payload start", resp, req.rbuf, k_tcp_res_len);
}

static void test_large_first_read_keeps_start(void) {
    unsigned char resp[1000];
    put_packet(resp, k_mssql_status_eom, sizeof(resp), 0x30);
    tcp_req_t req = {0};

    check_int("large first read: waits for the rest", -1, mssql_response_eom(&req, resp, 300));
    check_int(
        "large first read: completes", 0, mssql_response_eom(&req, resp + 300, sizeof(resp) - 300));
    check_bytes("large first read: rbuf holds the first bytes", resp, req.rbuf, k_tcp_res_len);
}

static void test_multi_packet_response_keeps_first_packet(void) {
    unsigned char first[96];
    unsigned char second[64];
    put_packet(first, 0, sizeof(first), 0x40);
    put_packet(second, k_mssql_status_eom, sizeof(second), 0x50);
    tcp_req_t req = {0};

    check_int(
        "two packets: waits after the first", -1, mssql_response_eom(&req, first, sizeof(first)));
    check_int("two packets: second completes", 0, mssql_response_eom(&req, second, sizeof(second)));
    check_bytes("two packets: rbuf holds the first packet", first, req.rbuf, sizeof(first));
}

static void test_payload_split_across_reads(void) {
    unsigned char resp[200];
    put_packet(resp, k_mssql_status_eom, sizeof(resp), 0x60);
    tcp_req_t req = {0};

    mssql_response_eom(&req, resp, k_mssql_hdr_size);
    mssql_response_eom(&req, resp + k_mssql_hdr_size, 4);
    check_int(
        "header, 4 bytes, rest: completes",
        0,
        mssql_response_eom(&req, resp + k_mssql_hdr_size + 4, sizeof(resp) - k_mssql_hdr_size - 4));
    check_bytes(
        "header, 4 bytes, rest: rbuf holds the response start", resp, req.rbuf, k_tcp_res_len);
}

static void test_byte_at_a_time(void) {
    unsigned char resp[150];
    put_packet(resp, k_mssql_status_eom, sizeof(resp), 0x70);
    tcp_req_t req = {0};

    int last = -1;
    for (u32 i = 0; i < sizeof(resp); i++) {
        last = mssql_response_eom(&req, resp + i, 1);
    }
    check_int("byte at a time: completes", 0, last);
    check_bytes("byte at a time: rbuf holds the response start", resp, req.rbuf, k_tcp_res_len);
}

int main(void) {
    test_whole_response_in_one_read();
    test_header_read_before_payload();
    test_large_first_read_keeps_start();
    test_multi_packet_response_keeps_first_packet();
    test_payload_split_across_reads();
    test_byte_at_a_time();

    if (failures > 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("all mssql response capture tests passed\n");
    return 0;
}
