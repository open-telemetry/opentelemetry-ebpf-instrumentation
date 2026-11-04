// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

static long copy_kernel(void *dst, u32 size, const void *src) {
    memcpy(dst, src, size);
    return 0;
}
#define bpf_probe_read_kernel copy_kernel
#include <generictracer/recv_prefix.h>

enum { max_read = 8192 };

int main(void) {
    unsigned char joined[max_read + MIN_HTTP2_SIZE];
    recv_prefix_t prefix = {};
    const unsigned char request[] = "POST /fragment HTTP/1.1\r\nHost: test\r\n\r\n";
    assert(append_recv_prefix(&prefix, request, 1, joined, max_read) == 0);
    assert(prefix.len == 1);
    u32 total = append_recv_prefix(&prefix, request + 1, sizeof(request) - 2, joined, max_read);
    assert(total == sizeof(request) - 1);
    assert(memcmp(joined, request, total) == 0 && prefix.len == 0);

    const unsigned char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    for (u32 i = 0; i < sizeof(preface) - 1; i++) {
        total = append_recv_prefix(&prefix, preface + i, 1, joined, max_read);
        assert(total == (i + 1 == MIN_HTTP2_SIZE ? MIN_HTTP2_SIZE : 0));
    }
    assert(memcmp(joined, preface, MIN_HTTP2_SIZE) == 0);

    unsigned char full[max_read];
    memset(full, 'x', sizeof(full));
    assert(append_recv_prefix(&prefix, (const unsigned char *)"P", 1, joined, max_read) == 0);
    total = append_recv_prefix(&prefix, full, sizeof(full), joined, max_read);
    assert(total == max_read + 1 && joined[0] == 'P');
    assert(memcmp(joined + 1, full, sizeof(full)) == 0);

    const unsigned char binary[] = {0x01, 0x02};
    assert(append_recv_prefix(&prefix, binary, 1, joined, max_read) == 0);
    assert(append_recv_prefix(&prefix, binary + 1, 1, joined, max_read) == 2);
    assert(memcmp(joined, binary, sizeof(binary)) == 0);
    const unsigned char nats[] = "PUB a 0\r\n\r\n";
    assert(append_recv_prefix(&prefix, nats, 1, joined, max_read) == 0);
    assert(append_recv_prefix(&prefix, nats + 1, sizeof(nats) - 2, joined, max_read) ==
           sizeof(nats) - 1);
    assert(memcmp(joined, nats, sizeof(nats) - 1) == 0);
    puts("PASS: single-byte TCP reads preserve HTTP/1, HTTP/2, binary data, and the full read "
         "capacity");
}
