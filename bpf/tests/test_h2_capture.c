// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <bpfcore/bpf_helpers.h>

static const unsigned char source[] = {0, 0, 3, 1, 4, 0, 0, 0, 3, 0x82, 0x86, 0x84};
static unsigned int reads;
static bool fail_read;

static long read_capture(void *destination, unsigned int size, const void *buffer) {
    reads++;
    if (fail_read || buffer != source || size > sizeof(source)) {
        return -EFAULT;
    }
    memcpy(destination, buffer, size);
    return 0;
}

#define bpf_probe_read read_capture
#include <common/h2_capture.h>

int main(void) {
    unsigned char capture[256];
    memset(capture, 0xff, sizeof(capture));
    assert(h2_capture_bytes(capture, sizeof(capture), source, sizeof(source)) == 0);
    assert(memcmp(capture, source, sizeof(source)) == 0);
    for (unsigned int i = sizeof(source); i < sizeof(capture); i++) {
        assert(capture[i] == 0);
    }
    assert(reads == 1);

    assert(h2_capture_bytes(capture, 4, source, sizeof(source)) == 0);
    assert(memcmp(capture, source, 4) == 0);
    assert(reads == 2);

    assert(h2_capture_bytes(capture, sizeof(capture), source, 0) == 0);
    assert(reads == 2);
    for (unsigned int i = 0; i < sizeof(capture); i++) {
        assert(capture[i] == 0);
    }

    fail_read = true;
    assert(h2_capture_bytes(capture, sizeof(capture), source, sizeof(source)) == -EFAULT);
    puts("HTTP/2 capture respects short source buffers and clears uncaptured bytes");
    return 0;
}
