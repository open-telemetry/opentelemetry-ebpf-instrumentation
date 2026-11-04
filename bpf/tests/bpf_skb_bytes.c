// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#define bpf_clamp_umin(var, min)                                                                   \
    do {                                                                                           \
        if ((var) < (min))                                                                         \
            (var) = (min);                                                                         \
    } while (0)

static unsigned char *destination;
static u32 capacity;
static u32 copied;
static u32 source_offset;

static long bpf_skb_load_bytes(const void *skb, u32 offset, void *to, u32 len) {
    assert(len > 0 && len <= 16);
    assert((unsigned char *)to == destination + copied);
    assert(offset == source_offset + copied);
    assert(copied + len <= capacity);
    memcpy(to, (const unsigned char *)skb + offset, len);
    copied += len;
    return 0;
}

#include <generictracer/skb_bytes.h>

int main(void) {
    unsigned char source[1024];
    unsigned char output[514];
    for (u32 i = 0; i < sizeof(source); ++i) {
        source[i] = (unsigned char)i;
    }
    const u32 lengths[] = {
        0, 1, 15, 16, 17, 255, 256, 257, 495, 496, 497, 511, 512, 513, UINT32_MAX};
    const u32 capacities[] = {256, 512};
    for (u32 c = 0; c < sizeof(capacities) / sizeof(*capacities); ++c) {
        for (u32 i = 0; i < sizeof(lengths) / sizeof(*lengths); ++i) {
            memset(output, 0xa5, sizeof(output));
            destination = output + 1;
            capacity = capacities[c];
            source_offset = 13;
            copied = 0;
            read_skb_bytes(source, source_offset, destination, lengths[i], capacity);
            const u32 expected = lengths[i] < capacity ? lengths[i] : capacity;
            assert(copied == expected);
            assert(memcmp(destination, source + source_offset, expected) == 0);
            assert(output[0] == 0xa5 && destination[expected] == 0xa5);
        }
    }
    puts("PASS: packet copies preserve all bytes and bounds in 30 boundary cases");
}
