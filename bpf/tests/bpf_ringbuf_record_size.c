// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

#include <bpfcore/vmlinux.h>

#include <common/ringbuf_record.h>

static void expect(u64 got, u64 want, const char *message) {
    if (got != want) {
        fprintf(stderr,
                "FAIL: %s (want %llu, got %llu)\n",
                message,
                (unsigned long long)want,
                (unsigned long long)got);
        exit(1);
    }
}

int main(void) {
    // header plus payload, rounded up to 8 bytes, as in __bpf_ringbuf_reserve
    expect(ringbuf_record_size(1), 16, "1-byte record takes header and padding");
    expect(ringbuf_record_size(8), 16, "aligned payload needs no padding");
    expect(ringbuf_record_size(9), 24, "one byte over alignment adds a full word");
    expect(ringbuf_record_size(13), 24, "unaligned payload is padded");
    expect(ringbuf_record_size(16), 24, "aligned payload after the header");
    expect(ringbuf_record_size(17), 32, "padding starts again past the next word");
    expect(ringbuf_record_size(4096), 4104, "page-sized payload");

    for (u64 size = 1; size <= 1024; size++) {
        const u64 record = ringbuf_record_size(size);

        expect(record % k_ringbuf_record_align, 0, "record is 8-byte aligned");
        expect(record >= size + BPF_RINGBUF_HDR_SZ, 1, "record holds header and payload");
        expect(
            record - size - BPF_RINGBUF_HDR_SZ < k_ringbuf_record_align, 1, "padding is minimal");
    }

    // a 20-byte bpf_ringbuf_output with 4072 bytes queued crosses a 4096-byte wakeup threshold:
    // the record takes 32 bytes, so counting only the payload would miss the wakeup
    const u64 queued = 4072;
    const u64 threshold = 4096;
    expect(queued + 20 >= threshold, 0, "payload alone stays under the threshold");
    expect(queued + ringbuf_record_size(20) >= threshold, 1, "record crosses the threshold");

    printf("OK: %s\n", __FILE__);
    return 0;
}
