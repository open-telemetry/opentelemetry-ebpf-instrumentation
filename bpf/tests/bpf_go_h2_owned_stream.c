// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

#include <common/go_h2_owned_stream.h>

static void expect(bool got, bool want, const char *message) {
    if (got != want) {
        fprintf(stderr, "FAIL: %s (want %d, got %d)\n", message, want, got);
        exit(1);
    }
}

int main(void) {
    const u64 now = 60ULL * 1000 * 1000 * 1000;

    expect(go_h2_owned_stream_is_fresh(now, now), true, "new marker is fresh");
    expect(go_h2_owned_stream_is_fresh(now - k_go_h2_owned_stream_fresh_ns, now),
           true,
           "marker at age bound is fresh");
    expect(go_h2_owned_stream_is_fresh(now - k_go_h2_owned_stream_fresh_ns - 1, now),
           false,
           "marker beyond age bound is stale");
    expect(go_h2_owned_stream_is_fresh(0, now), false, "zero timestamp is not a marker");
    expect(go_h2_owned_stream_is_fresh(now + 1, now), false, "future timestamp is stale");

    printf("OK: %s\n", __FILE__);
    return 0;
}
