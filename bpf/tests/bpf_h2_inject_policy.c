// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tpinjector/inject_policy.h>

static void expect(h2_inject_facts_t f, h2_inject_verdict_t want, const char *msg) {
    const h2_inject_verdict_t got = h2_inject_verdict(&f);
    if (got != want) {
        fprintf(stderr, "FAIL: %s (want %d, got %d)\n", msg, want, got);
        exit(1);
    }
}

// :method POST, the ordinary request opener
static h2_inject_facts_t request(void) {
    h2_inject_facts_t f = {0};
    f.opener = 0x83;
    f.opener_readable = true;
    return f;
}

int main(void) {
    expect(request(), k_h2_inject_allow, "plain request is injected");

    h2_inject_facts_t f = request();
    f.opener = 0xc3; // dyn-table entry, encoder is warm
    expect(f, k_h2_inject_allow, "warm request is injected");

    f = request();
    f.opener_readable = false;
    expect(f, k_h2_skip_unreadable, "unreadable opener skips");

    f = request();
    f.opener = 0x88; // :status 200
    expect(f, k_h2_skip_not_request, "response skips");

    f = request();
    f.opener = 0x40; // literal new name: gRPC trailers
    expect(f, k_h2_skip_not_request, "trailers skip");

    f = request();
    f.sk_server = true;
    expect(f, k_h2_skip_server_socket, "server socket skips");

    f = request();
    f.uprobe_wrote = true;
    expect(f, k_h2_skip_uprobe_wrote, "uprobe-written stream skips");

    f = request();
    f.go_conn_without_tp = true;
    expect(f, k_h2_skip_go_no_tp, "go conn without a stored tp skips");

    f = request();
    f.frame_tp_present = true;
    expect(f, k_h2_skip_app_propagates, "frame already carrying one skips");

    f = request();
    f.sk_app_tp = true;
    expect(f, k_h2_skip_app_propagates, "self-propagating socket skips");

    f = request();
    f.opener = 0x20; // dynamic table size update, never skipped past
    expect(f, k_h2_skip_not_request, "unskipped size update is not a request opener");

    f = request();
    f.scan_incomplete = true;
    expect(f, k_h2_skip_unscanned, "unproven absence skips");

    // direction outranks everything: a response must never be injected, whatever else holds
    f = request();
    f.opener = 0x88;
    f.uprobe_wrote = true;
    f.scan_incomplete = true;
    expect(f, k_h2_skip_not_request, "response wins over other reasons");

    printf("OK: %s\n", __FILE__);
    return 0;
}
