// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/h2_defs.h>

// Whether a HEADERS frame may receive a traceparent. The facts arrive in two stages —
// detect_h2 knows the direction, create_h2_tp knows what the block already carries — so the
// verdict is computed twice over the same rules rather than scattered across both.
typedef enum {
    k_h2_inject_allow = 0,
    k_h2_skip_unreadable,     // opener byte could not be read
    k_h2_skip_not_request,    // response or trailer block
    k_h2_skip_server_socket,  // a response was seen here, we are the server
    k_h2_skip_uprobe_wrote,   // Go uprobe already put the traceparent in the buffer
    k_h2_skip_go_no_tp,       // Go conn with no stored tp: uprobes own creation
    k_h2_skip_app_propagates, // sender sends its own, a second field invalidates both
    k_h2_skip_unscanned,      // block not walked to the end, absence unproven
} h2_inject_verdict_t;

typedef struct h2_inject_facts {
    u8 opener;
    bool opener_readable;
    bool sk_server;
    bool frame_tp_present;
    bool sk_app_tp;
    bool uprobe_wrote;
    bool go_conn_without_tp;
    bool scan_incomplete;
} h2_inject_facts_t;

static __always_inline h2_inject_verdict_t h2_inject_verdict(const h2_inject_facts_t *f) {
    if (!f->opener_readable) {
        return k_h2_skip_unreadable;
    }
    if (!h2_hpack_opens_request(f->opener)) {
        return k_h2_skip_not_request;
    }
    if (f->sk_server) {
        return k_h2_skip_server_socket;
    }
    if (f->uprobe_wrote) {
        return k_h2_skip_uprobe_wrote;
    }
    if (f->go_conn_without_tp) {
        return k_h2_skip_go_no_tp;
    }
    if (f->frame_tp_present || f->sk_app_tp) {
        return k_h2_skip_app_propagates;
    }
    // a second traceparent invalidates both, so absence has to be proven, not assumed
    if (f->scan_incomplete) {
        return k_h2_skip_unscanned;
    }

    return k_h2_inject_allow;
}
