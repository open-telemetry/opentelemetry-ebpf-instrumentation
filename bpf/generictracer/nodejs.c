// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/common.h>
#include <common/ringbuf.h>
#include <common/strings.h>
#include <common/tracing.h>

#include <logger/bpf_dbg.h>

#include <maps/fd_to_connection.h>
#include <maps/nodejs_fd_map.h>

#include <pid/pid.h>

#include <shared/obi_ctx.h>

enum {
    k_delim_offset = 13,
    k_variant_offset = 14,
    k_fd1_offset = 14,
    k_fd2_offset = 18,
    k_ctx_fd_offset = 18,
    k_max_fd_digits = 4,
    // strlen("/dev/null/obi-span/") — the JSON span payload starts here
    k_span_payload_offset = 19,
};

static __always_inline int handle_async_switch(char *buf, const u64 pid_tgid) {
    u32 fd = 0;
    for (u8 i = 0; i < k_max_fd_digits; ++i) {
        fd *= 10;
        fd += buf[k_ctx_fd_offset + i] - '0';
    }

    bpf_dbg_printk("nodejs_async_switch: %s, pid_tgid = %llx, fd = %u", buf, pid_tgid, fd);

    const fd_key fkey = {.pid_tgid = pid_tgid, .fd = (s32)fd};
    const connection_info_t *conn = bpf_map_lookup_elem(&fd_to_connection, &fkey);
    if (!conn) {
        obi_ctx__del(pid_tgid);
        return 0;
    }

    const tp_info_pid_t *tp = trace_info_for_connection(conn, TRACE_TYPE_SERVER);
    if (tp && tp->valid) {
        obi_ctx__set(pid_tgid, &tp->tp);
    } else {
        obi_ctx__del(pid_tgid);
    }

    return 0;
}

// Manual span emitted by the injected span bridge (spanbridge.js):
//     /dev/null/obi-span/<json>
// The JSON document (name, ids, duration, attributes...) is copied verbatim
// into a node_span_event_t; user space parses it (ReadNodeSpanEventIntoSpan).
// We stamp the event with bpf_ktime_get_ns() (the sentinel fires inside
// span.end(), so this is the span end time in the same monotonic domain the
// rest of the pipeline uses) and with the current request trace context from
// traces_ctx_v1 — maintained by the async-context sentinels above — so the
// span can be parented under OBI's automatic server span.
static __always_inline int handle_node_span(const char *path, const u64 pid_tgid) {
    node_span_event_t *ev = bpf_ringbuf_reserve(&events, sizeof(node_span_event_t), 0);
    if (!ev) {
        return 0;
    }

    // Only explicitly-read fields need initializing. We don't zero the whole
    // event: a memset over the ~2KB struct compiles to an out-of-line memset
    // call the BPF loader rejects ("unknown func"). The payload bytes past
    // payload_len are never read by user space, and the _pad bytes are never
    // read at all, so both are fine left uninitialized. has_parent_ctx MUST be
    // set though — user space reads the parent ids only when it is non-zero.
    ev->type = EVENT_NODE_SPAN;
    ev->end_ktime = bpf_ktime_get_ns();
    task_pid(&ev->pid);

    const obi_ctx_info_t *octx = obi_ctx__get(pid_tgid);
    if (octx) {
        ev->has_parent_ctx = 1;
        bpf_memcpy(ev->parent_trace_id, (void *)octx->trace_id, TRACE_ID_SIZE_BYTES);
        bpf_memcpy(ev->parent_span_id, (void *)octx->span_id, SPAN_ID_SIZE_BYTES);
    } else {
        ev->has_parent_ctx = 0;
    }

    const long len = bpf_probe_read_user_str(
        ev->payload, NODE_SPAN_PAYLOAD_MAX_LEN, path + k_span_payload_offset);
    if (len <= 1) { // empty or unreadable payload
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    ev->payload_len = (u32)(len - 1); // exclude the NUL terminator

    bpf_dbg_printk("nodejs_manual_span: len=%d", ev->payload_len);

    bpf_ringbuf_submit(ev, get_flags());

    return 0;
}

static __always_inline int handle_fd_correlation(char *buf, const u64 pid_tgid) {
    u32 fd1 = 0;
    u32 fd2 = 0;

    for (u8 i = 0; i < k_max_fd_digits; ++i) {
        fd1 *= 10;
        fd1 += buf[k_fd1_offset + i] - '0';
        fd2 *= 10;
        fd2 += buf[k_fd2_offset + i] - '0';
    }

    bpf_dbg_printk("nodejs_fd_correlation: %s, fd1 = %u, fd2 = %u", buf, fd1, fd2);

    const u64 key = (pid_tgid << 32) | fd2;

    bpf_map_update_elem(&nodejs_fd_map, &key, &fd1, BPF_ANY);

    return 0;
}

SEC("uprobe/node:uv_fs_access")
int BPF_KPROBE(obi_uv_fs_access, void *loop, void *req, const char *path) {
    (void)ctx;
    (void)loop;
    (void)req;

    // the obi nodejs agents (fdextractor.js, spanbridge.js) pass signals to
    // the ebpf layer by invoking uv_fs_access() with a fake path. Three
    // formats are used:
    //
    // 1. fd pair correlation (outgoing -> incoming):
    //    /dev/null/obi/<fd1><fd2>  — each fd is a left-zero-padded 4-digit number
    //
    // 2. async context switch (before-hook fires before each JS callback):
    //    /dev/null/obi-ctx/<fd>    — 4-digit incoming fd for the current async context
    //
    // 3. manual span end (spanbridge.js):
    //    /dev/null/obi-span/<json> — serialized manual span, variable length
    //
    // All paths share the prefix "/dev/null/obi" (13 chars). The characters at
    // positions 13-14 distinguish the formats:
    //   '/'       -> format 1 (fd pair)
    //   '-', 'c'  -> format 2 (context switch, "-ctx/" follows)
    //   '-', 's'  -> format 3 (manual span, "-span/" follows)
    static const char prefix[] = "/dev/null/obi";
    static const u8 prefix_size = sizeof(prefix) - 1;

    // Buffer sized to hold the longest fixed-size path + null terminator.
    // Formats 1 and 2 are exactly 22 characters long; format 3 is read
    // directly from user memory in handle_node_span.
    char buf[] = "/dev/null/obi/00000000";

    if (bpf_probe_read_user(buf, sizeof(buf), path) != 0) {
        return 0;
    }

    if (obi_bpf_memcmp(prefix, buf, prefix_size) != 0) {
        return 0;
    }

    const u64 pid_tgid = bpf_get_current_pid_tgid();

    // Only act on processes we are actually instrumenting. The sentinel path
    // is otherwise trivial for any co-located code to forge (mimicking our
    // injected agent), so gate every handler up front — same class of concern
    // as the Java TLS path.
    if (!valid_pid(pid_tgid)) {
        return 0;
    }

    if (buf[k_delim_offset] == '-') {
        // Manual span: /dev/null/obi-span/<json>
        if (buf[k_variant_offset] == 's') {
            return handle_node_span(path, pid_tgid);
        }
        // Async context switch: /dev/null/obi-ctx/XXXX
        // Fires from the async_hooks 'before' callback in fdextractor.js to
        // refresh traces_ctx_v1 before each JS callback.
        return handle_async_switch(buf, pid_tgid);
    }
    // fd pair correlation: /dev/null/obi/<fd1><fd2>
    return handle_fd_correlation(buf, pid_tgid);
}
