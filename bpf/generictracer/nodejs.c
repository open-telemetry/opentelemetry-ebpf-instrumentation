// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/common.h>
#include <common/event_defs.h>
#include <common/preempt_guard.h>
#include <common/ringbuf.h>
#include <common/scratch_mem.h>
#include <common/strings.h>
#include <common/trace_helpers.h>
#include <common/trace_util.h>
#include <common/tracing.h>

#include <generictracer/types/nodejs.h>

#include <logger/bpf_dbg.h>

#include <maps/fd_to_connection.h>
#include <maps/node_manual_ctx_shadow.h>
#include <maps/nodejs_fd_map.h>

#include <pid/pid.h>

#include <shared/obi_ctx.h>

volatile const u64 nodejs_runtime_metrics_enabled = 0;

struct nodejs_eventloop_event _nodejs_eventloop_event = {};

enum {
    k_delim_offset = 13,
    k_variant_offset = 14,
    k_fd1_offset = 14,
    k_fd2_offset = 18,
    k_ctx_fd_offset = 18,
    k_max_fd_digits = 4,
    // strlen("/dev/null/obi-span/") — the JSON span payload starts here
    k_span_payload_offset = 19,
    // strlen("/dev/null/obi-mspan/") — the manual-span override payload starts here
    k_mspan_payload_offset = 20,
};

enum {
    k_rt_kind_offset = 14,    // 'r' of "-rt/", 'c' of "-ctx/"
    k_rt_payload_offset = 17, // first hex char after "/dev/null/obi-rt/"
    k_rt_field_hex_len = 16,  // one u64 as fixed-width lowercase hex
    k_rt_field_count = 10,
    // payload + the byte past it, which must be the path's NUL terminator
    k_rt_payload_read_len = k_rt_field_count * k_rt_field_hex_len + 1,
};

enum {
    // record kind chars at k_v8_kind_offset, emitted by fdextractor.js
    k_v8_record_gc = 'g',
    k_v8_record_heap_space = 'h',
    k_v8_kind_offset = 17,    // record kind char after "/dev/null/obi-v8/"
    k_v8_payload_offset = 18, // record payload starts here
    // g payload: 1 kind char + 16 hex duration chars (+ NUL when read)
    k_v8_gc_payload_len = 1 + k_rt_field_hex_len,
    k_v8_heap_num_fields = 4,
    k_v8_heap_numbers_len = k_v8_heap_num_fields * k_rt_field_hex_len,
    // h payload upper bound: numbers + name + NUL
    k_v8_heap_payload_read_len = k_v8_heap_numbers_len + k_nodejs_heap_space_name_max + 1,
};

SCRATCH_MEM_SIZED(nodejs_rt_payload, k_rt_payload_read_len)
SCRATCH_MEM_SIZED(nodejs_v8_payload, k_v8_heap_payload_read_len)

static __always_inline int nodejs_parse_hex_u64(const unsigned char *buf, u64 *out) {
    u64 v = 0;
    for (u8 i = 0; i < k_rt_field_hex_len; ++i) {
        const unsigned char c = buf[i];
        u8 digit;
        if (c >= '0' && c <= '9') {
            digit = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            digit = c - 'a' + 10;
        } else {
            return -1;
        }
        v = (v << 4) | digit;
    }
    *out = v;
    return 0;
}

// The v8 record parsers are pure over (payload, len) — len is what
// bpf_probe_read_user_str returned, including the terminating NUL — and are
// unit-tested in bpf/tests/bpf_nodejs_v8.c; keep both copies in sync.

static __always_inline int
nodejs_v8_parse_gc(const unsigned char *payload, u64 len, u8 *kind, u64 *duration_ns) {
    // len counts the NUL: the payload must be exactly kind + duration
    if (len != k_v8_gc_payload_len + 1) {
        return -1;
    }
    const unsigned char c = payload[0];
    if (c >= '0' && c <= '9') {
        *kind = c - '0';
    } else if (c >= 'a' && c <= 'f') {
        *kind = c - 'a' + 10;
    } else {
        return -1;
    }
    return nodejs_parse_hex_u64(payload + 1, duration_ns);
}

static __always_inline int
nodejs_v8_parse_heap(const unsigned char *payload, u64 len, u64 *vals, u8 *name_len) {
    // len counts the NUL: at least one name byte, at most the name cap
    if (len < k_v8_heap_numbers_len + 1 + 1 || len > k_v8_heap_payload_read_len) {
        return -1;
    }
    for (u8 f = 0; f < k_v8_heap_num_fields; ++f) {
        if (nodejs_parse_hex_u64(payload + (u32)f * k_rt_field_hex_len, &vals[f]) != 0) {
            return -1;
        }
    }
    *name_len = (u8)(len - 1 - k_v8_heap_numbers_len);
    return 0;
}

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
    } else {
        const tp_info_pid_t *tp = trace_info_for_connection(conn, TRACE_TYPE_SERVER);
        if (tp && tp->valid) {
            obi_ctx__set(pid_tgid, &tp->tp);
        } else {
            obi_ctx__del(pid_tgid);
        }
    }

    // Each callback re-derives the base context, so drop any stale manual-span
    // override shadow left over from the previous callback. The bridge's own
    // async_hooks 'before' hook re-applies the active manual span's override
    // right after this one runs (the bridge hook is registered after
    // fdextractor's, so it fires second per callback).
    bpf_map_delete_elem(&node_manual_ctx_shadow, &pid_tgid);

    return 0;
}

// Manual-span context override emitted by the span bridge (spanbridge.js):
//     /dev/null/obi-mspan/<32-hex trace_id><16-hex span_id>   -> override
//     /dev/null/obi-mspan/-                                   -> pop
//
// "Override" means: the innermost active manual span is now this one; make the
// thread's traces_ctx_v1 entry point at it so OBI's automatic client spans nest
// under the manual span instead of the server span. Both the exported client
// span and the injected traceparent read it, through the two call sites of
// nodejs_manual_parent_span_id in trace_parent.h. We keep the request (base)
// trace id and only swap in the manual span's span id. The pre-override entry is
// saved once per sync block in node_manual_ctx_shadow; "pop" restores it. This
// mirrors go_sdk.c's update_tp_parent_go / prev_tp semantics.
//
// The log enricher (logenricher.c) also reads traces_ctx_v1, so while a manual
// span is active, log lines correlate to it rather than to the server span.
static __always_inline int handle_manual_ctx(const char *path, const u64 pid_tgid) {
    // 48 hex chars + NUL for an override, or the single-char '-' pop marker.
    unsigned char hexbuf[2 * (TRACE_ID_SIZE_BYTES + SPAN_ID_SIZE_BYTES) + 1] = {};
    const long n = bpf_probe_read_user_str(hexbuf, sizeof(hexbuf), path + k_mspan_payload_offset);
    if (n <= 0) {
        return 0;
    }

    // Pop: the innermost manual span ended in this sync block. Restore the base
    // context if there was a real one, otherwise clear the (bridge-only) entry.
    if (hexbuf[0] == '-') {
        obi_ctx_info_t *shadow = bpf_map_lookup_elem(&node_manual_ctx_shadow, &pid_tgid);
        if (shadow) {
            if (valid_trace(shadow->trace_id)) {
                bpf_map_update_elem(&traces_ctx_v1, &pid_tgid, shadow, BPF_ANY);
            } else {
                obi_ctx__del(pid_tgid);
            }
            bpf_map_delete_elem(&node_manual_ctx_shadow, &pid_tgid);
        }
        bpf_dbg_printk("nodejs_mspan pop: pid_tgid = %llx", pid_tgid);
        return 0;
    }

    // Override needs exactly 48 hex chars (49 incl. the NUL terminator).
    if (n < (long)sizeof(hexbuf)) {
        return 0;
    }

    obi_ctx_info_t sentinel = {};
    decode_hex(sentinel.trace_id, hexbuf, 2 * TRACE_ID_SIZE_BYTES);
    decode_hex(sentinel.span_id, hexbuf + 2 * TRACE_ID_SIZE_BYTES, 2 * SPAN_ID_SIZE_BYTES);

    // Save the pre-override base on the first override of this sync block. A
    // missing live entry is recorded as an all-zero "no base existed" marker so
    // pop / span-end can tell it apart from a real server context.
    obi_ctx_info_t *shadow = bpf_map_lookup_elem(&node_manual_ctx_shadow, &pid_tgid);
    if (!shadow) {
        obi_ctx_info_t base = {};
        const obi_ctx_info_t *live = obi_ctx__get(pid_tgid);
        if (live) {
            bpf_memcpy(&base, live, sizeof(base));
        }
        bpf_map_update_elem(&node_manual_ctx_shadow, &pid_tgid, &base, BPF_ANY);
        shadow = bpf_map_lookup_elem(&node_manual_ctx_shadow, &pid_tgid);
        if (!shadow) {
            return 0;
        }
    }

    obi_ctx_info_t newlive = {};
    if (valid_trace(shadow->trace_id)) {
        // Keep the request trace id; adopt the manual span's span id.
        bpf_memcpy(newlive.trace_id, shadow->trace_id, TRACE_ID_SIZE_BYTES);
    } else {
        // No request in flight: the manual span is its own (bridge) trace.
        bpf_memcpy(newlive.trace_id, sentinel.trace_id, TRACE_ID_SIZE_BYTES);
    }
    bpf_memcpy(newlive.span_id, sentinel.span_id, SPAN_ID_SIZE_BYTES);
    bpf_map_update_elem(&traces_ctx_v1, &pid_tgid, &newlive, BPF_ANY);

    bpf_dbg_printk("nodejs_mspan override: pid_tgid = %llx", pid_tgid);

    return 0;
}

// Manual span emitted by the injected span bridge (spanbridge.js):
//     /dev/null/obi-span/<json>
// The JSON document (name, ids, duration, attributes...) is copied verbatim
// into a node_span_event_t; user space parses it (ReadNodeSpanEventIntoSpan).
// We stamp the event with bpf_ktime_get_ns() (the sentinel fires inside
// span.end(), so this is the span end time in the same monotonic domain the
// rest of the pipeline uses) and with the current request trace context so the
// span can be parented under OBI's automatic server span.
//
// Parent context: prefer the saved base in node_manual_ctx_shadow over the live
// traces_ctx_v1 entry. When a manual span is active, the live entry holds this
// span's OWN override (see handle_manual_ctx), so a root manual span would
// otherwise become its own parent; the shadow holds the pre-override base (the
// server context, or a no-base marker meaning the span is outside any request).
// Nested manual spans still carry an in-bridge parent (psid) that user space
// prefers over this context anyway.
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

    const obi_ctx_info_t *shadow = bpf_map_lookup_elem(&node_manual_ctx_shadow, &pid_tgid);
    const obi_ctx_info_t *octx;
    if (shadow) {
        // A manual span is active: the base (server) context, if any, lives in
        // the shadow — the live entry is this span's own override.
        octx = valid_trace(shadow->trace_id) ? shadow : NULL;
    } else {
        octx = obi_ctx__get(pid_tgid);
    }

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

// Explicit "no request context" signal emitted by fdextractor.js when an async
// callback fires outside any tracked request (e.g. a background timer). Drop the
// stale request context so a manual span ending in that callback
// (handle_node_span) is not mis-parented into the previous request's trace.
static __always_inline int handle_ctx_clear(const u64 pid_tgid) {
    bpf_dbg_printk("nodejs_ctx_clear: pid_tgid = %llx", pid_tgid);
    obi_ctx__del(pid_tgid);
    // As with the '-ctx' refresh: this callback re-derives the base (here, no
    // request), so any stale override shadow must go. The bridge re-applies an
    // override right after if a manual span is active in this async context.
    bpf_map_delete_elem(&node_manual_ctx_shadow, &pid_tgid);
    return 0;
}

// Decodes the fixed-width runtime-metrics payload emitted by fdextractor.js:
// /dev/null/obi-rt/<10 x 16 lowercase hex chars> (field order and semantics
// in types/nodejs.h). Any non-hex character aborts the parse — a short or
// malformed path never produces an event.
static __always_inline int handle_runtime_metrics(const char *path, const u64 pid_tgid) {
    if (!nodejs_runtime_metrics_enabled) {
        return 0;
    }

    // Read one byte past the payload and require the path to end exactly
    // there. The pid fields come from the kernel, so a foreign process
    // calling fs.access() on a path that happens to share the obi-rt prefix
    // could otherwise get residual heap bytes decoded into a plausible but
    // wrong event attributed to itself; the exact-length check turns that
    // into a dropped event.
    unsigned char *payload = nodejs_rt_payload_mem();
    if (!payload) {
        return 0;
    }
    if (bpf_probe_read_user(payload, k_rt_payload_read_len, path + k_rt_payload_offset) != 0) {
        return 0;
    }
    if (payload[k_rt_payload_read_len - 1] != '\0') {
        return 0;
    }

    u64 vals[k_rt_field_count];
    for (u8 f = 0; f < k_rt_field_count; ++f) {
        if (nodejs_parse_hex_u64(payload + (u32)f * k_rt_field_hex_len, &vals[f]) != 0) {
            return 0;
        }
    }

    struct nodejs_eventloop_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    bpf_memset(e, 0, sizeof(*e));
    e->type = EVENT_NODEJS_EVENTLOOP;
    e->timestamp = bpf_ktime_get_ns();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int ns_pid = 0;
    int ns_ppid = 0;
    u32 pid_ns_id = 0;
    ns_pid_ppid(task, &ns_pid, &ns_ppid, &pid_ns_id);

    e->global_pid = pid_from_pid_tgid(pid_tgid);
    e->global_tid = tid_from_pid_tgid(pid_tgid);
    e->ns_pid = (u32)ns_pid;
    e->ns_tid = get_task_tid();
    e->pid_ns_id = pid_ns_id;

    e->elu_idle_ns = vals[0];
    e->elu_active_ns = vals[1];
    e->delay_min_ns = vals[2];
    e->delay_max_ns = vals[3];
    e->delay_mean_ns = vals[4];
    e->delay_stddev_ns = vals[5];
    e->delay_p50_ns = vals[6];
    e->delay_p90_ns = vals[7];
    e->delay_p99_ns = vals[8];
    e->delay_count = vals[9];

    bpf_dbg_printk("nodejs_runtime_metrics: pid_tgid=%llx idle=%llu active=%llu",
                   pid_tgid,
                   e->elu_idle_ns,
                   e->elu_active_ns);

    bpf_ringbuf_submit(e, get_flags());
    return 0;
}

static __always_inline void nodejs_fill_event_pids(const u64 pid_tgid,
                                                   u32 *global_pid,
                                                   u32 *global_tid,
                                                   u32 *ns_pid_out,
                                                   u32 *ns_tid,
                                                   u32 *pid_ns_id_out) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int ns_pid = 0;
    int ns_ppid = 0;
    u32 pid_ns_id = 0;
    ns_pid_ppid(task, &ns_pid, &ns_ppid, &pid_ns_id);

    *global_pid = pid_from_pid_tgid(pid_tgid);
    *global_tid = tid_from_pid_tgid(pid_tgid);
    *ns_pid_out = (u32)ns_pid;
    *ns_tid = get_task_tid();
    *pid_ns_id_out = pid_ns_id;
}

// Decodes the v8js records emitted by fdextractor.js under /dev/null/obi-v8/
// (record layouts in types/nodejs.h; parsers unit-tested in
// bpf/tests/bpf_nodejs_v8.c). The payload is variable-length (the heap record
// carries the space name), so it is read with bpf_probe_read_user_str — a
// fixed-size read past the path's NUL could fault at a page boundary and drop
// valid events.
static __always_inline int handle_v8_metrics(const char *path, const u64 pid_tgid) {
    if (!nodejs_runtime_metrics_enabled) {
        return 0;
    }

    unsigned char kind_char = 0;
    if (bpf_probe_read_user(&kind_char, sizeof(kind_char), path + k_v8_kind_offset) != 0) {
        return 0;
    }

    unsigned char *payload = nodejs_v8_payload_mem();
    if (!payload) {
        return 0;
    }
    const long len =
        bpf_probe_read_user_str(payload, k_v8_heap_payload_read_len, path + k_v8_payload_offset);
    if (len <= 0) {
        return 0;
    }

    if (kind_char == k_v8_record_gc) {
        u8 kind = 0;
        u64 duration_ns = 0;
        if (nodejs_v8_parse_gc(payload, (u64)len, &kind, &duration_ns) != 0) {
            return 0;
        }

        struct nodejs_gc_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) {
            return 0;
        }
        bpf_memset(e, 0, sizeof(*e));
        e->type = EVENT_NODEJS_GC;
        e->timestamp = bpf_ktime_get_ns();
        nodejs_fill_event_pids(
            pid_tgid, &e->global_pid, &e->global_tid, &e->ns_pid, &e->ns_tid, &e->pid_ns_id);
        e->kind = kind;
        e->duration_ns = duration_ns;

        bpf_dbg_printk(
            "nodejs_v8_gc: pid_tgid=%llx kind=%u duration=%llu", pid_tgid, e->kind, e->duration_ns);
        bpf_ringbuf_submit(e, get_flags());
        return 0;
    }

    if (kind_char == k_v8_record_heap_space) {
        u64 vals[k_v8_heap_num_fields];
        u8 name_len = 0;
        if (nodejs_v8_parse_heap(payload, (u64)len, vals, &name_len) != 0) {
            return 0;
        }

        struct nodejs_heap_space_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) {
            return 0;
        }
        bpf_memset(e, 0, sizeof(*e));
        e->type = EVENT_NODEJS_HEAP_SPACE;
        e->timestamp = bpf_ktime_get_ns();
        nodejs_fill_event_pids(
            pid_tgid, &e->global_pid, &e->global_tid, &e->ns_pid, &e->ns_tid, &e->pid_ns_id);
        e->name_len = name_len;
        e->space_size = vals[0];
        e->space_used_size = vals[1];
        e->space_available_size = vals[2];
        e->physical_space_size = vals[3];
        for (u8 i = 0; i < k_nodejs_heap_space_name_max; ++i) {
            if (i >= name_len) {
                break;
            }
            e->space_name[i] = payload[k_v8_heap_numbers_len + i];
        }

        bpf_dbg_printk("nodejs_v8_heap: pid_tgid=%llx used=%llu name_len=%u",
                       pid_tgid,
                       e->space_used_size,
                       e->name_len);
        bpf_ringbuf_submit(e, get_flags());
        return 0;
    }

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
int BPF_KPROBE_GUARDED(obi_uv_fs_access, void *loop, void *req, const char *path) {
    (void)ctx;
    (void)loop;
    (void)req;

    // the obi nodejs agents (fdextractor.js, spanbridge.js) pass signals to
    // the ebpf layer by invoking uv_fs_access() with a fake path. Six
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
    // 4. no request context (before-hook, callback outside any request):
    //    /dev/null/obi-noreqctx    — clears the stale traces_ctx_v1 entry
    //
    // 5. runtime metrics (1s sampling interval in the agent):
    //    /dev/null/obi-rt/<10 x 16 hex chars> — eventloop metrics payload
    //
    // 6. v8js metrics (gc cycles and heap-space samples):
    //    /dev/null/obi-v8/<'g'|'h'><payload> — record layouts in types/nodejs.h
    //
    // 7. manual-span context override / pop (spanbridge.js):
    //    /dev/null/obi-mspan/<48-hex> — active manual span (trace_id+span_id)
    //    /dev/null/obi-mspan/-        — no manual span active anymore
    //
    // All paths share the prefix "/dev/null/obi" (13 chars). The characters at
    // positions 13-14 distinguish the formats:
    //   '/'       -> format 1 (fd pair)
    //   '-', 'c'  -> format 2 (context switch, "-ctx/" follows)
    //   '-', 's'  -> format 3 (manual span, "-span/" follows)
    //   '-', 'n'  -> format 4 (no request context, "-noreqctx")
    //   '-', 'r'  -> format 5 (runtime metrics, "-rt/" follows)
    //   '-', 'v'  -> format 6 (v8js metrics, "-v8/" follows)
    //   '-', 'm'  -> format 7 (manual-span override, "-mspan/" follows)
    static const char prefix[] = "/dev/null/obi";
    static const u8 prefix_size = sizeof(prefix) - 1;

    // Buffer sized to hold the longest fixed-size path + null terminator.
    // Formats 1 and 2 are exactly 22 characters long; formats 3 and 5 to 7 are
    // longer and are re-read from the original user pointer in their handlers
    // (handle_node_span, handle_runtime_metrics, handle_v8_metrics,
    // handle_manual_ctx).
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
        // Manual-span context override / pop: /dev/null/obi-mspan/...
        if (buf[k_variant_offset] == 'm') {
            return handle_manual_ctx(path, pid_tgid);
        }
        // No request context: /dev/null/obi-noreqctx
        // Fires from the async_hooks 'before' callback in fdextractor.js when a
        // callback runs outside any request; clears the stale traces_ctx_v1 entry.
        if (buf[k_variant_offset] == 'n') {
            return handle_ctx_clear(pid_tgid);
        }
        // Runtime metrics: /dev/null/obi-rt/<payload> — needs the original user
        // pointer because the payload extends past the 23-byte prefix buffer.
        if (buf[k_variant_offset] == 'r') {
            return handle_runtime_metrics(path, pid_tgid);
        }
        // v8js metrics: /dev/null/obi-v8/<'g'|'h'><payload> — same re-read
        // from the original user pointer as the runtime metrics.
        if (buf[k_variant_offset] == 'v') {
            return handle_v8_metrics(path, pid_tgid);
        }
        // Async context switch: /dev/null/obi-ctx/XXXX
        // Fires from the async_hooks 'before' callback in fdextractor.js to
        // refresh traces_ctx_v1 before each JS callback.
        return handle_async_switch(buf, pid_tgid);
    }
    // fd pair correlation: /dev/null/obi/<fd1><fd2>
    return handle_fd_correlation(buf, pid_tgid);
}
