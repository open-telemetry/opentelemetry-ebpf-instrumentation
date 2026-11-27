// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/amqp_defs.h>
#include <common/connection_info.h>
#include <common/event_defs.h>
#include <common/http_types.h>
#include <common/preempt_guard.h>
#include <common/protocol_defs.h>
#include <common/ringbuf.h>
#include <common/scratch_mem.h>
#include <common/trace_helpers.h>
#include <common/trace_parent.h>

#include <generictracer/k_tracer_tailcall.h>
#include <generictracer/protocol_common.h>

#include <generictracer/maps/amqp_streams.h>
#include <generictracer/maps/protocol_cache.h>

#include <logger/bpf_dbg.h>

#include <pid/pid_helpers.h>

enum {
    k_amqp_frames_per_walk = 16,
    k_amqp_max_walks = 16,
    k_amqp_max_messages = 64, // Masked array index requires a power of two.
    // a larger frame size means the walk lost the frame boundaries; RabbitMQ's
    // default frame_max is 128 KiB
    k_amqp_frame_size_max = 1 << 20,
    // return_recvmsg drops reads of this many bytes or fewer
    k_amqp_untraced_read_max = 1,
};

typedef struct amqp_msg_ref {
    u32 off;
    u32 size;
} amqp_msg_ref_t;

// Walk state threaded through the tail calls of one buffer
typedef struct amqp_walk {
    u64 base;
    u64 start_monotime_ns;
    u32 len;
    u32 pos;
    u8 user;
    u8 walks;
    u8 messages;
    u8 resume_after_emit;
    // a header kept from the previous buffer and completed from this one; twice
    // the header size, so the completing read stays in bounds
    unsigned char header[2 * k_amqp_frame_header_len];
    u8 saved_method;
    u8 _pad;
    // a send starts at a frame boundary, so its state lives only for the buffer
    amqp_stream_t send;
    amqp_msg_ref_t msgs[k_amqp_max_messages];
    // The verifier bounds the append offset and read length independently.
    unsigned char method[2 * k_amqp_method_copy_len];
} amqp_walk_t;

SCRATCH_MEM_TYPED(amqp_walk, amqp_walk_t)
SCRATCH_MEM_TYPED(amqp_msg_event, amqp_msg_event_t)

static __always_inline long amqp_read(void *dst, u32 n, const amqp_walk_t *w, u32 off) {
    const void *src = (const void *)(w->base + off);
    if (w->user) {
        return bpf_probe_read_user(dst, n, src);
    }
    return bpf_probe_read_kernel(dst, n, src);
}

static __always_inline u8 amqp_read_u8(const amqp_walk_t *w, u32 off) {
    u8 v = 0;
    amqp_read(&v, sizeof(v), w, off);
    return v;
}

static __always_inline u16 amqp_be16(const unsigned char *p) {
    u16 v;
    __builtin_memcpy(&v, p, sizeof(v));
    return bpf_ntohs(v);
}

static __always_inline u32 amqp_be32(const unsigned char *p) {
    u32 v;
    __builtin_memcpy(&v, p, sizeof(v));
    return bpf_ntohl(v);
}

static __always_inline bool amqp_protocol_header(const unsigned char *h) {
    return h[0] == 'A' && h[1] == 'M' && h[2] == 'Q' && h[3] == 'P' && h[4] == k_amqp_protocol_id &&
           h[5] == k_amqp_protocol_version_major && h[6] == k_amqp_protocol_version_minor &&
           h[7] == k_amqp_protocol_version_revision;
}

static __always_inline bool amqp_frame_type_valid(u8 type) {
    return type == k_amqp_frame_method || type == k_amqp_frame_content_header ||
           type == k_amqp_frame_body || type == k_amqp_frame_heartbeat;
}

static __always_inline bool amqp_basic_method(u16 class_id, u16 method_id) {
    if (class_id != k_amqp_class_basic) {
        return false;
    }

    switch (method_id) {
    case k_amqp_method_publish:
    case k_amqp_method_deliver:
    case k_amqp_method_get_ok:
    case k_amqp_method_ack:
    case k_amqp_method_reject:
    case k_amqp_method_nack:
        return true;
    default:
        return false;
    }
}

// If OBI missed the connection greeting, recognize a Basic method only when
// the buffer also contains the end marker at the offset declared by the frame.
static __always_inline bool amqp_sniff_frame(const unsigned char *data, u32 len) {
    unsigned char hdr[k_amqp_frame_header_len + k_amqp_method_header_len];
    if (len <= sizeof(hdr) || bpf_probe_read(hdr, sizeof(hdr), data) != 0) {
        return false;
    }

    if (hdr[0] != k_amqp_frame_method) {
        return false;
    }

    const u32 size = amqp_be32(hdr + k_amqp_frame_size_off);
    if (size < k_amqp_method_header_len || size >= len - k_amqp_frame_header_len) {
        return false;
    }

    u8 end = 0;
    if (bpf_probe_read(&end, sizeof(end), data + k_amqp_frame_header_len + size) != 0 ||
        end != k_amqp_frame_end) {
        return false;
    }

    const unsigned char *method = hdr + k_amqp_frame_header_len;
    return amqp_basic_method(amqp_be16(method), amqp_be16(method + sizeof(u16)));
}

static __always_inline u8 is_amqp(connection_info_t *conn_info,
                                  const unsigned char *data,
                                  u32 data_len,
                                  enum protocol_type *protocol_type) {
    if (*protocol_type != k_protocol_type_unknown || data_len < k_amqp_protocol_header_len) {
        return 0;
    }

    unsigned char hdr[k_amqp_protocol_header_len];
    if (bpf_probe_read(hdr, sizeof(hdr), data) != 0) {
        return 0;
    }

    // AMQP 1.0 shares the "AMQP" magic and stays with the userspace heuristic
    if (!amqp_protocol_header(hdr) && !amqp_sniff_frame(data, data_len)) {
        return 0;
    }

    *protocol_type = k_protocol_type_amqp;
    bpf_map_update_elem(&protocol_cache, conn_info, protocol_type, BPF_ANY);
    return 1;
}

static __always_inline void amqp_lose_sync(amqp_stream_t *st) {
    __builtin_memset(st, 0, sizeof(*st));
}

static __always_inline amqp_stream_t *amqp_stream_of(const call_protocol_args_t *args,
                                                     amqp_walk_t *w) {
    if (args->direction == TCP_SEND) {
        return &w->send;
    }
    return bpf_map_lookup_elem(&amqp_streams, &args->pid_conn);
}

static __always_inline bool amqp_message_method(const call_protocol_args_t *args,
                                                const unsigned char *m) {
    if (amqp_be16(m) != k_amqp_class_basic) {
        return false;
    }

    const u16 method_id = amqp_be16(m + sizeof(u16));
    if (args->direction == TCP_SEND) {
        return method_id == k_amqp_method_publish;
    }
    return method_id == k_amqp_method_deliver || method_id == k_amqp_method_get_ok;
}

static __always_inline void
amqp_record(const call_protocol_args_t *args, amqp_walk_t *w, u8 type, u32 payload, u32 size) {
    if (type != k_amqp_frame_method || w->messages >= k_amqp_max_messages ||
        size < k_amqp_method_header_len) {
        return;
    }
    unsigned char method[k_amqp_method_header_len];
    if (amqp_read(method, sizeof(method), w, payload) || !amqp_message_method(args, method)) {
        return;
    }

    // Save the method's location in this buffer. The emitter copies its bytes
    // after the walker has found the other message methods in the same buffer.
    amqp_msg_ref_t *ref = &w->msgs[w->messages & (k_amqp_max_messages - 1)];
    ref->off = payload;
    ref->size = size;
    w->messages++;
}

// Every frame has a seven-byte header, a payload and a one-byte end marker.
// Use the size from the header to walk past all frame types, including bodies.
// Only message methods contribute a record for userspace.
static __always_inline bool amqp_payload(const call_protocol_args_t *args,
                                         amqp_walk_t *w,
                                         amqp_stream_t *st,
                                         const unsigned char *hdr,
                                         u32 payload) {
    const u32 size = amqp_be32(hdr + k_amqp_frame_size_off);
    if (!amqp_frame_type_valid(hdr[0]) || size > k_amqp_frame_size_max) {
        bpf_dbg_printk("resetting parser after invalid header: type=%u, size=%u", hdr[0], size);
        amqp_lose_sync(st);
        return false;
    }

    const u32 avail = w->len - payload;
    if (size > avail) {
        // The payload continues in another read. Count the frame end in skip.
        if (args->direction == TCP_RECV && hdr[0] == k_amqp_frame_method &&
            avail < k_amqp_method_copy_len && size >= k_amqp_method_header_len) {
            st->method_target = size < k_amqp_method_copy_len ? size : k_amqp_method_copy_len;
            u32 copy_len = avail;
            bpf_clamp_umax(copy_len, k_amqp_method_copy_len);
            st->method_len = copy_len;
            if (copy_len && amqp_read(st->method, copy_len, w, payload)) {
                st->method_target = 0;
            }
        } else {
            amqp_record(args, w, hdr[0], payload, avail);
        }
        st->skip = size - avail + 1;
        return false;
    }

    w->pos = payload + size;
    if (w->pos == w->len) {
        // py-amqp reads the frame end on its own, too short a read to be traced
        amqp_record(args, w, hdr[0], payload, size);
        st->frame_end_due = 1;
        return false;
    }

    // The expected frame end is inside this buffer. Check it before advancing.
    if (amqp_read_u8(w, w->pos) != k_amqp_frame_end) {
        if (!payload && size <= k_amqp_untraced_read_max) {
            // py-amqp read the header, this payload and the frame end on their own,
            // the last two too short to be traced: the buffer starts the next frame
            w->pos = 0;
            return true;
        }
        bpf_dbg_printk("resetting parser after frame end mismatch: offset=%u", w->pos);
        amqp_lose_sync(st);
        return false;
    }
    amqp_record(args, w, hdr[0], payload, size);
    w->pos++;
    return true;
}

static __always_inline bool
amqp_next_frame(const call_protocol_args_t *args, amqp_walk_t *w, amqp_stream_t *st) {
    const u32 pos = w->pos;
    if (pos >= w->len) {
        return false;
    }

    u32 rest = w->len - pos;
    if (rest <= k_amqp_frame_header_len) {
        // py-amqp reads a frame header on its own; other reads may cut one
        bpf_clamp_umax(rest, k_amqp_frame_header_len);
        amqp_read(st->header, rest, w, pos);
        st->header_len = rest;
        return false;
    }

    unsigned char hdr[k_amqp_frame_header_len];
    amqp_read(hdr, sizeof(hdr), w, pos);
    return amqp_payload(args, w, st, hdr, pos + k_amqp_frame_header_len);
}

static __always_inline bool
amqp_resume_header(const call_protocol_args_t *args, amqp_walk_t *w, amqp_stream_t *st) {
    u32 have = st->header_len;
    bpf_clamp_umax(have, k_amqp_frame_header_len);
    const u32 need = k_amqp_frame_header_len - have;
    u32 take = w->len < need ? w->len : need;
    bpf_clamp_umax(take, k_amqp_frame_header_len);
    __builtin_memcpy(w->header, st->header, k_amqp_frame_header_len);
    if (take && amqp_read(w->header + have, take, w, 0)) {
        amqp_lose_sync(st);
        return false;
    }

    // Keep the accumulated header until a read also contains payload bytes.
    if (w->len <= need) {
        __builtin_memcpy(st->header, w->header, k_amqp_frame_header_len);
        st->header_len = have + take;
        return false;
    }
    st->header_len = 0;
    return amqp_payload(args, w, st, w->header, need);
}

static __always_inline void
amqp_resume_method(const call_protocol_args_t *args, amqp_walk_t *w, amqp_stream_t *st) {
    const u32 have = st->method_len;
    const u32 target = st->method_target;
    if (!target || target > k_amqp_method_copy_len || have >= target) {
        return;
    }

    const u32 need = target - have;
    u32 n = w->len < need ? w->len : need;
    bpf_clamp_umax(n, k_amqp_method_copy_len);
    __builtin_memcpy(w->method, st->method, sizeof(st->method));
    if (amqp_read(w->method + have, n, w, 0)) {
        st->method_target = 0;
        return;
    }
    if (n < need) {
        __builtin_memcpy(st->method, w->method, sizeof(st->method));
        st->method_len = have + n;
        return;
    }

    st->method_target = 0;
    if (amqp_message_method(args, w->method)) {
        // A method resumed from the previous read is always the first record.
        w->saved_method = 1;
        w->msgs[0].size = target;
        w->messages = 1;
    }
}

static __always_inline bool
amqp_resume(const call_protocol_args_t *args, amqp_walk_t *w, amqp_stream_t *st) {
    if (st->header_len) {
        return amqp_resume_header(args, w, st);
    }

    // The previous read ended inside a payload. Skip its remaining bytes and
    // end marker before treating any bytes in this read as a new header.
    if (st->skip) {
        if (st->skip > w->len) {
            amqp_resume_method(args, w, st);
            st->skip -= w->len;
            if (st->skip == sizeof(u8)) {
                // only the frame end is left, which py-amqp reads untraced
                st->skip = 0;
                st->frame_end_due = 1;
            }
            return false;
        }
        w->pos = st->skip;
        st->skip = 0;
        if (amqp_read_u8(w, w->pos - 1) != k_amqp_frame_end) {
            bpf_dbg_printk("resetting parser after frame end mismatch: offset=%u", w->pos - 1);
            amqp_lose_sync(st);
            return false;
        }
        amqp_resume_method(args, w, st);
        return true;
    }

    // A separate one-byte read of the frame end can go untraced. Consume the
    // marker if it is still here; otherwise the next frame starts at byte zero.
    if (st->frame_end_due) {
        st->frame_end_due = 0;
        if (amqp_read_u8(w, 0) == k_amqp_frame_end) {
            w->pos = 1;
        }
    }
    return true;
}

static __always_inline void amqp_emit_recorded(void *ctx, const amqp_walk_t *w) {
    if (w->messages) {
        preempt_guarded_tail_call_static(ctx, &jump_table, k_tail_protocol_amqp_emit);
    }
}

static __always_inline void
amqp_walk(void *ctx, const call_protocol_args_t *args, amqp_walk_t *w, amqp_stream_t *st) {
    for (u8 i = 0; i < k_amqp_frames_per_walk; i++) {
        if (!amqp_next_frame(args, w, st)) {
            amqp_emit_recorded(ctx, w);
            return;
        }
    }

    // Each invocation walks a bounded batch of frames. The continuation picks
    // up at w->pos with the message references collected so far.
    if (w->walks < k_amqp_max_walks) {
        w->walks++;
        // Leave room for one message per frame in the next walk.
        if (w->messages > k_amqp_max_messages - k_amqp_frames_per_walk) {
            w->resume_after_emit = 1;
            amqp_emit_recorded(ctx, w);
            w->resume_after_emit = 0;
        } else {
            preempt_guarded_tail_call_static(ctx, &jump_table, k_tail_protocol_amqp_continue);
        }
        bpf_dbg_printk("failed to continue frame walk: offset=%u", w->pos);
    }
    amqp_lose_sync(st);
    amqp_emit_recorded(ctx, w);
}

// The protocol dispatcher enters here with one buffer from an AMQP connection.
SEC("kprobe/amqp")
int GUARDED_PROG(obi_protocol_amqp, void *, ctx) {
    call_protocol_args_t *args = protocol_args();
    amqp_walk_t *w = amqp_walk_mem();
    if (!args || !w) {
        return 0;
    }

    // Message references and method bytes are filled before use.
    __builtin_memset(w, 0, __builtin_offsetof(amqp_walk_t, msgs));
    w->start_monotime_ns = bpf_ktime_get_ns();
    // a receive longer than the kernel copy is walked in the application's buffer
    if (args->user_buf && args->user_len > (u32)args->bytes_len) {
        w->base = args->user_buf;
        w->len = args->user_len;
        w->user = 1;
    } else {
        w->base = args->u_buf;
        w->len = (u32)args->bytes_len;
        w->user = args->ssl;
    }

    if (w->len == k_amqp_protocol_header_len) {
        unsigned char hdr[k_amqp_protocol_header_len];
        amqp_read(hdr, sizeof(hdr), w, 0);
        if (amqp_protocol_header(hdr)) {
            // the connection starts: drop what a previous one on this address left
            bpf_map_delete_elem(&amqp_streams, &args->pid_conn);
            return 0;
        }
    }

    // A socket read can end anywhere in a frame. Keep the receive position
    // for this connection so the next read can finish that frame.
    amqp_stream_t *st = &w->send;
    if (args->direction == TCP_RECV) {
        st = bpf_map_lookup_elem(&amqp_streams, &args->pid_conn);
        if (!st) {
            bpf_map_update_elem(&amqp_streams, &args->pid_conn, &w->send, BPF_NOEXIST);
            st = bpf_map_lookup_elem(&amqp_streams, &args->pid_conn);
        }
        if (!st) {
            return 0;
        }
    }

    if (amqp_resume(args, w, st)) {
        preempt_guarded_tail_call_static(ctx, &jump_table, k_tail_protocol_amqp_continue);
        amqp_lose_sync(st);
    }
    amqp_emit_recorded(ctx, w);
    return 0;
}

SEC("kprobe/amqp")
int GUARDED_PROG(obi_protocol_amqp_continue, void *, ctx) {
    call_protocol_args_t *args = protocol_args();
    amqp_walk_t *w = amqp_walk_mem();
    if (!args || !w) {
        return 0;
    }

    amqp_stream_t *st = amqp_stream_of(args, w);
    if (st) {
        amqp_walk(ctx, args, w, st);
    }
    return 0;
}

SEC("kprobe/amqp")
int GUARDED_PROG(obi_protocol_amqp_emit, void *, ctx) {
    const call_protocol_args_t *args = protocol_args();
    amqp_walk_t *w = amqp_walk_mem();
    amqp_msg_event_t *ev = amqp_msg_event_mem();
    if (!args || !w || !ev) {
        return 0;
    }

    bpf_memset(ev, 0, sizeof(*ev));
    ev->type = k_event_type_amqp_message;
    ev->start_monotime_ns = w->start_monotime_ns;
    ev->conn_info = args->pid_conn.conn;
    fixup_connection_info(&ev->conn_info, 1, args->orig_dport);
    task_pid(&ev->pid);

    // the messages of one buffer share the request the thread serves
    tp_info_t parent = {.ts = bpf_ktime_get_ns()};
    const u8 parent_status =
        find_trace_for_client_request(&args->pid_conn, args->orig_dport, args->lw_thread, &parent);

    // One buffer can hold several publishes or deliveries. Send one event to
    // userspace for each recorded method.
    for (u8 i = 0; i < k_amqp_max_messages; i++) {
        if (i >= w->messages) {
            break;
        }

        const amqp_msg_ref_t *ref = &w->msgs[i];
        u32 len = ref->size;
        bpf_clamp_umax(len, k_amqp_method_copy_len);
        if (i == 0 && w->saved_method) {
            bpf_probe_read_kernel(ev->method, len, w->method);
        } else {
            amqp_read(ev->method, len, w, ref->off);
        }
        ev->method_len = len;

        ev->parent_status = parent_status;
        ev->tp = parent;
        if (parent_status) {
            urand_bytes(ev->tp.span_id, SPAN_ID_SIZE_BYTES);
        } else {
            init_new_trace_for_pid(&ev->tp, &ev->pid);
        }

        ev->end_monotime_ns = bpf_ktime_get_ns();
        events_ringbuf_output(ev, sizeof(*ev));
    }
    if (w->resume_after_emit) {
        w->saved_method = 0;
        w->messages = 0;
        w->resume_after_emit = 0;
        preempt_guarded_tail_call_static(ctx, &jump_table, k_tail_protocol_amqp_continue);
        amqp_stream_t *st = amqp_stream_of(args, w);
        if (st) {
            amqp_lose_sync(st);
        }
        bpf_dbg_printk("failed to continue frame walk: offset=%u", w->pos);
    }
    return 0;
}
