// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

// HTTP/2 HPACK traceparent injection chain for socktracer's client egress.
// Ported from tpinjector's detect/find/validate/create/write chain, reusing the
// shared HPACK byte-logic (common/h2_hpack.h) and frame parser (common/h2_parse.h)
// but substituting socktracer's primitives (init_tp/init_span_id/tp_buf_mem/sk_data,
// the obi_egress_progs jump table and k_tail_egress_h2_* slots). Included by egress.c
// AFTER those statics are defined.

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_builtins.h>

#include <common/go_grpc_client_conn.h>
#include <common/h2_hpack.h>
#include <common/h2_parse.h>

#include <logger/bpf_dbg.h>

// Resume detection at next_pos to process the next HEADERS frame in this packet.
// Targets the detect program (not obi_egress_http2) so emit_http2_buffer runs once.
static __always_inline void
h2_resume_after(struct sk_msg_md *msg, tailcall_ctx *t_ctx, u32 next_pos) {
    t_ctx->h2_scan_pos = next_pos;
    t_ctx->h2_frames++;
    bpf_tail_call_static(msg, &obi_egress_progs, k_tail_egress_h2_detect);
}

// HTTP/2 needs the stream id in the outgoing_trace_map key (multiplexed
// connections); socktracer's set_trace keys by connection only.
static __always_inline void h2_set_outgoing(const egress_key_t *e_key, tp_info_pid_t *tp_p) {
    bpf_map_update_elem(&outgoing_trace_map, e_key, tp_p, BPF_ANY);
}

// Scan up to k_h2_max_frame_scan frames for HEADERS+END_HEADERS, skipping the
// preface (gRPC may send it inline) and non-HEADERS frames (e.g. SETTINGS).
static __always_inline int obi_egress_h2_detect_step(struct sk_msg_md *msg, tailcall_ctx *t_ctx) {
    if (t_ctx->h2_frames >= k_h2_max_frames_per_packet) {
        return SK_PASS;
    }

    // Read msg->size once: repeated reads confuse the sk_msg verifier.
    const u32 msg_size = msg->size;
    u32 pos = t_ctx->h2_scan_pos;

    if (pos == 0 && msg_size >= k_h2_preface_check_len) {
        if (bpf_msg_pull_data(msg, 0, k_h2_preface_check_len, 0) == 0) {
            if (is_http2_preface(msg->data, msg->data_end)) {
                if (msg_size >= k_h2_preface_len + k_h2_frame_header_len) {
                    pos = k_h2_preface_len;
                } else {
                    return SK_PASS;
                }
            }
        }
    }

    if (msg_size < k_h2_frame_header_len || pos >= msg_size) {
        return SK_PASS;
    }

    for (u8 i = 0; i < k_h2_max_frame_scan; i++) {
        h2_frame_info_t f;
        if (!parse_h2_frame_at(msg, pos, msg_size, &f)) {
            return SK_PASS;
        }
        if (f.is_headers_end) {
            t_ctx->e_key.stream_id = f.stream_id;
            t_ctx->h2_frame_offset = pos;
            t_ctx->h2_payload_len = f.payload_len;
            t_ctx->h2_hpack_offset = f.hpack_offset_in_msg;
            t_ctx->h2_hpack_len = f.hpack_len;

            // Already injected (Go/SSL uprobe seeded it, or a prior pass) — skip.
            tp_info_pid_t *existing = get_tp_info_pid(&t_ctx->e_key);
            if (existing && existing->valid && existing->written) {
                h2_resume_after(msg, t_ctx, pos + k_h2_frame_header_len + f.payload_len);
                return SK_PASS;
            }

            bpf_tail_call_static(msg, &obi_egress_progs, k_tail_egress_h2_find_existing_tp);
            return SK_PASS;
        }

        pos += k_h2_frame_header_len + f.payload_len;
    }

    return SK_PASS;
}

static __always_inline int obi_egress_h2_find_existing_step(struct sk_msg_md *msg,
                                                            tailcall_ctx *t_ctx) {
    t_ctx->h2_tp_candidate_pos =
        find_first_h2_tp_candidate(msg, t_ctx->h2_hpack_offset, t_ctx->h2_hpack_len);
    bpf_tail_call_static(msg, &obi_egress_progs, k_tail_egress_h2_validate_tp);
    return SK_PASS;
}

// Walk with a loop counter — a pkt pointer offset by a stack-loaded scalar loses
// its verified range, so we re-walk to the candidate index.
static __always_inline int obi_egress_h2_validate_step(struct sk_msg_md *msg, tailcall_ctx *t_ctx) {
    const u32 target = t_ctx->h2_tp_candidate_pos;
    if (target >= k_h2_max_hpack_scan) {
        bpf_tail_call_static(msg, &obi_egress_progs, k_tail_egress_h2_create_tp);
        return SK_PASS;
    }

    tp_info_pid_t *tp_p = tp_buf_mem();
    if (!tp_p) {
        return SK_PASS;
    }

    const u32 hpack_start = t_ctx->h2_hpack_offset;
    const u32 hpack_len = t_ctx->h2_hpack_len;
    if (!pull_hpack_window(msg, hpack_start, hpack_len)) {
        bpf_tail_call_static(msg, &obi_egress_progs, k_tail_egress_h2_create_tp);
        return SK_PASS;
    }
    const unsigned char *data = msg->data;
    const unsigned char *end = msg->data_end;
    if (!data) {
        bpf_tail_call_static(msg, &obi_egress_progs, k_tail_egress_h2_create_tp);
        return SK_PASS;
    }

    u32 off = 0;
    for (u32 i = 0; i < k_h2_max_hpack_scan; i++) {
        if (i + k_h2_tp_hpack_huffman_size > hpack_len) {
            break;
        }
        const unsigned char *p = data + i;
        if ((void *)(p + k_h2_tp_hpack_huffman_size) > (void *)end) {
            break;
        }
        if (i > target) {
            break;
        }
        if (i != target) {
            continue;
        }
        const u8 nlb = p[1];
        if (nlb == k_hpack_tp_name_len) {
            off = validate_h2_tp_plain(p, end, &tp_p->tp);
        } else if (nlb == (k_hpack_tp_name_huffman_len | 0x80)) {
            off = validate_h2_tp_huffman(p, end, &tp_p->tp);
        }
        break;
    }

    if (off) {
        struct socket_data *sk_data = bpf_map_lookup_elem(&sk_data_map, &t_ctx->sock_cookie);
        if (!sk_data) {
            return SK_PASS;
        }
        // init_span_id reparents and, if this is a proxy-forwarded header, mints a
        // new span id and rewrites it on the wire at the HPACK value's span-id slot.
        const u32 span_id_offset = hpack_start + target + off;
        if (bpf_msg_pull_data(msg, span_id_offset, span_id_offset + SPAN_ID_CHAR_LEN, 0) == 0) {
            unsigned char *d = msg->data;
            const unsigned char *e = msg->data_end;
            if (d && (void *)d + SPAN_ID_CHAR_LEN <= (void *)e) {
                init_span_id(sk_data, &tp_p->tp, d);
            }
        }
        tp_p->tp.ts = bpf_ktime_get_ns();
        tp_p->valid = 1;
        tp_p->written = 1;
        tp_p->pid = t_ctx->p_conn.pid;
        tp_p->req_type = EVENT_HTTP_CLIENT;
        h2_set_outgoing(&t_ctx->e_key, tp_p);
        schedule_write_tcp_option(msg, tp_p);
        h2_resume_after(
            msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
        return SK_PASS;
    }

    bpf_tail_call_static(msg, &obi_egress_progs, k_tail_egress_h2_create_tp);
    return SK_PASS;
}

static __always_inline int obi_egress_h2_create_step(struct sk_msg_md *msg, tailcall_ctx *t_ctx) {
    struct socket_data *sk_data = bpf_map_lookup_elem(&sk_data_map, &t_ctx->sock_cookie);
    if (!sk_data) {
        return SK_PASS;
    }

    tp_info_pid_t *tp_p = tp_buf_mem();
    if (!tp_p) {
        return SK_PASS;
    }
    bpf_memset(tp_p, 0, sizeof(*tp_p));

    tp_info_pid_t *existing = get_tp_info_pid(&t_ctx->e_key);
    const bool have_existing = existing && existing->valid && valid_trace(existing->tp.trace_id);

    if (have_existing && existing->written) {
        h2_resume_after(
            msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
        return SK_PASS;
    }

    if (have_existing) {
        bpf_memcpy(tp_p, existing, sizeof(*tp_p));
        tp_p->written = 1;
        h2_set_outgoing(&t_ctx->e_key, tp_p);
    } else {
        init_tp(sk_data, &tp_p->tp);
        // Reuse the emitted client span's trace+span id (carried via t_ctx) so the
        // injected wire traceparent matches the span userspace builds, rather than
        // minting a fresh one that leaves the downstream server on a phantom parent.
        __builtin_memcpy(tp_p->tp.trace_id, t_ctx->emit_trace_id, sizeof(tp_p->tp.trace_id));
        __builtin_memcpy(tp_p->tp.span_id, t_ctx->emit_span_id, sizeof(tp_p->tp.span_id));
        tp_p->tp.ts = bpf_ktime_get_ns();
        tp_p->tp.flags = 1;
        tp_p->valid = 1;
        tp_p->written = 1;
        tp_p->pid = sk_data->pid_tgid;
        tp_p->req_type = EVENT_HTTP_CLIENT;
        if (bpf_map_update_elem(&outgoing_trace_map, &t_ctx->e_key, tp_p, BPF_NOEXIST) != 0) {
            existing = get_tp_info_pid(&t_ctx->e_key);
            if (existing) {
                bpf_memcpy(tp_p, existing, sizeof(*tp_p));
            }
        }
    }

    schedule_write_tcp_option(msg, tp_p);

    if (inject_flags & k_inject_http_headers) {
        bpf_tail_call_static(msg, &obi_egress_progs, k_tail_egress_h2_write_tp);
    }
    return SK_PASS;
}

// Push k_h2_tp_hpack_size bytes of HPACK at the end of the HEADERS block and
// patch the frame length. Small fixed-offset pulls keep the verifier happy;
// bpf_msg_push_data invalidates msg pointers, so re-pull after it.
static __always_inline int obi_egress_h2_write_step(struct sk_msg_md *msg, tailcall_ctx *t_ctx) {
    tp_info_pid_t *tp_p = tp_buf_mem();
    if (!tp_p) {
        return SK_PASS;
    }

    const u32 frame_offset = t_ctx->h2_frame_offset;
    const u32 payload_len = t_ctx->h2_payload_len;

    if (payload_len + k_h2_tp_hpack_size > k_h2_default_max_frame_size) {
        return SK_PASS;
    }

    const u32 inject_offset = t_ctx->h2_hpack_offset + t_ctx->h2_hpack_len;

    bpf_msg_pull_data(msg, 0, msg->size, 0);
    if (bpf_msg_push_data(msg, inject_offset, k_h2_tp_hpack_size, 0) != 0) {
        return SK_PASS;
    }

    const u32 pull_end = inject_offset + k_h2_tp_hpack_size;
    if (bpf_msg_pull_data(msg, frame_offset, pull_end, 0) != 0) {
        return SK_PASS;
    }

    unsigned char *data = msg->data;
    const unsigned char *end = msg->data_end;

    if (!data || (void *)data + 3 > (void *)end) {
        return SK_PASS;
    }

    const u32 new_len = payload_len + k_h2_tp_hpack_size;
    data[0] = (new_len >> 16) & 0xFF;
    data[1] = (new_len >> 8) & 0xFF;
    data[2] = new_len & 0xFF;

    if (bpf_msg_pull_data(msg, inject_offset, inject_offset + k_h2_tp_hpack_size, 0) != 0) {
        return SK_PASS;
    }
    data = msg->data;
    end = msg->data_end;
    if (!data || (void *)data + k_h2_tp_hpack_size > (void *)end) {
        return SK_PASS;
    }
    make_h2_tp_hpack(data, &tp_p->tp, end);

    bpf_msg_pull_data(msg, 0, msg->size, 0);

    print_tp("h2: written TP to HPACK", &tp_p->tp);

    h2_resume_after(msg,
                    t_ctx,
                    t_ctx->h2_frame_offset + k_h2_frame_header_len + payload_len +
                        k_h2_tp_hpack_size);
    return SK_PASS;
}
