// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_endian.h>

#include <common/algorithm.h>
#include <common/connection_info.h>
#include <common/egress_key.h>
#include <common/event_defs.h>
#include <common/go_grpc_client_conn.h>
#include <common/h2_defs.h>
#define OBI_HPACK_ENABLE_DYNAMIC_TRACEPARENT_CACHE 0
#include <common/hpack.h>
#include <common/http_buf_size.h>
#include <common/http_types.h>
#include <common/lw_thread.h>
#include <common/msg_buffer.h>
#include <common/outgoing_trace_handoff.h>
#include <common/protocol_http_helpers.h>
#include <common/protocol_http2_helpers.h>
#include <common/protocol_tcp_helpers.h>
#include <common/scratch_mem.h>
#include <common/ssl_connection.h>
#include <common/tc_common.h>
#include <common/tp_info.h>
#include <common/trace_helpers.h>
#include <common/trace_parent.h>
#include <common/trace_util.h>
#include <common/tracing.h>

#include <pid/pid.h>

#include <logger/bpf_dbg.h>

#include <maps/incoming_trace_map.h>
#include <maps/msg_buffers.h>
#include <maps/outgoing_trace_map.h>
#include <maps/sock_dir.h>
#include <maps/tp_info_mem.h>
#include <maps/tracked_sock_cookies.h>

#include <tpinjector/h2_parse.h>
#include <tpinjector/inject_policy.h>
#include <tpinjector/injection_state.h>
#include <tpinjector/maps/sk_h2_flags.h>
#include <tpinjector/maps/sk_h2_conn_flag.h>
#include <tpinjector/maps/sk_tp_info_pid_map.h>
#include <tpinjector/tp_options.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// =============================================================================
// Tail-call chain map
// =============================================================================
//
//   obi_packet_extender (sk_msg entry)
//   │
//   ├── tp_pid present?               ─┐  Central dispatch: Go net/http,
//   │     └── handle_existing_tp_pid   │  SSL. Pulls+fills internally after
//   │                                  │  passing valid check, then injects
//   │                                  │
//   ├── is_go_grpc_client_conn?        │  Go gRPC: pull+fill, then the H2 chain
//   │     └── pull+fill+H2 chain       │  verifies or injects the pending
//   │                                  │  per-stream traceparent
//   │                                  │
//   ├── !valid_pid → SK_PASS           │  Unmonitored process — no pull
//   │                                  │
//   ├── pull_data + fill_msg_buffers   │  Committed to processing
//   │                                  │
//   ├── is_h2_socket?                  │  Preface seen / confirmed H2: skip
//   │     └─ tail-call detect_h2       │  preface check, drive the H2 chain
//   │                                 │
//   ├── HTTP/1 detected?              │  ── find_existing_tp ── create_tp ──
//   │                                 │     write_msg_traceparent
//   │                                 │
//   └── fall through ─────────────────┴─▶ wrap_http2_traceparent
//                                           │ preface at pos 0, or (for conns
//                                           │ whose preface predates attach)
//                                           │ strict mid-stream frame sniff
//                                           │ confirms; known-SSL conns are
//                                           │ never sniffed
//                                           ▼
//                                        detect_h2 ◀──────────────┐
//                                           │                     │
//                                           │ preface→SETTINGS     │ resume on
//                                           │ confirms genuine H2  │ batched
//                                           │ (else reject);       │ frame via
//                                           │ then HEADERS+        │ h2_scan_pos
//                                           │ END_HEADERS          │
//                                           ▼                     │
//                                        find_existing_h2_tp ─────┤
//                                           │ adopt or            │
//                                           ▼                     │
//                                        create_h2_tp ────────────┤
//                                           │                     │
//                                           ▼                     │
//                                        write_h2_tp ─────────────┘
//
// State for the H2 chain lives in tailcall_ctx (per-CPU scratch); see its
// definition below for field meanings.
// =============================================================================

// Flags to control what tpinjector should inject
enum {
    k_inject_http_headers = 1 << 0, // Bit 0: inject HTTP headers
    k_inject_tcp_options = 1 << 1,  // Bit 1: inject TCP options
};

volatile const u32 inject_flags =
    k_inject_http_headers | k_inject_tcp_options; // default: both enabled

enum {
    k_tail_write_msg_traceparent,
    k_tail_find_existing_tp,
    k_tail_finalize_existing_tp,
    k_tail_create_tp,
    k_tail_write_h2_traceparent,
    k_tail_create_h2_tp,
    k_tail_find_existing_h2_tp,
    k_tail_validate_h2_tp,
    k_tail_detect_h2,
    k_tail_sniff_h2,
    k_tail_reserve_h2_tp,
    k_tail_finish_existing_h2_tp,
    k_tail_reserve_existing_h2_tp,
    k_tail_claim_existing_h2_tp,
    k_tail_validate_existing_tp,
    k_tail_continue_existing_h2_tp,
    k_tail_count,
};

int obi_packet_extender_write_msg_tp(struct sk_msg_md *msg);
int obi_packet_extender_find_existing_tp(struct sk_msg_md *msg);
int obi_packet_extender_finalize_existing_tp(struct sk_msg_md *msg);
int obi_packet_extender_create_tp(struct sk_msg_md *msg);
int obi_packet_extender_write_h2_tp(struct sk_msg_md *msg);
int obi_packet_extender_create_h2_tp(struct sk_msg_md *msg);
int obi_packet_extender_find_existing_h2_tp(struct sk_msg_md *msg);
int obi_packet_extender_validate_h2_tp(struct sk_msg_md *msg);
int obi_packet_extender_detect_h2(struct sk_msg_md *msg);
int obi_packet_extender_sniff_h2(struct sk_msg_md *msg);
int obi_packet_extender_reserve_h2_tp(struct sk_msg_md *msg);
int obi_packet_extender_finish_existing_h2_tp(struct sk_msg_md *msg);
int obi_packet_extender_reserve_existing_h2_tp(struct sk_msg_md *msg);
int obi_packet_extender_claim_existing_h2_tp(struct sk_msg_md *msg);
int obi_packet_extender_validate_existing_tp(struct sk_msg_md *msg);
int obi_packet_extender_continue_existing_h2_tp(struct sk_msg_md *msg);

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, k_tail_count);
    __uint(key_size, sizeof(u32));
    __array(values, int(void *));
} extender_jump_table SEC(".maps") = {
    .values =
        {
            [k_tail_write_msg_traceparent] = (void *)&obi_packet_extender_write_msg_tp,
            [k_tail_find_existing_tp] = (void *)&obi_packet_extender_find_existing_tp,
            [k_tail_finalize_existing_tp] = (void *)&obi_packet_extender_finalize_existing_tp,
            [k_tail_create_tp] = (void *)&obi_packet_extender_create_tp,
            [k_tail_write_h2_traceparent] = (void *)&obi_packet_extender_write_h2_tp,
            [k_tail_create_h2_tp] = (void *)&obi_packet_extender_create_h2_tp,
            [k_tail_find_existing_h2_tp] = (void *)&obi_packet_extender_find_existing_h2_tp,
            [k_tail_validate_h2_tp] = (void *)&obi_packet_extender_validate_h2_tp,
            [k_tail_detect_h2] = (void *)&obi_packet_extender_detect_h2,
            [k_tail_sniff_h2] = (void *)&obi_packet_extender_sniff_h2,
            [k_tail_reserve_h2_tp] = (void *)&obi_packet_extender_reserve_h2_tp,
            [k_tail_finish_existing_h2_tp] = (void *)&obi_packet_extender_finish_existing_h2_tp,
            [k_tail_reserve_existing_h2_tp] = (void *)&obi_packet_extender_reserve_existing_h2_tp,
            [k_tail_claim_existing_h2_tp] = (void *)&obi_packet_extender_claim_existing_h2_tp,
            [k_tail_validate_existing_tp] = (void *)&obi_packet_extender_validate_existing_tp,
            [k_tail_continue_existing_h2_tp] = (void *)&obi_packet_extender_continue_existing_h2_tp,
        },
};

// State threaded across the tail-call chain via per-CPU scratch memory.
// Set in obi_packet_extender; read/written by the H2 and HTTP/1 chains.
typedef struct tailcall_ctx {
    pid_connection_info_t p_conn; // sorted connection + caller PID
    tp_info_t parent_tp;          // parent trace context (set by init_tp_ctx_parent_tp)
    egress_key_t e_key;           // {endpoints, PID, stream} key for outgoing_trace_map
    u32 h2_frame_offset;          // start of the HEADERS frame in msg
    u32 h2_payload_len;           // HEADERS payload length
    u32 h2_hpack_offset;          // start of HPACK bytes (after PADDED/PRIORITY prefix)
    u32 h2_hpack_len;             // HPACK length (frame payload minus prefix and trailing pad)
    u32 h2_scan_pos;              // resume offset for detect_h2 across tail calls
    u32 h2_tp_candidate_pos;      // traceparent value offset (>= max = none)
    u32 h2_tp_value_len;          // encoded traceparent value length
    u32 http1_span_id_offset;     // existing HTTP/1 traceparent span ID in msg
    u32 http1_scan_pos;           // next absolute HTTP/1 byte to scan
    u32 http1_value_offset;       // candidate traceparent value in msg
    u8 niter;                     // HTTP/1 find-existing scan iteration counter
    u8 http1_tp_status;           // authoritative HTTP/1 traceparent scan state
    u8 h2_frames;                 // H2 frames already injected this packet (capped)
    u8 h2_tp_status;              // hpack_traceparent_status
    u8 h2_tp_value_huffman;       // traceparent value uses HPACK Huffman coding
    u8 h2_tp_representation;      // hpack_field_representation
    bool has_parent_tp;           // true if parent_tp holds a valid context
    bool go_h2_conn;              // Go H2 egress: exact per-stream state owns identity
    bool tp_present;              // frame already carries a traceparent we cannot adopt
    bool scan_exhausted;          // HPACK block exceeds the bounded scan
    u8 opener;                    // first HPACK field byte of the frame being considered
    bool rewrite_http1_tp;        // parsed header became a new OBI client span
    bool tcp_option_scheduled;    // a sockops callback can still publish this traceparent
    unsigned char h2_wire_trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char h2_wire_span_id[SPAN_ID_SIZE_BYTES];
    u8 h2_wire_flags;
    bool rewrite_h2_tp; // parsed H2 header became a new OBI client span
    u8 h2_handoff_fresh;
    u8 h2_hpack_scan_calls; // completed parser calls at the current continuation boundary
    u8 h2_hpack_scan_guard; // binds the continuation token to the saved parser state
    u8 h2_tail_calls;       // conservative per-packet kernel tail-call depth
    u8 _h2_wire_pad[2];
    unsigned char original_span_id[SPAN_ID_SIZE_BYTES];
    u8 original_flags; // restore when a parsed wire traceparent rewrite fails
    u8 handoff_expected;
    u8 _tail_pad[5];
    outgoing_trace_token_t handoff_token;
} tailcall_ctx;

SCRATCH_MEM(tailcall_ctx);
SCRATCH_MEM_SIZED(tp_str_buf, 64);
SCRATCH_MEM_SIZED(h2_hpack_buf, k_h2_max_hpack_scan);
SCRATCH_MEM_TYPED(h2_hpack_dynamic_names, hpack_dynamic_name_state_t);
SCRATCH_MEM_TYPED(h2_hpack_scan_state, hpack_traceparent_scan_state_t);
SCRATCH_MEM_TYPED(h2_hpack_decoder_state, hpack_traceparent_decoder_state_t);
SCRATCH_MEM_TYPED(fill_msg_buffer, msg_buffer_t);

static __always_inline bool h2_take_tail_call(tailcall_ctx *t_ctx) {
    if (t_ctx->h2_tail_calls >= k_h2_tail_call_limit) {
        return false;
    }
    t_ctx->h2_tail_calls++;
    return true;
}

// Resume detect_h2 at next_pos for the next batched HEADERS frame.
// Bumps the per-packet frame counter, then tail-calls back into detect_h2.
static __always_inline void
h2_resume_after(struct sk_msg_md *msg, tailcall_ctx *t_ctx, u32 next_pos) {
    t_ctx->h2_scan_pos = next_pos;
    t_ctx->h2_frames++;
    if (t_ctx->h2_frames >= k_h2_max_frames_per_packet) {
        return;
    }
    if (h2_take_tail_call(t_ctx)) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_detect_h2);
    }
}

// Per-socket HTTP/2 detection state (sk_h2_conn_flag values).
//
// We only splice an HPACK traceparent once we've confirmed a *genuine* HTTP/2
// stream. RFC 7540 §3.4/§3.5 require the client connection preface
// ("PRI * HTTP/2.0...") to be immediately followed by a SETTINGS frame. A stream
// that merely embeds the preface inside some other framing — e.g. GitLab
// Gitaly's yamux-multiplexed backchannel (issue #2706) — never emits that
// SETTINGS frame as the next bytes on the raw socket; instead the peer's framing
// header follows. Injecting into such a stream shifts the outer framing and
// corrupts the connection, so those sockets must be rejected.
enum {
    k_h2_sock_none = 0,      // nothing seen yet
    k_h2_sock_preface = 1,   // preface seen, awaiting the mandatory SETTINGS frame
    k_h2_sock_confirmed = 2, // SETTINGS seen after preface — genuine HTTP/2, inject
    k_h2_sock_rejected = 3,  // post-preface bytes were not SETTINGS — never inject
};

static __always_inline u8 h2_sock_state(struct sk_msg_md *msg) {
    struct bpf_sock *sk = msg->sk;
    if (!sk) {
        return k_h2_sock_none;
    }
    const u8 *flag = bpf_sk_storage_get(&sk_h2_conn_flag, sk, NULL, 0);
    return flag ? *flag : k_h2_sock_none;
}

static __always_inline bool h2_sk_flag(struct sk_msg_md *msg, u8 flag) {
    struct bpf_sock *sk = msg->sk;
    if (!sk) {
        return false;
    }
    const u8 *flags = bpf_sk_storage_get(&sk_h2_flags, sk, NULL, 0);
    return flags && (*flags & flag);
}

static __always_inline void set_h2_sk_flag(struct sk_msg_md *msg, u8 flag) {
    struct bpf_sock *sk = msg->sk;
    if (!sk) {
        return;
    }
    u8 init = flag;
    u8 *flags = bpf_sk_storage_get(&sk_h2_flags, sk, &init, BPF_SK_STORAGE_GET_F_CREATE);
    if (flags) {
        *flags |= flag;
    }
}

// First HPACK field byte of a header block, past any dynamic table size updates. False when
// it cannot be read: a short block leaves no room to skip the updates.
static __always_inline bool
h2_headers_opener(struct sk_msg_md *msg, u32 hpack_offset, u32 msg_size, u8 *out) {
    if (hpack_offset + k_h2_hpack_opener_window <= msg_size &&
        bpf_msg_pull_data(msg, hpack_offset, hpack_offset + k_h2_hpack_opener_window, 0) == 0) {
        const unsigned char *d = msg->data;
        if (!d || (void *)(d + k_h2_hpack_opener_window) > msg->data_end) {
            return false;
        }

        unsigned char w[k_h2_hpack_opener_window];
        bpf_memcpy(w, d, sizeof(w));

        const u32 skip = h2_hpack_skip_size_updates(w, sizeof(w));
        if (skip >= sizeof(w)) {
            return false;
        }

        *out = w[skip & k_h2_hpack_opener_mask];

        return true;
    }

    if (hpack_offset + 1 > msg_size ||
        bpf_msg_pull_data(msg, hpack_offset, hpack_offset + 1, 0) != 0) {
        return false;
    }

    const unsigned char *d = msg->data;
    if (!d || (void *)(d + 1) > msg->data_end || h2_hpack_is_size_update(d[0])) {
        return false;
    }

    *out = d[0];

    return true;
}

static __always_inline void set_h2_sock_state(struct sk_msg_md *msg, u8 state) {
    struct bpf_sock *sk = msg->sk;
    if (!sk) {
        return;
    }
    u8 *flag = bpf_sk_storage_get(&sk_h2_conn_flag, sk, &state, BPF_SK_STORAGE_GET_F_CREATE);
    if (flag) {
        *flag = state;
    }
}

// True while the socket is in an HTTP/2 scanning state (preface seen or
// confirmed) — i.e. detect_h2 should keep driving its state machine. Rejected
// and never-seen sockets are excluded.
static __always_inline bool is_h2_socket(struct sk_msg_md *msg) {
    const u8 state = h2_sock_state(msg);
    return state == k_h2_sock_preface || state == k_h2_sock_confirmed;
}

#ifndef ENOMSG
#define ENOMSG 42
#endif

static __always_inline const char *tp_string_from_opt(const otel_tcp_option_t *opt,
                                                      const u8 flags) {
    unsigned char *buf = tp_str_buf_mem();

    if (!buf) {
        return NULL;
    }

    unsigned char *ptr = buf;

    // Version
    *ptr++ = '0';
    *ptr++ = '0';
    *ptr++ = '-';

    // Trace ID
    encode_hex(ptr, opt->trace_id, TRACE_ID_SIZE_BYTES);
    ptr += TRACE_ID_CHAR_LEN;

    *ptr++ = '-';

    // SpanID
    encode_hex(ptr, opt->span_id, SPAN_ID_SIZE_BYTES);
    ptr += SPAN_ID_CHAR_LEN;

    *ptr++ = '-';

    encode_traceparent_flags(ptr, flags);
    ptr += FLAGS_CHAR_LEN;
    *ptr++ = '\0';

    return (const char *)buf;
}

static __always_inline void print_tp(const char *msg, const tp_info_t *tp) {
    if (!g_bpf_debug) {
        return;
    }

    unsigned char tp_buf_str[TP_MAX_VAL_LENGTH];
    make_tp_string(tp_buf_str, tp);
    bpf_dbg_printk("%s: %s", msg, tp_buf_str);
}

static __always_inline void clear_matching_pending_tp_info_pid(const egress_key_t *e_key,
                                                               const outgoing_trace_token_t *token,
                                                               const tp_info_pid_t *expected) {
    request_outgoing_trace_handoff_retirement(e_key, token, expected, 1);
}

static __always_inline void retire_fresh_h2_handoff(tailcall_ctx *t_ctx,
                                                    const tp_info_pid_t *expected) {
    if (h2_handoff_failure_retires(t_ctx->h2_handoff_fresh)) {
        clear_matching_pending_tp_info_pid(&t_ctx->e_key, &t_ctx->handoff_token, expected);
    }
    t_ctx->h2_handoff_fresh = 0;
    t_ctx->h2_hpack_scan_calls = 0;
    t_ctx->h2_hpack_scan_guard = 0;
}

static __always_inline u8 already_tracked(const pid_connection_info_t *p_conn) {
    return already_tracked_http(p_conn) || already_tracked_tcp(p_conn) ||
           already_tracked_http2(p_conn);
}

static __always_inline void
sk_ops_read_ip4_ports(struct bpf_sock_ops *ops,
                      u32 *local_ip4,     // NOLINT(readability-non-const-parameter)
                      u32 *remote_ip4,    // NOLINT(readability-non-const-parameter)
                      u32 *local_port,    // NOLINT(readability-non-const-parameter)
                      u32 *remote_port) { // NOLINT(readability-non-const-parameter)
    asm("%[local_ip] = *(u32 *)(%[base] + %[local_ip_offset])\n"
        "%[remote_ip] = *(u32 *)(%[base] + %[remote_ip_offset])\n"
        "%[local_p] = *(u32 *)(%[base] + %[local_port_offset])\n"
        "%[remote_p] = *(u32 *)(%[base] + %[remote_port_offset])\n"
        : [local_ip] "=&r"(*local_ip4),
          [remote_ip] "=&r"(*remote_ip4),
          [local_p] "=&r"(*local_port),
          [remote_p] "=&r"(*remote_port)
        : [base] "r"(ops),
          [local_ip_offset] "i"(offsetof(struct bpf_sock_ops, local_ip4)),
          [remote_ip_offset] "i"(offsetof(struct bpf_sock_ops, remote_ip4)),
          [local_port_offset] "i"(offsetof(struct bpf_sock_ops, local_port)),
          [remote_port_offset] "i"(offsetof(struct bpf_sock_ops, remote_port)),
          "m"(*ops));
}

static __always_inline void
sk_ops_read_remote_ip6(struct bpf_sock_ops *ops,
                       u32 *res) { // NOLINT(readability-non-const-parameter)
    asm("%[res0] = *(u32 *)(%[base] + %[offset] + 0)\n"
        "%[res1] = *(u32 *)(%[base] + %[offset] + 4)\n"
        "%[res2] = *(u32 *)(%[base] + %[offset] + 8)\n"
        "%[res3] = *(u32 *)(%[base] + %[offset] + 12)\n"
        : [res0] "=&r"(res[0]), [res1] "=&r"(res[1]), [res2] "=&r"(res[2]), [res3] "=&r"(res[3])
        : [base] "r"(ops), [offset] "i"(offsetof(struct bpf_sock_ops, remote_ip6)), "m"(*ops));
}

static __always_inline void
sk_ops_read_local_ip6(struct bpf_sock_ops *ops,
                      u32 *res) { // NOLINT(readability-non-const-parameter)
    asm("%[res0] = *(u32 *)(%[base] + %[offset] + 0)\n"
        "%[res1] = *(u32 *)(%[base] + %[offset] + 4)\n"
        "%[res2] = *(u32 *)(%[base] + %[offset] + 8)\n"
        "%[res3] = *(u32 *)(%[base] + %[offset] + 12)\n"
        : [res0] "=&r"(res[0]), [res1] "=&r"(res[1]), [res2] "=&r"(res[2]), [res3] "=&r"(res[3])
        : [base] "r"(ops), [offset] "i"(offsetof(struct bpf_sock_ops, local_ip6)), "m"(*ops));
}

// Extracts what we need for connection_info_t from bpf_sock_ops if the
// communication is IPv4
static __always_inline connection_info_t sk_ops_extract_key_ip4(struct bpf_sock_ops *ops) {
    connection_info_t conn = {};

    u32 local_ip4;
    u32 remote_ip4;
    u32 local_port;
    u32 remote_port;
    sk_ops_read_ip4_ports(ops, &local_ip4, &remote_ip4, &local_port, &remote_port);

    __builtin_memcpy(conn.s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn.s_ip[3] = local_ip4;
    __builtin_memcpy(conn.d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn.d_ip[3] = remote_ip4;

    conn.s_port = local_port;
    conn.d_port = bpf_ntohl(remote_port);

    return conn;
}

// Extracts what we need for connection_info_t from bpf_sock_ops if the
// communication is IPv6
// The order of copying the data from bpf_sock_ops matters and must match how
// the struct is laid in vmlinux.h, otherwise the verifier thinks we are modifying
// the context twice.
static __always_inline connection_info_t sk_ops_extract_key_ip6(struct bpf_sock_ops *ops) {
    connection_info_t conn = {};

    sk_ops_read_remote_ip6(ops, conn.d_ip);
    sk_ops_read_local_ip6(ops, conn.s_ip);

    u32 local_ip4;
    u32 remote_ip4;
    u32 local_port;
    u32 remote_port;
    sk_ops_read_ip4_ports(ops, &local_ip4, &remote_ip4, &local_port, &remote_port);
    conn.d_port = bpf_ntohl(remote_port);
    conn.s_port = local_port;

    return conn;
}

static __always_inline connection_info_t get_connection_info_ops(struct bpf_sock_ops *ops) {
    return ops->family == AF_INET6 ? sk_ops_extract_key_ip6(ops) : sk_ops_extract_key_ip4(ops);
}

// Extracts what we need for connection_info_t from sk_msg_md if the
// communication is IPv4
static __always_inline void sk_msg_extract_key_ip4(const struct sk_msg_md *msg,
                                                   connection_info_t *conn) {
    __builtin_memcpy(conn->s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn->s_ip[3] = msg->local_ip4;
    __builtin_memcpy(conn->d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn->d_ip[3] = msg->remote_ip4;

    conn->s_port = msg->local_port;
    conn->d_port = bpf_ntohl(msg->remote_port);
}

// Extracts what we need for connection_info_t from sk_msg_md if the
// communication is IPv6
// The order of copying the data from bpf_sock_ops matters and must match how
// the struct is laid in vmlinux.h, otherwise the verifier thinks we are modifying
// the context twice.
static __always_inline void sk_msg_extract_key_ip6(struct sk_msg_md *msg, connection_info_t *conn) {
    sk_msg_read_remote_ip6(msg, conn->d_ip);
    sk_msg_read_local_ip6(msg, conn->s_ip);

    conn->d_port = bpf_ntohl(sk_msg_remote_port(msg));
    conn->s_port = sk_msg_local_port(msg);
}

static __always_inline void init_tp_ctx_parent_tp(tailcall_ctx *t_ctx) {
    t_ctx->parent_tp.ts = bpf_ktime_get_ns();
    t_ctx->parent_tp.flags = k_flag_sampled;
    reset_sampling_decision(&t_ctx->parent_tp);

    t_ctx->has_parent_tp = find_parent_trace_for_client_request(
        &t_ctx->p_conn, t_ctx->p_conn.conn.d_port, k_lw_thread_none, &t_ctx->parent_tp);
}

static __always_inline bool create_trace_info(const tailcall_ctx *t_ctx, tp_info_pid_t *tp_p) {
    // t_ctx->parent_tp was initialised earlier in init_tp_ctx_parent_tp - if
    // t_ctx->has_parent_tp is true, then it actually contains a valid tp_info
    // with the corrent trace_id and parent_id - all we need to do is generate
    // a new span_id
    // this logic is cumbersome, but it is done so to avoid calling
    // find_trace_for_client_request multiple times (i.e. once here, and once
    // earlier in  k_tail_find_existing_tp - sorry!
    urand_bytes(tp_p->tp.span_id, sizeof(tp_p->tp.span_id));
    initialize_created_client_trace(tp_p, t_ctx->p_conn.pid, bpf_ktime_get_ns());

    if (t_ctx->has_parent_tp) {
        bpf_dbg_printk("found existing tp info");

        __builtin_memcpy(tp_p->tp.trace_id, t_ctx->parent_tp.trace_id, sizeof(tp_p->tp.trace_id));
        __builtin_memcpy(tp_p->tp.parent_id, t_ctx->parent_tp.span_id, sizeof(tp_p->tp.parent_id));
        inherit_parent_sampling_state(&tp_p->tp, &t_ctx->parent_tp);
    } else {
        bpf_dbg_printk("generating tp info");

        new_trace_id(&tp_p->tp);
        __builtin_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));
    }
    apply_sampling_decision(&tp_p->tp, t_ctx->has_parent_tp, 0);

    return true;
}

static __always_inline void bpf_sock_ops_set_flags(struct bpf_sock_ops *skops, u8 flags) {
    bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | flags);
}

static __always_inline egress_key_t sock_ops_egress_key(struct bpf_sock_ops *skops,
                                                        const tp_info_pid_t *tp_pid) {
    const connection_info_t conn = get_connection_info_ops(skops);
    return make_egress_key(&conn, tp_pid->pid, 0);
}

static __always_inline u8 scheduled_tcp_option_is_current(
    struct bpf_sock_ops *skops, const sk_outgoing_trace_handoff_t *stored) {
    const egress_key_t e_key = sock_ops_egress_key(skops, &stored->tp);
    tp_info_pid_t snapshot = {};
    return snapshot_outgoing_trace_handoff(
               &e_key, &stored->token, stored->tp.pid, EVENT_HTTP_CLIENT, 0, &snapshot, NULL) &&
           outgoing_trace_identity_matches(&snapshot, &stored->tp);
}

static __always_inline void discard_scheduled_tcp_option(struct bpf_sock_ops *skops,
                                                         struct bpf_sock *sk) {
    const sk_outgoing_trace_handoff_t *stored =
        bpf_sk_storage_get(&sk_tp_info_pid_map, sk, NULL, 0);
    if (!stored) {
        return;
    }
    const sk_outgoing_trace_handoff_t pending = *stored;
    bpf_sk_storage_delete(&sk_tp_info_pid_map, sk);

    const egress_key_t e_key = sock_ops_egress_key(skops, &pending.tp);
    clear_matching_pending_tp_info_pid(&e_key, &pending.token, &pending.tp);
}

// Helper that writes in the sock map for a sock_ops program
static __always_inline void bpf_sock_ops_active_est_cb(struct bpf_sock_ops *skops) {
    const u64 cookie = bpf_get_socket_cookie(skops);

    if (bpf_sock_hash_update(skops, &sock_dir, (void *)&cookie, BPF_ANY) == 0) {
        bpf_map_update_elem(&tracked_sock_cookies, &cookie, &(u8){1}, BPF_ANY);
    }
    bpf_sock_ops_set_flags(skops, BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
}

static __always_inline void bpf_sock_ops_passive_est_cb(struct bpf_sock_ops *skops) {
    if (!(inject_flags & k_inject_tcp_options)) {
        return;
    }

    bpf_sock_ops_set_flags(skops, BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG);
}

static __always_inline void bpf_sock_ops_opt_len_cb(struct bpf_sock_ops *skops) {
    struct bpf_sock *sk = skops->sk;

    if (!sk) {
        return;
    }

    sk_outgoing_trace_handoff_t *stored = bpf_sk_storage_get(&sk_tp_info_pid_map, sk, NULL, 0);

    if (!stored) {
        return;
    }
    if (!scheduled_tcp_option_is_current(skops, stored)) {
        discard_scheduled_tcp_option(skops, sk);
        return;
    }

    long ret;
    if (use_otel_tcp_legacy_option(&stored->tp.tp)) {
        ret = bpf_reserve_hdr_opt(skops, sizeof(otel_tcp_option_t), 0);
    } else {
        ret = bpf_reserve_hdr_opt(skops, sizeof(otel_tcp_extended_option_t), 0);
    }

    if (ret != 0) {
        bpf_dbg_printk("failed to reserve TCP option: %d", ret);
        discard_scheduled_tcp_option(skops, sk);
    }
}

static __always_inline void bpf_sock_ops_write_hdr_cb(struct bpf_sock_ops *skops) {
    struct bpf_sock *sk = skops->sk;

    if (!sk) {
        return;
    }

    const sk_outgoing_trace_handoff_t *stored =
        bpf_sk_storage_get(&sk_tp_info_pid_map, sk, NULL, 0);

    if (!stored) {
        bpf_dbg_printk("tp info not found");
        return;
    }
    const sk_outgoing_trace_handoff_t pending = *stored;

    // cleanup the storage to prevent it from being written more than once
    // (including during responses);
    bpf_sk_storage_delete(&sk_tp_info_pid_map, sk);

    const egress_key_t e_key = sock_ops_egress_key(skops, &pending.tp);
    if (!claim_outgoing_trace_handoff(
            &e_key, &pending.token, pending.tp.pid, EVENT_HTTP_CLIENT, &pending.tp, 0, 0, NULL)) {
        return;
    }

    otel_tcp_extended_option_t opt = {};
    long ret;
    if (use_otel_tcp_legacy_option(&pending.tp.tp)) {
        make_otel_tcp_option(&opt.legacy, &pending.tp.tp);
        ret = bpf_store_hdr_opt(skops, &opt.legacy, sizeof(opt.legacy), 0);
    } else {
        make_otel_tcp_extended_option(&opt, &pending.tp.tp);
        ret = bpf_store_hdr_opt(skops, &opt, sizeof(opt), 0);
    }

    if (ret != 0) {
        bpf_dbg_printk("failed to store option: %d", ret);
        release_claimed_outgoing_trace_handoff(&e_key, &pending.token);
        clear_matching_pending_tp_info_pid(&e_key, &pending.token, &pending.tp);
        return;
    }

    // The matched map value is the same object that authorized this callback. Transitioning it
    // in place after bpf_store_hdr_opt avoids a fallible post-wire map update.
    commit_claimed_outgoing_trace_handoff(&e_key, &pending.token);
    mirror_outgoing_trace_handoff_commit(&e_key, &pending.tp);

    if (g_bpf_debug) {
        const char *tp_str = tp_string_from_opt(&opt.legacy, pending.tp.tp.flags);

        if (tp_str) {
            bpf_dbg_printk("written TP to TCP options: %s", tp_str);
        }
    }
}

static __always_inline void bpf_sock_ops_parse_hdr_cb(struct bpf_sock_ops *skops) {
    if (!(inject_flags & k_inject_tcp_options)) {
        return;
    }

    otel_tcp_extended_option_t opt = {};
    opt.legacy.kind = k_tcp_option_kind_otel;

    const long ret = bpf_load_hdr_opt(skops, &opt, sizeof(opt), 0);

    if (ret == -ENOMSG) {
        return;
    }

    if (ret < 0) {
        bpf_dbg_printk("error parsing TCP option: %d", ret);
        return;
    }

    if (!valid_otel_tcp_option(&opt, ret)) {
        bpf_dbg_printk("invalid TCP option");
        return;
    }

    const u8 flags = otel_tcp_flags(&opt, ret);

    tp_info_pid_t tp = {};
    tp.valid = 1;

    __builtin_memcpy(tp.tp.trace_id, opt.legacy.trace_id, sizeof(tp.tp.trace_id));
    __builtin_memcpy(tp.tp.span_id, opt.legacy.span_id, sizeof(tp.tp.span_id));
    tp.tp.flags = flags;

    if (g_bpf_debug) {
        const char *tp_str = tp_string_from_opt(&opt.legacy, flags);

        if (tp_str) {
            bpf_dbg_printk("found TP in TCP options: %s", tp_str);
        }
    }

    connection_info_t conn = get_connection_info_ops(skops);
    sort_connection_info(&conn);

    dbg_print_http_connection_info(&conn);
    bpf_map_update_elem(&incoming_trace_map, &conn, &tp, BPF_ANY);
}

// Tracks all outgoing sockets (BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
// We don't track incoming, those would be BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB
SEC("sockops")
int obi_sockmap_tracker(struct bpf_sock_ops *skops) {
    struct bpf_sock *sk = skops->sk;

    if (!sk) {
        return 1;
    }

    switch (skops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        bpf_sock_ops_active_est_cb(skops);
        break;
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        bpf_sock_ops_passive_est_cb(skops);
        break;
    case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
        bpf_sock_ops_opt_len_cb(skops);
        break;
    case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
        bpf_sock_ops_write_hdr_cb(skops);
        break;
    case BPF_SOCK_OPS_PARSE_HDR_OPT_CB:
        bpf_sock_ops_parse_hdr_cb(skops);
        break;
    default:
        break;
    }

    return 1;
}

// This code is copied from the kprobe on tcp_sendmsg and it's called from
// the sock_msg program, which does the packet extension for injecting the
// Traceparent. Since the sock_msg runs before the kprobe on tcp_sendmsg, we
// need to extend the packet before we'll have the opportunity to setup the
// outgoing_trace_map metadata. We can directly perhaps run the same code that
// the kprobe on tcp_sendmsg does, but it's complicated, no tail calls from
// sock_msg programs and inlining will eventually hit us with the instruction
// limit when we eventually add HTTP2/gRPC support.
// Populates msg_buffers / msg_buffer_mem for the kprobe on tcp_sendmsg,
// which runs after sk_msg. Bails on size=0, SSL, or allocation failure.
static __noinline bool fill_msg_buffers(struct sk_msg_md *msg,
                                        const pid_connection_info_t *p_conn,
                                        const egress_key_t *e_key) {
    if (msg->size == 0 || is_ssl_connection(p_conn)) {
        return false;
    }

    msg_buffer_t *msg_buf = fill_msg_buffer_mem();
    if (!msg_buf) {
        return false;
    }
    __builtin_memset(msg_buf, 0, sizeof(*msg_buf));
    msg_buf->real_size = min(msg->size, k_msg_buffer_size_max);
    msg_buf->cpu_id = bpf_get_smp_processor_id();

    bpf_probe_read_kernel(msg_buf->fallback_buf, k_kprobes_http2_buf_size, msg->data);

    const u16 copy_bytes = max(msg_buf->real_size, k_kprobes_http2_buf_size);

    unsigned char **msg_ptr = bpf_map_lookup_elem(&msg_buffer_mem, &(u32){0});

    if (!msg_ptr) {
        bpf_d_printk("failed to reserve msg_buffer space [%s]", __FUNCTION__);
        return false;
    }

    msg_ptr[0] = 0;
    bpf_probe_read_kernel(msg_ptr, copy_bytes & k_msg_buffer_size_max_mask, msg->data);
    bpf_map_update_elem(&msg_buffer_mem, &(u32){0}, msg_ptr, BPF_ANY);

    // We setup any call that looks like HTTP request to be extended.
    // This must match exactly to what the decision will be for
    // the kprobe program on tcp_sendmsg, which sets up the
    // outgoing_trace_map data used by Traffic Control to write the
    // actual 'Traceparent:...' string.

    if (bpf_map_update_elem(&msg_buffers, e_key, msg_buf, BPF_ANY)) {
        // fail if we can't setup a msg buffer
        return false;
    }

    return true;
}

static __always_inline u8 reserve_transport_handoff_result(const egress_key_t *e_key,
                                                           const tp_info_pid_t *tp,
                                                           outgoing_trace_token_t *token) {
    egress_key_t msg_key = *e_key;
    msg_key.stream_id = 0;
    msg_buffer_t *msg_buf =
        e_key->stream_id == 0 ? bpf_map_lookup_elem(&msg_buffers, &msg_key) : NULL;
    if (msg_buf) {
        __builtin_memset(&msg_buf->handoff_token, 0, sizeof(msg_buf->handoff_token));
        msg_buf->handoff_expected = 1;
    }

    const u8 result = reserve_outgoing_trace_handoff(e_key, tp, token);
    if (msg_buf && token) {
        msg_buf->handoff_token = *token;
    }
    return result;
}

static __always_inline u8 reserve_transport_handoff(const egress_key_t *e_key,
                                                    const tp_info_pid_t *tp,
                                                    outgoing_trace_token_t *token) {
    return reserve_transport_handoff_result(e_key, tp, token) !=
           k_outgoing_trace_reservation_failed;
}

static __always_inline void mark_transport_handoff_expected(const egress_key_t *e_key,
                                                            const outgoing_trace_token_t *token) {
    if (e_key->stream_id != 0) {
        return;
    }
    egress_key_t msg_key = *e_key;
    msg_key.stream_id = 0;
    msg_buffer_t *msg_buf = bpf_map_lookup_elem(&msg_buffers, &msg_key);
    if (msg_buf) {
        msg_buf->handoff_expected = 1;
        msg_buf->handoff_token = *token;
    }
}

static __always_inline u8 protocol_detector(struct sk_msg_md *msg,
                                            u64 id,
                                            const connection_info_t *conn) {
    bpf_dbg_printk("id=%d, size=%d", id, msg->size);

    pid_connection_info_t p_conn = {};
    bpf_memcpy(&p_conn.conn, conn, sizeof(connection_info_t));

    dbg_print_http_connection_info(&p_conn.conn);
    sort_connection_info(&p_conn.conn);
    p_conn.pid = pid_from_pid_tgid(id);

    if (already_tracked(&p_conn)) {
        bpf_dbg_printk("already extended before, ignoring this packet...");
        return 0;
    }

    unsigned char **msg_ptr = bpf_map_lookup_elem(&msg_buffer_mem, &(u32){0});

    if (!msg_ptr) {
        return 0;
    }

    if (is_http_request_buf((const unsigned char *)msg_ptr)) {
        bpf_dbg_printk("setting up request to be extended");

        return 1;
    }

    return 0;
}

static __always_inline void get_connection_info(struct sk_msg_md *msg, connection_info_t *conn) {
    if (msg->family == AF_INET6) {
        sk_msg_extract_key_ip6(msg, conn);
    } else {
        sk_msg_extract_key_ip4(msg, conn);
    }
}

// this "beauty" ensures we hold pkt in the same register being range
// validated
static __always_inline unsigned char *
check_pkt_access(unsigned char *buf, //NOLINT(readability-non-const-parameter)
                 u32 offset,
                 const unsigned char *end) {
    unsigned char *ret;

    asm goto("r4 = %[buf]\n"
             "r4 += %[offset]\n"
             "if r4 > %[end] goto %l[error]\n"
             "%[ret] = %[buf]"
             : [ret] "=r"(ret)
             : [buf] "r"(buf), [end] "r"(end), [offset] "i"(offset)
             : "r4"
             : error);

    return ret;
error:
    return NULL;
}

static __always_inline void
make_tp_string_skb(unsigned char *buf, const tp_info_t *tp, const unsigned char *end) {
    buf = check_pkt_access(buf, TP_SIZE, end);

    if (!buf) {
        return;
    }

    const __attribute__((unused)) unsigned char *tp_string = buf;

    *buf++ = 'T';
    *buf++ = 'r';
    *buf++ = 'a';
    *buf++ = 'c';
    *buf++ = 'e';
    *buf++ = 'p';
    *buf++ = 'a';
    *buf++ = 'r';
    *buf++ = 'e';
    *buf++ = 'n';
    *buf++ = 't';
    *buf++ = ':';
    *buf++ = ' ';

    // Version
    *buf++ = '0';
    *buf++ = '0';
    *buf++ = '-';

    // Trace ID
    encode_hex(buf, tp->trace_id, TRACE_ID_SIZE_BYTES);
    buf += TRACE_ID_CHAR_LEN;

    *buf++ = '-';

    // SpanID
    encode_hex(buf, tp->span_id, SPAN_ID_SIZE_BYTES);
    buf += SPAN_ID_CHAR_LEN;

    *buf++ = '-';

    encode_traceparent_flags(buf, tp->flags);
    buf += FLAGS_CHAR_LEN;
    *buf++ = '\r';
    *buf++ = '\n';

    bpf_dbg_printk("tp_string=%s", tp_string);
}

static __always_inline void
make_h2_tp_hpack(unsigned char *buf, const tp_info_t *tp, const unsigned char *end) {
    buf = check_pkt_access(buf, k_h2_tp_hpack_size, end);

    if (!buf) {
        return;
    }

    *buf++ = k_hpack_literal_no_index;
    *buf++ = k_hpack_tp_name_len;

    *buf++ = 't';
    *buf++ = 'r';
    *buf++ = 'a';
    *buf++ = 'c';
    *buf++ = 'e';
    *buf++ = 'p';
    *buf++ = 'a';
    *buf++ = 'r';
    *buf++ = 'e';
    *buf++ = 'n';
    *buf++ = 't';

    *buf++ = k_hpack_value_len_tp;

    // Version
    *buf++ = '0';
    *buf++ = '0';
    *buf++ = '-';

    // Trace ID
    encode_hex(buf, tp->trace_id, TRACE_ID_SIZE_BYTES);
    buf += TRACE_ID_CHAR_LEN;

    *buf++ = '-';

    // Span ID
    encode_hex(buf, tp->span_id, SPAN_ID_SIZE_BYTES);
    buf += SPAN_ID_CHAR_LEN;

    *buf++ = '-';

    encode_traceparent_flags(buf, tp->flags);
}

enum msg_write_result : s8 {
    k_msg_write_rollback_failed = -1,
    k_msg_write_failed = 0,
    k_msg_write_succeeded = 1,
};

static __always_inline s8 extend_and_write_tp(struct sk_msg_md *msg,
                                              u32 offset,
                                              const tp_info_t *tp) {
    const long err = bpf_msg_push_data(msg, offset, TP_SIZE, 0);

    if (err != 0) {
        bpf_d_printk("failed to push data: %d [%s]", err, __FUNCTION__);
        return k_msg_write_failed;
    }

    if (bpf_msg_pull_data(msg, 0, msg->size, 0) != 0) {
        return bpf_msg_pop_data(msg, offset, TP_SIZE, 0) == 0 ? k_msg_write_failed
                                                              : k_msg_write_rollback_failed;
    }
    bpf_dbg_printk(
        "offset to split=%d, available=%u, size=%u", offset, msg->data_end - msg->data, msg->size);

    if (!msg->data) {
        bpf_d_printk("null data [%s]", __FUNCTION__);
        return bpf_msg_pop_data(msg, offset, TP_SIZE, 0) == 0 ? k_msg_write_failed
                                                              : k_msg_write_rollback_failed;
    }

    unsigned char *ptr = msg->data + offset;

    if ((void *)ptr + TP_SIZE > msg->data_end) {
        bpf_d_printk("not enough space [%s]", __FUNCTION__);
        return bpf_msg_pop_data(msg, offset, TP_SIZE, 0) == 0 ? k_msg_write_failed
                                                              : k_msg_write_rollback_failed;
    }

    make_tp_string_skb(ptr, tp, msg->data_end);

    return k_msg_write_succeeded;
}

static __always_inline s8 write_msg_traceparent(struct sk_msg_md *msg,
                                                const tp_info_t *tp,
                                                u32 *write_offset) {
    unsigned char *data = ctx_msg_data(msg);

    if (!data) {
        return k_msg_write_failed;
    }

    const u32 newline_pos = find_first_pos_of(data, ctx_msg_data_end(msg), '\n');

    if (newline_pos == INVALID_POS) {
        return k_msg_write_failed;
    }

    *write_offset = newline_pos + 1;

    return extend_and_write_tp(msg, *write_offset, tp);
}

static __always_inline bool schedule_write_tcp_option(struct sk_msg_md *msg,
                                                      const tp_info_pid_t *tp_p,
                                                      const outgoing_trace_token_t *token) {
    struct bpf_sock *sk = msg->sk;

    if (!sk) {
        return false;
    }

    sk_outgoing_trace_handoff_t *stored =
        bpf_sk_storage_get(&sk_tp_info_pid_map, sk, NULL, BPF_SK_STORAGE_GET_F_CREATE);

    if (!stored || !outgoing_trace_token_valid(token)) {
        return false;
    }

    // associate it also with this socket for the tcp options program
    stored->tp = *tp_p;
    stored->token = *token;

    return true;
}

static __always_inline void
cancel_pending_transports(struct sk_msg_md *msg, tailcall_ctx *t_ctx, const tp_info_pid_t *tp_p) {
    if (t_ctx->tcp_option_scheduled && msg->sk) {
        bpf_sk_storage_delete(&sk_tp_info_pid_map, msg->sk);
        t_ctx->tcp_option_scheduled = false;
    }
    clear_matching_pending_tp_info_pid(&t_ctx->e_key, &t_ctx->handoff_token, tp_p);
}

static __always_inline void
write_http_traceparent(struct sk_msg_md *msg, tailcall_ctx *t_ctx, const tp_info_pid_t *tp_pid) {
    // used for the upcoming tailcall
    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();

    if (!tp_p) {
        return;
    }

    *tp_p = *tp_pid;

    bpf_tail_call_static(msg, &extender_jump_table, k_tail_write_msg_traceparent);

    if (!t_ctx->tcp_option_scheduled) {
        clear_matching_pending_tp_info_pid(&t_ctx->e_key, &t_ctx->handoff_token, tp_p);
    }
    bpf_d_printk("tailcall failed [%s]", __FUNCTION__);
}

static __always_inline bool is_http2_preface(const unsigned char *d, const unsigned char *end) {
    return d && (void *)d + k_h2_preface_check_len <= (void *)end && d[0] == 'P' && d[1] == 'R' &&
           d[2] == 'I' && d[3] == ' ';
}

// Mid-stream H2 recognition for sockets whose preface predates attachment. On success
// hpack_at holds the HPACK offset of the first HEADERS frame, 0 if the buffer carried none.
static __always_inline bool sniff_http2_frames(struct sk_msg_md *msg, u32 *hpack_at) {
    const u32 msg_size = msg->size;
    u32 pos = 0;
    h2_sniff_state_t st = {0};

    *hpack_at = 0;

    for (u8 i = 0; i < k_h2_sniff_max_frames && pos < msg_size; i++) {
        if (pos + k_h2_frame_header_len > msg_size) {
            return false;
        }
        if (bpf_msg_pull_data(msg, pos, pos + k_h2_frame_header_len, 0) != 0) {
            return false;
        }
        const unsigned char *d = msg->data;
        if (!d || (void *)d + k_h2_frame_header_len > msg->data_end) {
            return false;
        }

        const u8 ftype = d[3];
        const u8 fflags = d[4];
        const bool first_headers = !st.seen_headers;

        u32 frame_len;
        if (!h2_sniff_frame_header(&st, d, &frame_len)) {
            return false;
        }

        if (ftype == k_h2_frame_headers && first_headers) {
            *hpack_at = pos + k_h2_frame_header_len + h2_hpack_prefix_len(fflags);
        }

        pos += k_h2_frame_header_len + frame_len;
    }

    return h2_sniff_accept(&st, pos, msg_size);
}

// Frame shapes alone match random bytes, so a sniffed buffer only counts as H2 once its first
// HEADERS block opens with a pseudo-header. Responses qualify: the socket is H2 either way,
// and whether the frame may be injected is decided later.
static __always_inline bool sniffed_block_is_h2(struct sk_msg_md *msg, u32 hpack_at, u32 msg_size) {
    u8 opener;

    if (!h2_headers_opener(msg, hpack_at, msg_size, &opener)) {
        return false;
    }
    if (h2_hpack_opens_response(opener)) {
        set_h2_sk_flag(msg, k_h2_sk_server);
        return true;
    }

    return h2_hpack_opens_request(opener);
}

// Skip SSL sockets — payload is encrypted, can't inject HPACK
static __noinline int wrap_http2_traceparent(struct sk_msg_md *msg,
                                             const pid_connection_info_t *p_conn) {
    if (msg->size < k_h2_frame_header_len) {
        return SK_PASS;
    }
    // A socket previously classified as non-HTTP/2 (e.g. a yamux-tunneled
    // stream) must never be injected into, regardless of what the generic
    // tracer thinks.
    if (h2_sock_state(msg) == k_h2_sock_rejected) {
        return SK_PASS;
    }
    if (is_h2_socket(msg)) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_detect_h2);
        return SK_PASS;
    }
    if (msg->size < k_h2_preface_check_len) {
        return SK_PASS;
    }
    if (bpf_msg_pull_data(msg, 0, k_h2_preface_check_len, 0) != 0) {
        return SK_PASS;
    }
    if (is_http2_preface(msg->data, msg->data_end)) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_detect_h2);
        return SK_PASS;
    }
    // known-SSL conns carry ciphertext here, a sniff false positive would corrupt TLS
    if (already_tracked_ssl_http2(p_conn)) {
        return SK_PASS;
    }
    // only route to confirmed for conns whose preface predates attach, tracked or not.
    // Own program: the frame walk inlined here costs the entry program too many
    // verifier states
    bpf_tail_call_static(msg, &extender_jump_table, k_tail_sniff_h2);
    return SK_PASS;
}

// k_tail_sniff_h2 — mid-stream H2 sniff for a socket with no preface
SEC("sk_msg")
int obi_packet_extender_sniff_h2(struct sk_msg_md *msg) {
    const u32 msg_size = msg->size;
    u32 hpack_at = 0;

    if (sniff_http2_frames(msg, &hpack_at) && hpack_at &&
        sniffed_block_is_h2(msg, hpack_at, msg_size)) {
        set_h2_sock_state(msg, k_h2_sock_confirmed);
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_detect_h2);
    }

    return SK_PASS;
}

// HTTP/1 only. Caller must skip this for H2 sockets — connection-scoped tp_pid
// carries the wrong context for multiplexed streams.
static __always_inline bool
handle_existing_tp_pid(struct sk_msg_md *msg, u64 id, tailcall_ctx *t_ctx, tp_info_pid_t *tp_pid) {
    if (tp_pid->written == k_outbound_trace_written) {
        // Only the immutable reservation can authorize this path. A completed
        // generation belongs to an earlier send and must never seed a new one.
        return true;
    }
    if (tp_pid->written != k_outbound_trace_pending) {
        return true;
    }

    bpf_msg_pull_data(msg, 0, msg->size, 0);
    fill_msg_buffers(msg, &t_ctx->p_conn, &t_ctx->e_key);
    mark_transport_handoff_expected(&t_ctx->e_key, &t_ctx->handoff_token);
    t_ctx->tcp_option_scheduled = (inject_flags & k_inject_tcp_options) &&
                                  schedule_write_tcp_option(msg, tp_pid, &t_ctx->handoff_token);

    const bool is_http = protocol_detector(msg, id, &t_ctx->p_conn.conn);
    if (is_http) {
        if (inject_flags & k_inject_http_headers) {
            write_http_traceparent(msg, t_ctx, tp_pid);
        } else if (!t_ctx->tcp_option_scheduled) {
            clear_matching_pending_tp_info_pid(&t_ctx->e_key, &t_ctx->handoff_token, tp_pid);
        }
        return true;
    }

    if (!t_ctx->tcp_option_scheduled) {
        clear_matching_pending_tp_info_pid(&t_ctx->e_key, &t_ctx->handoff_token, tp_pid);
    }
    return false;
}

// Sock_msg program which detects packets where it should add space for
// the 'Traceparent' string. It extends the HTTP header and writes the
// Traceparent string.
SEC("sk_msg")
int obi_packet_extender(struct sk_msg_md *msg) {
    // If neither injection method is enabled, nothing to do
    if (!(inject_flags & (k_inject_http_headers | k_inject_tcp_options))) {
        return SK_PASS;
    }

    tailcall_ctx *t_ctx = tailcall_ctx_mem();

    if (!t_ctx) {
        return SK_PASS;
    }

    const u64 id = bpf_get_current_pid_tgid();
    get_connection_info(msg, &t_ctx->p_conn.conn);
    sort_connection_info(&t_ctx->p_conn.conn);
    t_ctx->p_conn.pid = pid_from_pid_tgid(id);
    make_egress_key_into(&t_ctx->e_key, &t_ctx->p_conn.conn, t_ctx->p_conn.pid, 0);
    t_ctx->niter = 0;
    t_ctx->http1_tp_status = k_http1_traceparent_scan_absent;
    t_ctx->h2_scan_pos = 0;
    t_ctx->h2_frames = 0;
    t_ctx->go_h2_conn = false;
    t_ctx->h2_tp_status = k_hpack_traceparent_unknown;
    t_ctx->h2_tp_value_huffman = 0;
    t_ctx->h2_tp_representation = k_hpack_representation_unknown;
    t_ctx->h2_tp_value_len = 0;
    t_ctx->rewrite_http1_tp = false;
    t_ctx->rewrite_h2_tp = false;
    t_ctx->h2_handoff_fresh = 0;
    t_ctx->h2_hpack_scan_calls = 0;
    t_ctx->h2_hpack_scan_guard = 0;
    // Reserve the generic entry/sniff prefix pessimistically. Known H2 sockets
    // use one fewer call, but retaining that margin keeps every route bounded.
    t_ctx->h2_tail_calls = k_h2_tail_calls_before_frames;
    t_ctx->tcp_option_scheduled = false;
    t_ctx->handoff_expected = 0;
    __builtin_memset(&t_ctx->handoff_token, 0, sizeof(t_ctx->handoff_token));
    __builtin_memset(t_ctx->original_span_id, 0, sizeof(t_ctx->original_span_id));
    t_ctx->original_flags = 0;
    t_ctx->http1_span_id_offset = 0;
    t_ctx->http1_scan_pos = 0;
    t_ctx->http1_value_offset = 0;

    // skip H2 here — it uses HPACK for per-stream traceparents
    tp_info_pid_t *authoritative = (tp_info_pid_t *)tp_info_mem();
    if (authoritative && !is_h2_socket(msg) &&
        snapshot_current_outgoing_trace_handoff(&t_ctx->e_key,
                                                t_ctx->p_conn.pid,
                                                EVENT_HTTP_CLIENT,
                                                1,
                                                &t_ctx->handoff_token,
                                                authoritative,
                                                NULL)) {
        t_ctx->handoff_expected = 1;
        if (handle_existing_tp_pid(msg, id, t_ctx, authoritative)) {
            return SK_PASS;
        }
    }

    if (is_go_h2_client_conn(&t_ctx->p_conn)) {
        bpf_msg_pull_data(msg, 0, msg->size, 0);
        fill_msg_buffers(msg, &t_ctx->p_conn, &t_ctx->e_key);
        t_ctx->go_h2_conn = true;
        return wrap_http2_traceparent(msg, &t_ctx->p_conn);
    }

    if (!valid_pid(id)) {
        return SK_PASS;
    }

    bpf_msg_pull_data(msg, 0, msg->size, 0);
    fill_msg_buffers(msg, &t_ctx->p_conn, &t_ctx->e_key);

    if (is_h2_socket(msg)) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_detect_h2);
        return SK_PASS;
    }

    if (msg->size <= MIN_HTTP_SIZE) {
        return SK_PASS;
    }

    bpf_dbg_printk("MSG=%llx:%d ->", t_ctx->p_conn.conn.s_ip[3], t_ctx->p_conn.conn.s_port);
    bpf_dbg_printk("MSG TO=%llx:%d", t_ctx->p_conn.conn.d_ip[3], t_ctx->p_conn.conn.d_port);
    bpf_dbg_printk("MSG SIZE=%u", msg->size);

    const bool is_http = protocol_detector(msg, id, &t_ctx->p_conn.conn);
    if (is_http) {
        bpf_dbg_printk("len=%d, s_port=%d", msg->size, msg->local_port);
        init_tp_ctx_parent_tp(t_ctx);
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_find_existing_tp);
        return SK_PASS;
    }

    return wrap_http2_traceparent(msg, &t_ctx->p_conn);
}

//k_tail_write_msg_traceparent
SEC("sk_msg")
int obi_packet_extender_write_msg_tp(struct sk_msg_md *msg) {
    bpf_dbg_printk("=== sk_msg ===");

    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    if (!t_ctx) {
        return SK_PASS;
    }

    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();

    if (!tp_p) {
        bpf_dbg_printk("empty tp_buf");
        return SK_PASS;
    }

    if (!claim_outgoing_trace_handoff(&t_ctx->e_key,
                                      &t_ctx->handoff_token,
                                      t_ctx->p_conn.pid,
                                      EVENT_HTTP_CLIENT,
                                      tp_p,
                                      0,
                                      1,
                                      NULL)) {
        cancel_pending_transports(msg, t_ctx, tp_p);
        return SK_PASS;
    }

    u32 write_offset = 0;
    const s8 write_result = write_msg_traceparent(msg, &tp_p->tp, &write_offset);
    if (write_result != k_msg_write_succeeded) {
        release_claimed_outgoing_trace_handoff(&t_ctx->e_key, &t_ctx->handoff_token);
        if (write_result == k_msg_write_rollback_failed) {
            cancel_pending_transports(msg, t_ctx, tp_p);
        } else if (!t_ctx->tcp_option_scheduled) {
            clear_matching_pending_tp_info_pid(&t_ctx->e_key, &t_ctx->handoff_token, tp_p);
        }
        bpf_d_printk("failed to write traceparent [%s]", __FUNCTION__);
        return write_result == k_msg_write_rollback_failed ? SK_DROP : SK_PASS;
    }

    commit_claimed_outgoing_trace_handoff(&t_ctx->e_key, &t_ctx->handoff_token);
    mirror_outgoing_trace_handoff_commit(&t_ctx->e_key, tp_p);
    tp_p->written = k_outbound_trace_written;

    print_tp("written TP to headers", &tp_p->tp);
    bpf_dbg_printk("BUF=[%s]", msg->data);

    return SK_PASS;
}

// Stitches the parsed wire tp into the in-process trace context. Returns true
// when a proxy was just forwarding our own header — caller must overwrite the
// span_id on the wire to keep the child distinct from the parent
static __always_inline bool apply_parent_tp(const tailcall_ctx *t_ctx, tp_info_t *tp) {
    if (!t_ctx->has_parent_tp ||
        bpf_memcmp(tp->trace_id, t_ctx->parent_tp.trace_id, TRACE_ID_SIZE_BYTES) != 0) {
        return false;
    }
    bpf_memcpy(tp->parent_id, t_ctx->parent_tp.span_id, SPAN_ID_SIZE_BYTES);
    if (bpf_memcmp(tp->span_id, t_ctx->parent_tp.parent_id, SPAN_ID_SIZE_BYTES) != 0) {
        return false;
    }
    inherit_parent_sampling_state(tp, &t_ctx->parent_tp);
    urand_bytes(tp->span_id, SPAN_ID_SIZE_BYTES);
    return true;
}

static __always_inline bool assign_parent_tp(const tailcall_ctx *t_ctx, tp_info_t *tp) {
    if (!apply_parent_tp(t_ctx, tp)) {
        return false;
    }
    bpf_dbg_printk("detected forwarded TP header, overriding span id");
    return true;
}

static __always_inline int abort_http1_traceparent(tailcall_ctx *t_ctx, const tp_info_pid_t *tp_p) {
    if (!t_ctx->tcp_option_scheduled) {
        clear_matching_pending_tp_info_pid(&t_ctx->e_key, &t_ctx->handoff_token, tp_p);
    }
    return SK_PASS;
}

static __always_inline u8 write_http1_existing_traceparent(struct sk_msg_md *msg,
                                                           const tailcall_ctx *t_ctx,
                                                           const tp_info_t *tp) {
    const u32 span_id_offset = t_ctx->http1_span_id_offset;
    if (span_id_offset > 4096 - k_traceparent_span_flags_wire_len ||
        bpf_msg_pull_data(
            msg, span_id_offset, span_id_offset + k_traceparent_span_flags_wire_len, 0) != 0) {
        return 0;
    }
    unsigned char *data = msg->data;
    const unsigned char *end = msg->data_end;
    if (!data || (void *)data + k_traceparent_span_flags_wire_len > (void *)end) {
        return 0;
    }
    write_traceparent_span_flags(data, tp->span_id, tp->flags);
    return 1;
}

static __always_inline int
finish_http1_traceparent_scan(struct sk_msg_md *msg, tailcall_ctx *t_ctx, tp_info_pid_t *tp_p) {
    const enum http1_injection_scan_action action =
        http1_injection_scan_action(t_ctx->http1_tp_status, 1, 0);
    if (action == k_http1_injection_scan_create) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_create_tp);
        return abort_http1_traceparent(t_ctx, tp_p);
    }
    if (action != k_http1_injection_scan_finalize) {
        return abort_http1_traceparent(t_ctx, tp_p);
    }

    bpf_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));
    preserve_outbound_traceparent(&tp_p->tp);
    __builtin_memcpy(t_ctx->original_span_id, tp_p->tp.span_id, sizeof(t_ctx->original_span_id));
    t_ctx->original_flags = tp_p->tp.flags;
    t_ctx->rewrite_http1_tp = assign_parent_tp(t_ctx, &tp_p->tp);

    if (t_ctx->rewrite_http1_tp) {
        apply_sampling_decision(&tp_p->tp, 1, 0);
    }
    tp_p->tp.ts = bpf_ktime_get_ns();
    tp_p->valid = 1;
    tp_p->written = k_outbound_trace_pending;
    tp_p->pid = t_ctx->p_conn.pid;
    tp_p->req_type = EVENT_HTTP_CLIENT;
    if (!reserve_transport_handoff(&t_ctx->e_key, tp_p, &t_ctx->handoff_token)) {
        if (t_ctx->rewrite_http1_tp) {
            restore_outbound_traceparent(&tp_p->tp, t_ctx->original_span_id, t_ctx->original_flags);
        }
        return SK_PASS;
    }
    t_ctx->handoff_expected = 1;
    bpf_tail_call_static(msg, &extender_jump_table, k_tail_finalize_existing_tp);
    if (!t_ctx->tcp_option_scheduled) {
        clear_matching_pending_tp_info_pid(&t_ctx->e_key, &t_ctx->handoff_token, tp_p);
    }
    if (t_ctx->rewrite_http1_tp) {
        restore_outbound_traceparent(&tp_p->tp, t_ctx->original_span_id, t_ctx->original_flags);
    }
    return SK_PASS;
}

static __noinline s32 http1_candidate_value_offset(const unsigned char *header,
                                                   const unsigned char *end) {
    if (!is_traceparent_name(header)) {
        return 0;
    }
    if (header + k_http1_traceparent_name_field_len + k_http_traceparent_ows_scan + 1 > end) {
        return -1;
    }

    const u8 value_offset = http_traceparent_value_offset(header);
    return !value_offset || value_offset == k_http_traceparent_value_offset_unknown ? -1
                                                                                    : value_offset;
}

//k_tail_find_existing_tp
SEC("sk_msg")
int obi_packet_extender_find_existing_tp(struct sk_msg_md *msg) {
    enum {
        k_max_scan_size = 4096,
        // 22 scanner calls cover 4 KiB and leave tail-call budget for validation and writes.
        k_max_chunk_size = 192,
    };

    tailcall_ctx *t_ctx = tailcall_ctx_mem();

    if (!t_ctx) {
        return SK_PASS;
    }

    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();

    if (!tp_p) {
        return SK_PASS;
    }
    reset_sampling_decision(&tp_p->tp);

    u32 scan_pos = t_ctx->http1_scan_pos;
    if (scan_pos >= k_max_scan_size) {
        return abort_http1_traceparent(t_ctx, tp_p);
    }
    bpf_clamp_umax(scan_pos, k_max_scan_size - 1);

    unsigned char *b = msg->data;
    const unsigned char *e = msg->data_end;
    unsigned char *ptr = b + scan_pos;

    bpf_dbg_printk("looking for traceparent header (iter=%u)", t_ctx->niter);

    if (ptr + 1 > e) {
        return abort_http1_traceparent(t_ctx, tp_p);
    }

    u32 data_size = e - ptr;

    if (data_size > k_max_chunk_size) {
        data_size = k_max_chunk_size;
    }
    if (data_size > k_max_scan_size - scan_pos) {
        data_size = k_max_scan_size - scan_pos;
    }

    for (u32 i = 0; i < data_size; ++i) {
        if (ptr + 1 > e) {
            break;
        }
        if (ptr + 4 <= e && is_eoh(ptr)) {
            return finish_http1_traceparent_scan(msg, t_ctx, tp_p);
        }

        unsigned char *header = ptr + 1;
        if (*ptr == '\n' && header + k_http1_traceparent_name_field_len <= e) {
            const s32 value_offset = http1_candidate_value_offset(header, e);
            if (value_offset < 0) {
                http1_injection_observe_traceparent(&t_ctx->http1_tp_status, 0);
                return abort_http1_traceparent(t_ctx, tp_p);
            }
            if (!value_offset) {
                ++ptr;
                continue;
            }
            if (header + value_offset + k_http1_traceparent_value_len + 2 > e) {
                http1_injection_observe_traceparent(&t_ctx->http1_tp_status, 0);
                return abort_http1_traceparent(t_ctx, tp_p);
            }

            t_ctx->http1_value_offset = header - b + value_offset;
            t_ctx->http1_scan_pos = ptr - b + 1;
            t_ctx->niter++;
            bpf_tail_call_static(msg, &extender_jump_table, k_tail_validate_existing_tp);
            http1_injection_observe_traceparent(&t_ctx->http1_tp_status, 0);
            return abort_http1_traceparent(t_ctx, tp_p);
        }

        ++ptr;
    }

    t_ctx->http1_scan_pos = scan_pos + data_size;
    t_ctx->niter++;

    const enum http1_injection_scan_action action = http1_injection_scan_action(
        t_ctx->http1_tp_status, 0, t_ctx->http1_scan_pos >= k_max_scan_size);
    if (action == k_http1_injection_scan_continue) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_find_existing_tp);
    }

    return abort_http1_traceparent(t_ctx, tp_p);
}

// Validate one located HTTP/1 candidate outside the bounded byte scanner.
SEC("sk_msg")
int obi_packet_extender_validate_existing_tp(struct sk_msg_md *msg) {
    enum {
        k_http1_tp_wire_len = k_http1_traceparent_value_len + 2,
        k_http1_max_value_offset =
            4096 + k_http1_traceparent_name_field_len + k_http_traceparent_ows_scan,
    };

    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    if (!t_ctx) {
        return SK_PASS;
    }
    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();
    if (!tp_p) {
        return SK_PASS;
    }
    unsigned char *value = tp_str_buf_mem();
    if (!value) {
        return abort_http1_traceparent(t_ctx, tp_p);
    }

    u32 value_offset = t_ctx->http1_value_offset;
    if (value_offset > k_http1_max_value_offset) {
        http1_injection_observe_traceparent(&t_ctx->http1_tp_status, 0);
        return abort_http1_traceparent(t_ctx, tp_p);
    }
    bpf_clamp_umax(value_offset, k_http1_max_value_offset);

    if (bpf_msg_pull_data(msg, value_offset, value_offset + k_http1_tp_wire_len, 0) != 0) {
        http1_injection_observe_traceparent(&t_ctx->http1_tp_status, 0);
        return abort_http1_traceparent(t_ctx, tp_p);
    }

    const unsigned char *data = msg->data;
    const unsigned char *end = msg->data_end;
    if (!data) {
        http1_injection_observe_traceparent(&t_ctx->http1_tp_status, 0);
        return abort_http1_traceparent(t_ctx, tp_p);
    }
    if (data + k_http1_tp_wire_len > end ||
        bpf_probe_read_kernel(value, k_http1_tp_wire_len, data)) {
        http1_injection_observe_traceparent(&t_ctx->http1_tp_status, 0);
        return abort_http1_traceparent(t_ctx, tp_p);
    }

    if (!valid_http_traceparent_value(value, value[k_http1_traceparent_value_len]) ||
        value[0] != '0' || value[1] != '0' || value[k_http1_traceparent_value_len] != '\r' ||
        value[k_http1_traceparent_value_len + 1] != '\n') {
        http1_injection_observe_traceparent(&t_ctx->http1_tp_status, 0);
        return abort_http1_traceparent(t_ctx, tp_p);
    }
    if (!http1_injection_observe_traceparent(&t_ctx->http1_tp_status, 1)) {
        return abort_http1_traceparent(t_ctx, tp_p);
    }

    const unsigned char *trace_id = value + k_tp_val_trace_id_start;
    const unsigned char *span_id = trace_id + TRACE_ID_CHAR_LEN + 1;
    const unsigned char *flags = span_id + SPAN_ID_CHAR_LEN + 1;
    decode_hex(tp_p->tp.trace_id, trace_id, TRACE_ID_CHAR_LEN);
    decode_hex(tp_p->tp.span_id, span_id, SPAN_ID_CHAR_LEN);
    decode_hex((unsigned char *)&tp_p->tp.flags, flags, FLAGS_CHAR_LEN);
    tp_p->tp.flags = traceparent_flags_for_version(value, tp_p->tp.flags);
    t_ctx->http1_span_id_offset = value_offset + k_tp_val_span_id_start;

    if (bpf_msg_pull_data(msg, 0, msg->size, 0) != 0) {
        return abort_http1_traceparent(t_ctx, tp_p);
    }
    bpf_tail_call_static(msg, &extender_jump_table, k_tail_find_existing_tp);
    return abort_http1_traceparent(t_ctx, tp_p);
}

// k_tail_finalize_existing_tp
SEC("sk_msg")
int obi_packet_extender_finalize_existing_tp(struct sk_msg_md *msg) {
    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    if (!t_ctx) {
        return SK_PASS;
    }

    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();
    if (!tp_p) {
        return SK_PASS;
    }

    if (!claim_outgoing_trace_handoff(&t_ctx->e_key,
                                      &t_ctx->handoff_token,
                                      t_ctx->p_conn.pid,
                                      EVENT_HTTP_CLIENT,
                                      tp_p,
                                      0,
                                      1,
                                      NULL)) {
        return SK_PASS;
    }

    u8 wire_rewritten = 0;
    if (t_ctx->rewrite_http1_tp) {
        wire_rewritten = write_http1_existing_traceparent(msg, t_ctx, &tp_p->tp);
        if (wire_rewritten) {
            commit_outbound_traceparent(&tp_p->tp);
        } else {
            release_claimed_outgoing_trace_handoff(&t_ctx->e_key, &t_ctx->handoff_token);
            clear_matching_pending_tp_info_pid(&t_ctx->e_key, &t_ctx->handoff_token, tp_p);
            restore_outbound_traceparent(&tp_p->tp, t_ctx->original_span_id, t_ctx->original_flags);
            tp_p->written = k_outbound_trace_pending;
            if (!reserve_transport_handoff(&t_ctx->e_key, tp_p, &t_ctx->handoff_token)) {
                return SK_PASS;
            }
            if (!claim_outgoing_trace_handoff(&t_ctx->e_key,
                                              &t_ctx->handoff_token,
                                              t_ctx->p_conn.pid,
                                              EVENT_HTTP_CLIENT,
                                              tp_p,
                                              0,
                                              1,
                                              NULL)) {
                return SK_PASS;
            }
        }
    }

    tp_p->valid = 1;
    tp_p->written = k_outbound_trace_pending;
    tp_p->pid = t_ctx->p_conn.pid;
    tp_p->req_type = EVENT_HTTP_CLIENT;

    print_tp("found TP in headers", &tp_p->tp);
    commit_claimed_outgoing_trace_handoff(&t_ctx->e_key, &t_ctx->handoff_token);
    mirror_outgoing_trace_handoff_commit(&t_ctx->e_key, tp_p);
    tp_p->written = k_outbound_trace_written;

    if (inject_flags & k_inject_tcp_options) {
        t_ctx->tcp_option_scheduled = schedule_write_tcp_option(msg, tp_p, &t_ctx->handoff_token);
    }

    return SK_PASS;
}

//k_tail_create_tp
SEC("sk_msg")
int obi_packet_extender_create_tp(struct sk_msg_md *msg) {
    tailcall_ctx *t_ctx = tailcall_ctx_mem();

    if (!t_ctx) {
        return SK_PASS;
    }

    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();

    if (!tp_p) {
        return SK_PASS;
    }

    if (!create_trace_info(t_ctx, tp_p)) {
        return SK_PASS;
    }

    tp_p->written = k_outbound_trace_pending;

    // Reserve a non-evicting handoff before either transport can mutate bytes.
    if (!reserve_transport_handoff(&t_ctx->e_key, tp_p, &t_ctx->handoff_token)) {
        return SK_PASS;
    }
    t_ctx->handoff_expected = 1;

    if (inject_flags & k_inject_tcp_options) {
        t_ctx->tcp_option_scheduled = schedule_write_tcp_option(msg, tp_p, &t_ctx->handoff_token);
    }

    if (inject_flags & k_inject_http_headers) {
        // write the HTTP headers
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_write_msg_traceparent);
        if (!t_ctx->tcp_option_scheduled) {
            clear_matching_pending_tp_info_pid(&t_ctx->e_key, &t_ctx->handoff_token, tp_p);
        }
        bpf_d_printk("tailcall failed [%s]", __FUNCTION__);
    } else if (!t_ctx->tcp_option_scheduled) {
        clear_matching_pending_tp_info_pid(&t_ctx->e_key, &t_ctx->handoff_token, tp_p);
    }

    return SK_PASS;
}

// k_tail_detect_h2 — scan for HEADERS+END_HEADERS, tail-call the inject
// chain. Resumes across tail calls via h2_scan_pos so senders that pack
// multiple HEADERS frames into one sendmsg get every stream injected
SEC("sk_msg")
int obi_packet_extender_detect_h2(struct sk_msg_md *msg) {
    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    if (!t_ctx) {
        return SK_PASS;
    }

    if (t_ctx->h2_frames >= k_h2_max_frames_per_packet) {
        return SK_PASS;
    }

    // Read msg->size once: repeated reads confuse the sk_msg verifier
    const u32 msg_size = msg->size;

    u32 pos = t_ctx->h2_scan_pos;

    u8 state = h2_sock_state(msg);
    if (state == k_h2_sock_rejected) {
        return SK_PASS;
    }

    // Only check the preface on the first scan of a packet (scan_pos == 0) and
    // only before we've classified the socket. Go gRPC sends the 24-byte
    // preface in its own packet, before any HEADERS frame.
    if (pos == 0 && state == k_h2_sock_none && msg_size >= k_h2_preface_check_len) {
        if (bpf_msg_pull_data(msg, 0, k_h2_preface_check_len, 0) == 0) {
            if (is_http2_preface(msg->data, msg->data_end)) {
                // Preface seen, but NOT yet genuine HTTP/2: RFC 7540 §3.5
                // requires a SETTINGS frame to follow. We confirm that below
                // (possibly on the next packet) before ever injecting.
                state = k_h2_sock_preface;
                set_h2_sock_state(msg, k_h2_sock_preface);
                if (msg_size >= k_h2_preface_len + k_h2_frame_header_len) {
                    pos = k_h2_preface_len; // SETTINGS may be coalesced here
                } else {
                    return SK_PASS; // preface-only packet; SETTINGS comes next
                }
            }
        }
    }

    if (msg_size < k_h2_frame_header_len || pos >= msg_size) {
        return SK_PASS;
    }

    // Awaiting the mandatory post-preface SETTINGS frame. If the next frame on
    // the raw socket is not SETTINGS, the "preface" was just payload of some
    // other protocol multiplexed over this connection (e.g. Gitaly's yamux
    // backchannel, GitHub issue #2706). Reject the socket so we never splice HPACK
    // into it — doing so would shift the outer framing and corrupt the stream.
    if (state == k_h2_sock_preface) {
        h2_frame_info_t sf;
        if (!parse_h2_frame_at(msg, pos, msg_size, &sf)) {
            // Not enough bytes to decide yet; wait for the next packet without
            // committing to confirmed or rejected.
            return SK_PASS;
        }
        if (sf.ftype != k_h2_frame_settings) {
            set_h2_sock_state(msg, k_h2_sock_rejected);
            return SK_PASS;
        }
        set_h2_sock_state(msg, k_h2_sock_confirmed);
        state = k_h2_sock_confirmed;
        // Continue after the SETTINGS frame in case HEADERS were coalesced.
        pos += k_h2_frame_header_len + sf.payload_len;
        if (msg_size < k_h2_frame_header_len || pos >= msg_size) {
            return SK_PASS;
        }
    }

    // Only a confirmed genuine-HTTP/2 socket may be injected into.
    if (state != k_h2_sock_confirmed) {
        return SK_PASS;
    }

    // responses were seen here, so nothing on this socket is ever injectable
    if (h2_sk_flag(msg, k_h2_sk_server)) {
        return SK_PASS;
    }

    // Scan up to 4 frames for HEADERS+END_HEADERS
    for (u8 i = 0; i < k_h2_max_frame_scan; i++) {
        h2_frame_info_t f;
        if (!parse_h2_frame_at(msg, pos, msg_size, &f)) {
            return SK_PASS;
        }
        if (f.is_headers_end) {
            h2_inject_facts_t facts = {0};
            facts.opener_readable =
                h2_headers_opener(msg, f.hpack_offset_in_msg, msg_size, &facts.opener);

            if (facts.opener_readable && h2_hpack_opens_response(facts.opener)) {
                set_h2_sk_flag(msg, k_h2_sk_server);
            }
            facts.sk_server = h2_sk_flag(msg, k_h2_sk_server);

            if (h2_inject_verdict(&facts) != k_h2_inject_allow) {
                h2_resume_after(msg, t_ctx, pos + k_h2_frame_header_len + f.payload_len);
                return SK_PASS;
            }

            t_ctx->e_key.stream_id = f.stream_id;
            t_ctx->h2_frame_offset = pos;
            t_ctx->h2_payload_len = f.payload_len;
            t_ctx->h2_hpack_offset = f.hpack_offset_in_msg;
            t_ctx->h2_hpack_len = f.hpack_len;
            t_ctx->tp_present = false;
            t_ctx->scan_exhausted = f.hpack_len > k_h2_max_hpack_scan;
            t_ctx->rewrite_h2_tp = false;
            t_ctx->opener = facts.opener;
            t_ctx->h2_hpack_scan_calls = 0;
            t_ctx->h2_hpack_scan_guard = 0;

            // Resolve every parsed stream independently. A send-level token is
            // ambiguous when multiple HEADERS frames share one sendmsg.
            t_ctx->handoff_expected = 0;
            t_ctx->h2_handoff_fresh = 0;
            __builtin_memset(&t_ctx->handoff_token, 0, sizeof(t_ctx->handoff_token));
            tp_info_pid_t *stream_tp = (tp_info_pid_t *)tp_info_mem();
            if (!stream_tp) {
                return SK_PASS;
            }
            const u8 resolution = resolve_current_outgoing_trace_handoff(&t_ctx->e_key,
                                                                         t_ctx->p_conn.pid,
                                                                         EVENT_HTTP_CLIENT,
                                                                         1,
                                                                         &t_ctx->handoff_token,
                                                                         stream_tp,
                                                                         NULL);
            if (resolution == k_outgoing_trace_fail_closed ||
                (resolution == k_outgoing_trace_absent && t_ctx->go_h2_conn)) {
                h2_resume_after(msg, t_ctx, pos + k_h2_frame_header_len + f.payload_len);
                return SK_PASS;
            }
            if (resolution == k_outgoing_trace_exact) {
                t_ctx->handoff_expected = 1;
                if (stream_tp->written == k_outbound_trace_written) {
                    h2_resume_after(msg, t_ctx, pos + k_h2_frame_header_len + f.payload_len);
                    return SK_PASS;
                }
                if (stream_tp->written != k_outbound_trace_pending) {
                    h2_resume_after(msg, t_ctx, pos + k_h2_frame_header_len + f.payload_len);
                    return SK_PASS;
                }
            }

            t_ctx->h2_tp_candidate_pos = 0;
            t_ctx->h2_tp_value_len = 0;
            t_ctx->h2_tp_status = k_hpack_traceparent_unknown;
            t_ctx->h2_tp_value_huffman = 0;
            t_ctx->h2_tp_representation = k_hpack_representation_unknown;
            if (h2_take_tail_call(t_ctx)) {
                bpf_tail_call_static(msg, &extender_jump_table, k_tail_find_existing_h2_tp);
            }
            return SK_PASS;
        }

        pos += k_h2_frame_header_len + f.payload_len;
    }

    // more frames than one pass can walk: carry on rather than dropping the packet
    if (pos < msg_size) {
        h2_resume_after(msg, t_ctx, pos);
    }

    return SK_PASS;
}

enum {
    // Fifteen parser calls stay below the oldest supported verifier's state
    // ceiling. One authenticated continuation program repeats that slice
    // until the complete 247-byte window is consumed.
    k_h2_hpack_scan_steps_per_call = 15,
    k_h2_hpack_max_scan_calls =
        (k_hpack_tp_max_scan + k_h2_hpack_scan_steps_per_call - 1) / k_h2_hpack_scan_steps_per_call,
    k_h2_hpack_max_completed_scan_calls =
        (k_h2_hpack_max_scan_calls - 1) * k_h2_hpack_scan_steps_per_call,
    k_tpinjector_hpack_decode_steps_per_call = 32,
    k_tpinjector_hpack_decode_calls_per_validation = 3,
};

_Static_assert(k_h2_hpack_max_scan_calls - 1 == k_h2_hpack_max_scan_tail_calls,
               "H2 parser continuation accounting is stale");
_Static_assert(
    k_tpinjector_hpack_decode_steps_per_call *k_tpinjector_hpack_decode_calls_per_validation >=
        k_hpack_value_len_tp + 1,
    "one validation cannot reach a raw future-version extension");

static __always_inline u8
h2_hpack_resume_state_valid(const hpack_traceparent_scan_state_t *state,
                            const hpack_dynamic_name_state_t *dynamic_names,
                            u32 minimum_pos) {
    if (state->done || !state->data_len || state->data_len > k_hpack_tp_max_scan ||
        state->pos < minimum_pos || state->pos >= state->data_len ||
        state->phase > k_hpack_scan_integer_value_length || state->integer_shift > 28 ||
        state->pending_representation > k_hpack_representation_never_indexed ||
        state->pending_name_classification > k_hpack_name_non_traceparent ||
        state->pending_name_size > k_hpack_max_ephemeral_decoded_string ||
        state->pending_string_decoded_size > k_hpack_max_ephemeral_decoded_string ||
        state->pending_name_size_known > 1 || state->pending_huffman > 1 ||
        state->pending_string_start > state->pending_string_end ||
        state->pending_string_end > state->data_len || state->table_size_updates > 2 ||
        state->complete || state->unknown || state->dynamic_invalid || state->saw_header > 1 ||
        state->traceparent_fields > 1 || state->status != k_hpack_traceparent_absent ||
        state->value_huffman > 1 || state->representation > k_hpack_representation_never_indexed ||
        !hpack_dynamic_name_state_bounds_valid(dynamic_names)) {
        return 0;
    }
    return 1;
}

static __noinline u8 h2_hpack_initial_scan_chunk(const unsigned char *data,
                                                 hpack_traceparent_scan_state_t *state,
                                                 hpack_dynamic_name_state_t *dynamic_names) {
#pragma clang loop unroll(disable)
    for (u8 step = 0; step < k_h2_hpack_scan_steps_per_call; step++) {
        if (hpack_traceparent_scan_step(data, state, dynamic_names)) {
            return 1;
        }
    }
    return 0;
}

static __always_inline u8 h2_hpack_scan_guard_value(const hpack_traceparent_scan_state_t *state,
                                                    u8 completed_calls) {
    return completed_calls ^ state->pos ^ state->data_len ^ 0xa5;
}

static __noinline void h2_hpack_decode_chunk(const unsigned char *data,
                                             hpack_traceparent_decoder_state_t *state,
                                             tp_info_t *tp) {
#pragma clang loop unroll(disable)
    for (u8 step = 0; step < k_tpinjector_hpack_decode_steps_per_call; step++) {
        if (hpack_traceparent_decoder_step(data, state, tp)) {
            return;
        }
    }
    if (state->huffman && state->value.value_len > k_hpack_value_len_tp &&
        state->encoded_pos < state->encoded_len) {
        hpack_traceparent_skip_huffman_suffix(data, state, tp);
    }
}

static __always_inline int h2_validate_existing_traceparent(struct sk_msg_md *msg,
                                                            tailcall_ctx *t_ctx);

static __always_inline u8 h2_hpack_start_scan(struct sk_msg_md *msg,
                                              const u32 hpack_start,
                                              const u32 hpack_len,
                                              hpack_traceparent_scan_state_t *state,
                                              hpack_dynamic_name_state_t *dynamic_names) {
    if (!hpack_len) {
        state->status = k_hpack_traceparent_absent;
        state->done = 1;
        return 1;
    }
    hpack_traceparent_scan_init(state, hpack_len, 1);
    if (state->done) {
        return 1;
    }

    const u32 pull_len = hpack_len;
    if (bpf_msg_pull_data(msg, hpack_start, hpack_start + pull_len, 0) != 0) {
        return hpack_traceparent_scan_fail(state);
    }

    const unsigned char *data = msg->data;
    const unsigned char *end = msg->data_end;
    if (!data) {
        return hpack_traceparent_scan_fail(state);
    }
    const unsigned char *hpack = data;
    if (hpack + pull_len > end) {
        return hpack_traceparent_scan_fail(state);
    }

    unsigned char *scratch = h2_hpack_buf_mem();
    if (!scratch || bpf_probe_read_kernel(scratch, pull_len, hpack)) {
        return hpack_traceparent_scan_fail(state);
    }

    hpack_dynamic_name_state_init(dynamic_names);
    return h2_hpack_initial_scan_chunk(scratch, state, dynamic_names);
}

static __always_inline void h2_store_traceparent_scan(tailcall_ctx *t_ctx,
                                                      const hpack_traceparent_scan_state_t *state) {
    const hpack_traceparent_result_t result = hpack_traceparent_scan_result(state);
    t_ctx->h2_tp_status = result.status;
    t_ctx->h2_tp_value_huffman = result.value_huffman;
    t_ctx->h2_tp_representation = result.representation;
    t_ctx->h2_tp_value_len = result.encoded_value_len;
    t_ctx->h2_tp_candidate_pos =
        result.status == k_hpack_traceparent_found ? result.value_offset : k_h2_max_hpack_scan;
    hpack_traceparent_decoder_state_t *decoder = h2_hpack_decoder_state_mem();
    if (decoder) {
        __builtin_memset(decoder, 0, sizeof(*decoder));
    }
}

static __always_inline void h2_publish_traceparent_scan(
    struct sk_msg_md *msg, tailcall_ctx *t_ctx, const hpack_traceparent_scan_state_t *state) {
    t_ctx->h2_hpack_scan_calls = 0;
    t_ctx->h2_hpack_scan_guard = 0;
    h2_store_traceparent_scan(t_ctx, state);
    if (h2_take_tail_call(t_ctx)) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_validate_h2_tp);
    }
}

SEC("sk_msg")
int obi_packet_extender_find_existing_h2_tp(struct sk_msg_md *msg) {
    bpf_dbg_printk("=== sk_msg find existing h2 tp ===");
    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    if (!t_ctx) {
        return SK_PASS;
    }
    t_ctx->h2_hpack_scan_calls = 0;
    t_ctx->h2_hpack_scan_guard = 0;
    hpack_traceparent_scan_state_t state = {};
    hpack_dynamic_name_state_t *dynamic_names = h2_hpack_dynamic_names_mem();
    if (!dynamic_names) {
        hpack_traceparent_scan_fail(&state);
        h2_publish_traceparent_scan(msg, t_ctx, &state);
        return SK_PASS;
    }
    if (h2_hpack_start_scan(
            msg, t_ctx->h2_hpack_offset, t_ctx->h2_hpack_len, &state, dynamic_names)) {
        h2_publish_traceparent_scan(msg, t_ctx, &state);
        return SK_PASS;
    }

    hpack_traceparent_scan_state_t *saved = h2_hpack_scan_state_mem();
    if (!saved) {
        hpack_traceparent_scan_fail(&state);
        h2_publish_traceparent_scan(msg, t_ctx, &state);
        return SK_PASS;
    }
    t_ctx->h2_hpack_scan_calls = k_h2_hpack_scan_steps_per_call;
    t_ctx->h2_hpack_scan_guard = h2_hpack_scan_guard_value(&state, k_h2_hpack_scan_steps_per_call);
    *saved = state;
    if (h2_take_tail_call(t_ctx)) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_continue_existing_h2_tp);
    }
    hpack_traceparent_scan_fail(&state);
    h2_publish_traceparent_scan(msg, t_ctx, &state);
    return SK_PASS;
}

SEC("sk_msg")
int obi_packet_extender_continue_existing_h2_tp(struct sk_msg_md *msg) {
    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    unsigned char *scratch = h2_hpack_buf_mem();
    hpack_dynamic_name_state_t *dynamic_names = h2_hpack_dynamic_names_mem();
    hpack_traceparent_scan_state_t *saved = h2_hpack_scan_state_mem();
    if (!t_ctx || !scratch || !dynamic_names || !saved) {
        if (t_ctx) {
            t_ctx->h2_hpack_scan_calls = 0;
            t_ctx->h2_hpack_scan_guard = 0;
        }
        return SK_PASS;
    }

    hpack_traceparent_scan_state_t state = *saved;
    const u8 completed_calls = t_ctx->h2_hpack_scan_calls;
    if (completed_calls < k_h2_hpack_scan_steps_per_call ||
        completed_calls > k_h2_hpack_max_completed_scan_calls ||
        completed_calls % k_h2_hpack_scan_steps_per_call ||
        t_ctx->h2_hpack_scan_guard != h2_hpack_scan_guard_value(&state, completed_calls) ||
        !h2_hpack_resume_state_valid(&state, dynamic_names, completed_calls)) {
        hpack_traceparent_scan_fail(&state);
        h2_publish_traceparent_scan(msg, t_ctx, &state);
        return SK_PASS;
    }
    const u8 done = h2_hpack_initial_scan_chunk(scratch, &state, dynamic_names);
    if (!done) {
        if (completed_calls >
            k_h2_hpack_max_completed_scan_calls - k_h2_hpack_scan_steps_per_call) {
            hpack_traceparent_scan_fail(&state);
            h2_publish_traceparent_scan(msg, t_ctx, &state);
            return SK_PASS;
        }
        const u8 next_completed_calls = completed_calls + k_h2_hpack_scan_steps_per_call;
        t_ctx->h2_hpack_scan_calls = next_completed_calls;
        t_ctx->h2_hpack_scan_guard = h2_hpack_scan_guard_value(&state, next_completed_calls);
        *saved = state;
        if (h2_take_tail_call(t_ctx)) {
            bpf_tail_call_static(msg, &extender_jump_table, k_tail_continue_existing_h2_tp);
        }
        hpack_traceparent_scan_fail(&state);
    }
    h2_publish_traceparent_scan(msg, t_ctx, &state);
    return SK_PASS;
}

static __always_inline u8 write_h2_existing_traceparent(struct sk_msg_md *msg,
                                                        const u32 span_id_offset,
                                                        const unsigned char *span_id,
                                                        const u8 flags) {
    if (bpf_msg_pull_data(
            msg, span_id_offset, span_id_offset + k_traceparent_span_flags_wire_len, 0) != 0) {
        return 0;
    }
    unsigned char *data = msg->data;
    const unsigned char *end = msg->data_end;
    if (!data || (void *)data + k_traceparent_span_flags_wire_len > (void *)end) {
        return 0;
    }
    write_traceparent_span_flags(data, span_id, flags);
    return 1;
}

static __always_inline int
h2_claim_existing_traceparent(struct sk_msg_md *msg, tailcall_ctx *t_ctx, tp_info_pid_t *tp_p) {
    if (!claim_outgoing_trace_handoff(&t_ctx->e_key,
                                      &t_ctx->handoff_token,
                                      t_ctx->p_conn.pid,
                                      EVENT_HTTP_CLIENT,
                                      tp_p,
                                      0,
                                      1,
                                      NULL)) {
        retire_fresh_h2_handoff(t_ctx, tp_p);
        if (t_ctx->rewrite_h2_tp) {
            restore_outbound_traceparent(&tp_p->tp, t_ctx->original_span_id, t_ctx->original_flags);
        }
        h2_resume_after(
            msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
        return SK_PASS;
    }

    if (t_ctx->rewrite_h2_tp) {
        const u32 span_id_offset =
            t_ctx->h2_hpack_offset + t_ctx->h2_tp_candidate_pos + k_tp_val_span_id_start;
        if (write_h2_existing_traceparent(msg, span_id_offset, tp_p->tp.span_id, tp_p->tp.flags)) {
            commit_outbound_traceparent(&tp_p->tp);
        } else {
            release_claimed_outgoing_trace_handoff(&t_ctx->e_key, &t_ctx->handoff_token);
            retire_fresh_h2_handoff(t_ctx, tp_p);
            restore_outbound_traceparent(&tp_p->tp, t_ctx->original_span_id, t_ctx->original_flags);
            tp_p->written = k_outbound_trace_pending;
            t_ctx->rewrite_h2_tp = false;
            if (h2_take_tail_call(t_ctx)) {
                bpf_tail_call_static(msg, &extender_jump_table, k_tail_reserve_existing_h2_tp);
            }
            h2_resume_after(
                msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
            return SK_PASS;
        }
    }
    commit_claimed_outgoing_trace_handoff(&t_ctx->e_key, &t_ctx->handoff_token);
    mirror_outgoing_trace_handoff_commit(&t_ctx->e_key, tp_p);
    tp_p->written = k_outbound_trace_written;
    t_ctx->h2_handoff_fresh = 0;
    h2_resume_after(
        msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
    return SK_PASS;
}

// Pull the candidate window directly so packet access stays at fixed offsets.
static __always_inline int h2_validate_existing_traceparent(struct sk_msg_md *msg,
                                                            tailcall_ctx *t_ctx) {
    if (t_ctx->h2_tp_status == k_hpack_traceparent_absent) {
        if (h2_take_tail_call(t_ctx)) {
            bpf_tail_call_static(msg, &extender_jump_table, k_tail_create_h2_tp);
        }
        return SK_PASS;
    }
    if (t_ctx->h2_tp_status != k_hpack_traceparent_found) {
        h2_resume_after(
            msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
        return SK_PASS;
    }

    const u32 target = t_ctx->h2_tp_candidate_pos;
    u32 encoded_len = t_ctx->h2_tp_value_len;
    if (target >= k_h2_max_hpack_scan || !encoded_len || encoded_len > k_hpack_tp_max_scan) {
        h2_resume_after(
            msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
        return SK_PASS;
    }
    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();
    if (!tp_p) {
        return SK_PASS;
    }
    reset_sampling_decision(&tp_p->tp);
    hpack_traceparent_decoder_state_t *decoder = h2_hpack_decoder_state_mem();
    if (!decoder) {
        h2_resume_after(
            msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
        return SK_PASS;
    }
    const u32 hpack_start = t_ctx->h2_hpack_offset;
    const u32 hpack_len = t_ctx->h2_hpack_len;
    if (target > hpack_len || encoded_len > hpack_len - target) {
        h2_resume_after(
            msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
        return SK_PASS;
    }

    unsigned char *scratch = h2_hpack_buf_mem();
    if (!scratch) {
        h2_resume_after(
            msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
        return SK_PASS;
    }

    if (!decoder->initialized) {
        bpf_clamp_umax(encoded_len, k_hpack_tp_max_scan);
        if (bpf_msg_pull_data(msg, hpack_start + target, hpack_start + target + encoded_len, 0) !=
            0) {
            h2_resume_after(
                msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
            return SK_PASS;
        }
        const unsigned char *data = msg->data;
        const unsigned char *end = msg->data_end;
        if (!data) {
            h2_resume_after(
                msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
            return SK_PASS;
        }
        const unsigned char *value = data;
        if (value + encoded_len > end || bpf_probe_read_kernel(scratch, encoded_len, value)) {
            h2_resume_after(
                msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
            return SK_PASS;
        }
        hpack_traceparent_decoder_init(
            decoder, encoded_len, t_ctx->h2_tp_value_huffman, 0, &tp_p->tp);
    }

    h2_hpack_decode_chunk(scratch, decoder, &tp_p->tp);
    if (!decoder->done) {
        h2_hpack_decode_chunk(scratch, decoder, &tp_p->tp);
    }
    if (!decoder->done) {
        h2_hpack_decode_chunk(scratch, decoder, &tp_p->tp);
    }
    if (!decoder->done) {
        if (h2_take_tail_call(t_ctx)) {
            bpf_tail_call_static(msg, &extender_jump_table, k_tail_validate_h2_tp);
        }
        decoder->value.valid_base = 0;
        hpack_traceparent_decoder_finish(decoder, &tp_p->tp);
    }
    if (h2_take_tail_call(t_ctx)) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_finish_existing_h2_tp);
    }
    h2_resume_after(
        msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
    return SK_PASS;
}

SEC("sk_msg")
int obi_packet_extender_validate_h2_tp(struct sk_msg_md *msg) {
    bpf_dbg_printk("=== sk_msg validate h2 tp ===");
    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    return t_ctx ? h2_validate_existing_traceparent(msg, t_ctx) : SK_PASS;
}

static __noinline int
h2_finish_go_existing_traceparent(struct sk_msg_md *msg, tailcall_ctx *t_ctx, tp_info_pid_t *tp_p) {
    bpf_memcpy(t_ctx->h2_wire_trace_id, tp_p->tp.trace_id, sizeof(t_ctx->h2_wire_trace_id));
    bpf_memcpy(t_ctx->h2_wire_span_id, tp_p->tp.span_id, sizeof(t_ctx->h2_wire_span_id));
    t_ctx->h2_wire_flags = tp_p->tp.flags;

    if (!claim_outgoing_trace_handoff(&t_ctx->e_key,
                                      &t_ctx->handoff_token,
                                      t_ctx->p_conn.pid,
                                      EVENT_HTTP_CLIENT,
                                      NULL,
                                      0,
                                      1,
                                      tp_p)) {
        h2_resume_after(
            msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
        return SK_PASS;
    }
    if (!h2_wire_traceparent_matches_authority(
            &tp_p->tp, t_ctx->h2_wire_trace_id, t_ctx->h2_wire_span_id, t_ctx->h2_wire_flags)) {
        release_claimed_outgoing_trace_handoff(&t_ctx->e_key, &t_ctx->handoff_token);
        h2_resume_after(
            msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
        return SK_PASS;
    }

    commit_claimed_outgoing_trace_handoff(&t_ctx->e_key, &t_ctx->handoff_token);
    mirror_outgoing_trace_handoff_commit(&t_ctx->e_key, tp_p);
    tp_p->written = k_outbound_trace_written;
    h2_resume_after(
        msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
    return SK_PASS;
}

SEC("sk_msg")
int obi_packet_extender_finish_existing_h2_tp(struct sk_msg_md *msg) {
    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();
    hpack_traceparent_decoder_state_t *decoder = h2_hpack_decoder_state_mem();
    if (!t_ctx || !tp_p || !decoder) {
        return SK_PASS;
    }

    const hpack_traceparent_decode_result_t decoded = hpack_traceparent_decoder_result(decoder);
    if (!decoded.valid) {
        t_ctx->tp_present = true;
        set_h2_sk_flag(msg, k_h2_sk_app_tp);
        h2_resume_after(
            msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
        return SK_PASS;
    }

    bpf_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));
    preserve_outbound_traceparent(&tp_p->tp);

    // Go's HPACK WriteField probe can reserve the exact per-stream authority
    // before sk_msg observes the already-serialized application traceparent.
    // Promote that original reservation in place when its wire identity
    // matches. The Go and sk_msg timestamps differ, so constructing and
    // reserving another candidate here would incorrectly compete with A.
    if (t_ctx->go_h2_conn && t_ctx->handoff_expected) {
        return h2_finish_go_existing_traceparent(msg, t_ctx, tp_p);
    }

    const bool may_rewrite =
        !t_ctx->h2_tp_value_huffman && decoded.version == 0 &&
        decoded.value_len == k_hpack_value_len_tp &&
        (t_ctx->h2_tp_representation == k_hpack_representation_without_indexing ||
         t_ctx->h2_tp_representation == k_hpack_representation_never_indexed);
    t_ctx->rewrite_h2_tp = false;
    // Go-owned blocks were already classified by WriteField. A valid
    // application traceparent is authoritative and must remain byte-for-byte
    // unchanged; only non-Go proxy forwarding may rewrite its child span.
    if (may_rewrite && !t_ctx->go_h2_conn) {
        init_tp_ctx_parent_tp(t_ctx);
        bpf_memcpy(t_ctx->original_span_id, tp_p->tp.span_id, sizeof(t_ctx->original_span_id));
        t_ctx->original_flags = tp_p->tp.flags;
        t_ctx->rewrite_h2_tp = apply_parent_tp(t_ctx, &tp_p->tp);
        if (t_ctx->rewrite_h2_tp) {
            apply_sampling_decision(&tp_p->tp, 1, 0);
        }
    }
    tp_p->tp.ts = bpf_ktime_get_ns();
    tp_p->valid = 1;
    tp_p->written = k_outbound_trace_pending;
    tp_p->pid = t_ctx->p_conn.pid;
    tp_p->req_type = EVENT_HTTP_CLIENT;

    if (h2_take_tail_call(t_ctx)) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_reserve_existing_h2_tp);
    }
    if (t_ctx->rewrite_h2_tp) {
        restore_outbound_traceparent(&tp_p->tp, t_ctx->original_span_id, t_ctx->original_flags);
    }
    h2_resume_after(
        msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
    return SK_PASS;
}

SEC("sk_msg")
int obi_packet_extender_reserve_existing_h2_tp(struct sk_msg_md *msg) {
    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();
    if (!t_ctx || !tp_p) {
        return SK_PASS;
    }

    const u8 reservation =
        reserve_transport_handoff_result(&t_ctx->e_key, tp_p, &t_ctx->handoff_token);
    t_ctx->h2_handoff_fresh = reservation == k_outgoing_trace_reservation_fresh;
    if (reservation == k_outgoing_trace_reservation_failed) {
        if (t_ctx->rewrite_h2_tp) {
            restore_outbound_traceparent(&tp_p->tp, t_ctx->original_span_id, t_ctx->original_flags);
        }
        h2_resume_after(
            msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
        return SK_PASS;
    }
    t_ctx->handoff_expected = 1;

    if (h2_take_tail_call(t_ctx)) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_claim_existing_h2_tp);
    }
    retire_fresh_h2_handoff(t_ctx, tp_p);
    if (t_ctx->rewrite_h2_tp) {
        restore_outbound_traceparent(&tp_p->tp, t_ctx->original_span_id, t_ctx->original_flags);
    }
    h2_resume_after(
        msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
    return SK_PASS;
}

SEC("sk_msg")
int obi_packet_extender_claim_existing_h2_tp(struct sk_msg_md *msg) {
    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();
    if (!t_ctx || !tp_p) {
        return SK_PASS;
    }
    return h2_claim_existing_traceparent(msg, t_ctx, tp_p);
}

// k_tail_create_h2_tp
SEC("sk_msg")
int obi_packet_extender_create_h2_tp(struct sk_msg_md *msg) {
    bpf_dbg_printk("=== sk_msg create h2 tp ===");

    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    if (!t_ctx) {
        return SK_PASS;
    }

    if (!(inject_flags & k_inject_http_headers)) {
        return SK_PASS;
    }

    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();
    if (!tp_p) {
        return SK_PASS;
    }
    bpf_memset(tp_p, 0, sizeof(*tp_p));

    tp_info_pid_t existing = {};
    const u8 resolution = resolve_current_outgoing_trace_handoff(&t_ctx->e_key,
                                                                 t_ctx->p_conn.pid,
                                                                 EVENT_HTTP_CLIENT,
                                                                 1,
                                                                 &t_ctx->handoff_token,
                                                                 &existing,
                                                                 NULL);
    if (resolution == k_outgoing_trace_fail_closed) {
        h2_resume_after(
            msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
        return SK_PASS;
    }
    const u8 has_authority = resolution == k_outgoing_trace_exact;
    const bool existing_written = has_authority && existing.written == k_outbound_trace_written;
    const bool existing_pending = has_authority && existing.written == k_outbound_trace_pending;

    h2_inject_facts_t facts = {0};
    facts.opener = t_ctx->opener;
    facts.opener_readable = true;
    facts.sk_server = h2_sk_flag(msg, k_h2_sk_server);
    facts.frame_tp_present = t_ctx->tp_present;
    facts.sk_app_tp = h2_sk_flag(msg, k_h2_sk_app_tp);
    facts.uprobe_wrote = existing_written;
    facts.go_conn_without_tp = t_ctx->go_h2_conn && !existing_written && !existing_pending;
    facts.scan_incomplete = t_ctx->scan_exhausted || t_ctx->h2_hpack_len > k_h2_max_hpack_scan;

    if (h2_inject_verdict(&facts) != k_h2_inject_allow) {
        h2_resume_after(
            msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
        return SK_PASS;
    }

    if (existing_pending) {
        bpf_memcpy(tp_p, &existing, sizeof(*tp_p));
        t_ctx->handoff_expected = 1;
        t_ctx->h2_handoff_fresh = 0;
    } else {
        init_tp_ctx_parent_tp(t_ctx);
        if (!create_trace_info(t_ctx, tp_p)) {
            return SK_PASS;
        }
    }
    tp_p->written = k_outbound_trace_pending;
    if (!existing_pending) {
        if (h2_take_tail_call(t_ctx)) {
            bpf_tail_call_static(msg, &extender_jump_table, k_tail_reserve_h2_tp);
        }
        h2_resume_after(
            msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
        return SK_PASS;
    }

    if (h2_take_tail_call(t_ctx)) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_write_h2_traceparent);
    }
    retire_fresh_h2_handoff(t_ctx, tp_p);
    h2_resume_after(
        msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
    return SK_PASS;
}

SEC("sk_msg")
int obi_packet_extender_reserve_h2_tp(struct sk_msg_md *msg) {
    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();
    if (!t_ctx || !tp_p) {
        return SK_PASS;
    }

    const u8 reservation =
        reserve_transport_handoff_result(&t_ctx->e_key, tp_p, &t_ctx->handoff_token);
    t_ctx->h2_handoff_fresh = reservation == k_outgoing_trace_reservation_fresh;
    if (reservation == k_outgoing_trace_reservation_failed) {
        h2_resume_after(
            msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
        return SK_PASS;
    }
    t_ctx->handoff_expected = 1;

    if (h2_take_tail_call(t_ctx)) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_write_h2_traceparent);
    }
    retire_fresh_h2_handoff(t_ctx, tp_p);
    h2_resume_after(
        msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
    return SK_PASS;
}

// k_tail_write_h2_traceparent — push k_h2_tp_hpack_size bytes of HPACK at
// the end of the HEADERS payload. Small targeted pulls keep writes at fixed
// offsets so the verifier is happy
SEC("sk_msg")
int obi_packet_extender_write_h2_tp(struct sk_msg_md *msg) {
    bpf_dbg_printk("=== sk_msg h2 tp ===");

    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    if (!t_ctx) {
        return SK_PASS;
    }

    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();
    if (!tp_p) {
        return SK_PASS;
    }

    if (!claim_outgoing_trace_handoff(&t_ctx->e_key,
                                      &t_ctx->handoff_token,
                                      t_ctx->p_conn.pid,
                                      EVENT_HTTP_CLIENT,
                                      tp_p,
                                      0,
                                      1,
                                      NULL)) {
        retire_fresh_h2_handoff(t_ctx, tp_p);
        h2_resume_after(
            msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
        return SK_PASS;
    }

    const u32 frame_offset = t_ctx->h2_frame_offset;
    const u32 payload_len = t_ctx->h2_payload_len;

    if (!h2_frame_can_append(payload_len, k_h2_tp_hpack_size)) {
        release_claimed_outgoing_trace_handoff(&t_ctx->e_key, &t_ctx->handoff_token);
        retire_fresh_h2_handoff(t_ctx, tp_p);
        h2_resume_after(msg, t_ctx, frame_offset + k_h2_frame_header_len + payload_len);
        return SK_PASS;
    }

    const u32 inject_offset = t_ctx->h2_hpack_offset + t_ctx->h2_hpack_len;

    if (bpf_msg_pull_data(msg, 0, msg->size, 0) != 0) {
        release_claimed_outgoing_trace_handoff(&t_ctx->e_key, &t_ctx->handoff_token);
        retire_fresh_h2_handoff(t_ctx, tp_p);
        h2_resume_after(msg, t_ctx, frame_offset + k_h2_frame_header_len + payload_len);
        return SK_PASS;
    }
    if (bpf_msg_push_data(msg, inject_offset, k_h2_tp_hpack_size, 0) != 0) {
        release_claimed_outgoing_trace_handoff(&t_ctx->e_key, &t_ctx->handoff_token);
        retire_fresh_h2_handoff(t_ctx, tp_p);
        h2_resume_after(msg, t_ctx, frame_offset + k_h2_frame_header_len + payload_len);
        return SK_PASS;
    }

    if (bpf_msg_pull_data(msg, inject_offset, inject_offset + k_h2_tp_hpack_size, 0) != 0) {
        const long rollback = bpf_msg_pop_data(msg, inject_offset, k_h2_tp_hpack_size, 0);
        release_claimed_outgoing_trace_handoff(&t_ctx->e_key, &t_ctx->handoff_token);
        retire_fresh_h2_handoff(t_ctx, tp_p);
        if (rollback != 0) {
            return SK_DROP;
        }
        h2_resume_after(msg, t_ctx, frame_offset + k_h2_frame_header_len + payload_len);
        return SK_PASS;
    }

    unsigned char *data = msg->data;
    const unsigned char *end = msg->data_end;
    if (!data || (void *)data + k_h2_tp_hpack_size > (void *)end) {
        const long rollback = bpf_msg_pop_data(msg, inject_offset, k_h2_tp_hpack_size, 0);
        release_claimed_outgoing_trace_handoff(&t_ctx->e_key, &t_ctx->handoff_token);
        retire_fresh_h2_handoff(t_ctx, tp_p);
        if (rollback != 0) {
            return SK_DROP;
        }
        h2_resume_after(msg, t_ctx, frame_offset + k_h2_frame_header_len + payload_len);
        return SK_PASS;
    }
    make_h2_tp_hpack(data, &tp_p->tp, end);

    const u32 new_len = payload_len + k_h2_tp_hpack_size;
    if (bpf_msg_pull_data(msg, frame_offset, frame_offset + 3, 0) != 0) {
        const long rollback = bpf_msg_pop_data(msg, inject_offset, k_h2_tp_hpack_size, 0);
        release_claimed_outgoing_trace_handoff(&t_ctx->e_key, &t_ctx->handoff_token);
        retire_fresh_h2_handoff(t_ctx, tp_p);
        if (rollback != 0) {
            return SK_DROP;
        }
        h2_resume_after(msg, t_ctx, frame_offset + k_h2_frame_header_len + payload_len);
        return SK_PASS;
    }
    data = msg->data;
    end = msg->data_end;
    if (!data || (void *)data + 3 > (void *)end) {
        const long rollback = bpf_msg_pop_data(msg, inject_offset, k_h2_tp_hpack_size, 0);
        release_claimed_outgoing_trace_handoff(&t_ctx->e_key, &t_ctx->handoff_token);
        retire_fresh_h2_handoff(t_ctx, tp_p);
        if (rollback != 0) {
            return SK_DROP;
        }
        h2_resume_after(msg, t_ctx, frame_offset + k_h2_frame_header_len + payload_len);
        return SK_PASS;
    }
    data[0] = (new_len >> 16) & 0xFF;
    data[1] = (new_len >> 8) & 0xFF;
    data[2] = new_len & 0xFF;

    commit_claimed_outgoing_trace_handoff(&t_ctx->e_key, &t_ctx->handoff_token);
    mirror_outgoing_trace_handoff_commit(&t_ctx->e_key, tp_p);
    tp_p->written = k_outbound_trace_written;
    t_ctx->h2_handoff_fresh = 0;

    bpf_msg_pull_data(msg, 0, msg->size, 0);

    print_tp("h2: written TP to HPACK", &tp_p->tp);

    // bpf_msg_push_data shifted bytes after inject_offset right by
    // k_h2_tp_hpack_size, so the next batched HEADERS frame is now at
    // frame_offset + 9 + new_payload_len
    h2_resume_after(msg,
                    t_ctx,
                    t_ctx->h2_frame_offset + k_h2_frame_header_len + payload_len +
                        k_h2_tp_hpack_size);
    return SK_PASS;
}
