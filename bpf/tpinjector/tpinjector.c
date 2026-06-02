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
#include <common/http_buf_size.h>
#include <common/http_types.h>
#include <common/lw_thread.h>
#include <common/msg_buffer.h>
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

#include <tpinjector/h2_parse.h>
#include <tpinjector/maps/sk_h2_conn_flag.h>
#include <tpinjector/maps/sk_tp_info_pid_map.h>

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
//   ├── is_go_grpc_client_conn?        │  Go gRPC: uprobe wrote HPACK in
//   │     └── pull+fill, SK_PASS       │  user buffer; sk_msg bails (kprobe
//   │                                  │  needs fill for correlation)
//   │                                  │
//   ├── !valid_pid → SK_PASS           │  Unmonitored process — no pull
//   │                                  │
//   ├── pull_data + fill_msg_buffers   │  Committed to processing
//   │                                  │
//   ├── is_h2_socket?                  │  Known plaintext H2: skip preface
//   │     └─ tail-call detect_h2       │  check, go straight to HPACK chain
//   │                                 │
//   ├── HTTP/1 detected?              │  ── find_existing_tp ── create_tp ──
//   │                                 │     write_msg_traceparent
//   │                                 │
//   └── fall through ─────────────────┴─▶ wrap_http2_traceparent
//                                           │
//                                           ▼
//                                        detect_h2 ◀──────────────┐
//                                           │                     │
//                                           │ HEADERS+END_HEADERS │ resume on
//                                           ▼                     │ batched
//                                        find_existing_h2_tp ─────┤ frame via
//                                           │ adopt or            │ h2_scan_pos
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

// Kind 25 is unassigned per IANA TCP Parameters registry (released 2000-12-18)
// Better than experimental options (253-254) which must not be shipped as defaults
enum { k_tcp_option_kind_otel = 25 };

enum {
    k_tail_write_msg_traceparent,
    k_tail_find_existing_tp,
    k_tail_create_tp,
    k_tail_write_h2_traceparent,
    k_tail_create_h2_tp,
    k_tail_find_existing_h2_tp,
    k_tail_validate_h2_tp,
    k_tail_detect_h2,
};

int obi_packet_extender_write_msg_tp(struct sk_msg_md *msg);
int obi_packet_extender_find_existing_tp(struct sk_msg_md *msg);
int obi_packet_extender_create_tp(struct sk_msg_md *msg);
int obi_packet_extender_write_h2_tp(struct sk_msg_md *msg);
int obi_packet_extender_create_h2_tp(struct sk_msg_md *msg);
int obi_packet_extender_find_existing_h2_tp(struct sk_msg_md *msg);
int obi_packet_extender_validate_h2_tp(struct sk_msg_md *msg);
int obi_packet_extender_detect_h2(struct sk_msg_md *msg);

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 8);
    __uint(key_size, sizeof(u32));
    __array(values, int(void *));
} extender_jump_table SEC(".maps") = {
    .values =
        {
            [k_tail_write_msg_traceparent] = (void *)&obi_packet_extender_write_msg_tp,
            [k_tail_find_existing_tp] = (void *)&obi_packet_extender_find_existing_tp,
            [k_tail_create_tp] = (void *)&obi_packet_extender_create_tp,
            [k_tail_write_h2_traceparent] = (void *)&obi_packet_extender_write_h2_tp,
            [k_tail_create_h2_tp] = (void *)&obi_packet_extender_create_h2_tp,
            [k_tail_find_existing_h2_tp] = (void *)&obi_packet_extender_find_existing_h2_tp,
            [k_tail_validate_h2_tp] = (void *)&obi_packet_extender_validate_h2_tp,
            [k_tail_detect_h2] = (void *)&obi_packet_extender_detect_h2,
        },
};

// State threaded across the tail-call chain via per-CPU scratch memory.
// Set in obi_packet_extender; read/written by the H2 and HTTP/1 chains.
typedef struct tailcall_ctx {
    pid_connection_info_t p_conn; // sorted connection + caller PID
    tp_info_t parent_tp;          // parent trace context (set by init_tp_ctx_parent_tp)
    egress_key_t e_key;           // {ports, stream_id} key for outgoing_trace_map
    u32 h2_frame_offset;          // start of the HEADERS frame in msg
    u32 h2_payload_len;           // HEADERS payload length
    u32 h2_hpack_offset;          // start of HPACK bytes (after PADDED/PRIORITY prefix)
    u32 h2_hpack_len;             // HPACK length (frame payload minus prefix and trailing pad)
    u32 h2_scan_pos;              // resume offset for detect_h2 across tail calls
    u32 h2_tp_candidate_pos;      // HPACK candidate offset (>= k_h2_max_hpack_scan = none)
    u8 niter;                     // HTTP/1 find-existing scan iteration counter
    u8 h2_frames;                 // H2 frames already injected this packet (capped)
    bool has_parent_tp;           // true if parent_tp holds a valid context
    u8 _pad[5];
} tailcall_ctx;

SCRATCH_MEM(tailcall_ctx);
SCRATCH_MEM_SIZED(tp_str_buf, 64);

// Resume detect_h2 at next_pos for the next batched HEADERS frame.
// Bumps the per-packet frame counter, then tail-calls back into detect_h2.
static __always_inline void
h2_resume_after(struct sk_msg_md *msg, tailcall_ctx *t_ctx, u32 next_pos) {
    t_ctx->h2_scan_pos = next_pos;
    t_ctx->h2_frames++;
    bpf_tail_call_static(msg, &extender_jump_table, k_tail_detect_h2);
}

static __always_inline bool is_h2_socket(struct sk_msg_md *msg) {
    struct bpf_sock *sk = msg->sk;
    if (!sk) {
        return false;
    }
    const u8 *flag = bpf_sk_storage_get(&sk_h2_conn_flag, sk, NULL, 0);
    return flag && *flag;
}

static __always_inline void mark_h2_socket(struct sk_msg_md *msg) {
    struct bpf_sock *sk = msg->sk;
    if (!sk) {
        return;
    }
    bpf_sk_storage_get(&sk_h2_conn_flag, sk, &(u8){1}, BPF_SK_STORAGE_GET_F_CREATE);
}

#ifndef ENOMSG
#define ENOMSG 42
#endif

struct tp_option {
    u8 kind;
    u8 len;
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
};

static __always_inline const char *tp_string_from_opt(const struct tp_option *opt) {
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

    *ptr++ = '0';
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

// This is setup here for Go and SSL tracking.
// Essentially, when the Go or the OpenSSL userspace
// probes activate for an outgoing HTTP request they setup this
// outgoing_trace_map for us. We then know this is a connection we should
// be injecting the Traceparent in. Another place which sets up this map is
// the kprobe on tcp_sendmsg, however that happens after the sock_msg runs,
// so we have a different detection for that - protocol_detector.
static __always_inline tp_info_pid_t *get_tp_info_pid(const egress_key_t *e_key) {
    return bpf_map_lookup_elem(&outgoing_trace_map, e_key);
}

static __always_inline void set_tp_info_pid(const egress_key_t *e_key, const tp_info_pid_t *tp_p) {
    bpf_map_update_elem(&outgoing_trace_map, e_key, tp_p, BPF_ANY);
}

static __always_inline void clear_tp_info_pid(const egress_key_t *e_key) {
    bpf_map_delete_elem(&outgoing_trace_map, e_key);
}

static __always_inline u8 already_tracked(const pid_connection_info_t *p_conn) {
    return already_tracked_http(p_conn) || already_tracked_tcp(p_conn) ||
           already_tracked_http2(p_conn);
}

// Extracts what we need for connection_info_t from bpf_sock_ops if the
// communication is IPv4
static __always_inline connection_info_t sk_ops_extract_key_ip4(struct bpf_sock_ops *ops) {
    connection_info_t conn = {};

    const u32 local_ip4 = ops->local_ip4;
    const u32 remote_ip4 = ops->remote_ip4;
    const u32 local_port = ops->local_port;
    const u32 remote_port = bpf_ntohl(ops->remote_port);

    __builtin_memcpy(conn.s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn.s_ip[3] = local_ip4;
    __builtin_memcpy(conn.d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn.d_ip[3] = remote_ip4;

    conn.s_port = local_port;
    conn.d_port = remote_port;

    return conn;
}

// Extracts what we need for connection_info_t from bpf_sock_ops if the
// communication is IPv6
// The order of copying the data from bpf_sock_ops matters and must match how
// the struct is laid in vmlinux.h, otherwise the verifier thinks we are modifying
// the context twice.
static __always_inline connection_info_t sk_ops_extract_key_ip6(struct bpf_sock_ops *ops) {
    connection_info_t conn = {};

    conn.d_ip[0] = ops->remote_ip6[0];
    conn.d_ip[1] = ops->remote_ip6[1];
    conn.d_ip[2] = ops->remote_ip6[2];
    conn.d_ip[3] = ops->remote_ip6[3];
    conn.s_ip[0] = ops->local_ip6[0];
    conn.s_ip[1] = ops->local_ip6[1];
    conn.s_ip[2] = ops->local_ip6[2];
    conn.s_ip[3] = ops->local_ip6[3];

    const u32 local_port = ops->local_port;
    const u32 remote_port = bpf_ntohl(ops->remote_port);

    conn.d_port = remote_port;
    conn.s_port = local_port;

    return conn;
}

static __always_inline connection_info_t get_connection_info_ops(struct bpf_sock_ops *ops) {
    return ops->family == AF_INET6 ? sk_ops_extract_key_ip6(ops) : sk_ops_extract_key_ip4(ops);
}

// Extracts what we need for connection_info_t from sk_msg_md if the
// communication is IPv4
static __always_inline connection_info_t sk_msg_extract_key_ip4(const struct sk_msg_md *msg) {
    connection_info_t conn = {};

    __builtin_memcpy(conn.s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn.s_ip[3] = msg->local_ip4;
    __builtin_memcpy(conn.d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn.d_ip[3] = msg->remote_ip4;

    conn.s_port = msg->local_port;
    conn.d_port = bpf_ntohl(msg->remote_port);

    return conn;
}

// Extracts what we need for connection_info_t from sk_msg_md if the
// communication is IPv6
// The order of copying the data from bpf_sock_ops matters and must match how
// the struct is laid in vmlinux.h, otherwise the verifier thinks we are modifying
// the context twice.
static __always_inline connection_info_t sk_msg_extract_key_ip6(struct sk_msg_md *msg) {
    connection_info_t conn = {};

    sk_msg_read_remote_ip6(msg, conn.d_ip);
    sk_msg_read_local_ip6(msg, conn.s_ip);

    conn.d_port = bpf_ntohl(sk_msg_remote_port(msg));
    conn.s_port = sk_msg_local_port(msg);

    return conn;
}

static __always_inline void init_tp_ctx_parent_tp(tailcall_ctx *t_ctx) {
    t_ctx->parent_tp.ts = bpf_ktime_get_ns();
    t_ctx->parent_tp.flags = 1;

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
    tp_p->tp.flags = 1;
    tp_p->valid = 1;
    tp_p->pid = t_ctx->p_conn.pid;
    tp_p->req_type = EVENT_HTTP_CLIENT;

    if (t_ctx->has_parent_tp) {
        bpf_dbg_printk("found existing tp info");

        __builtin_memcpy(tp_p->tp.trace_id, t_ctx->parent_tp.trace_id, sizeof(tp_p->tp.trace_id));
        __builtin_memcpy(tp_p->tp.parent_id, t_ctx->parent_tp.span_id, sizeof(tp_p->tp.parent_id));
    } else {
        bpf_dbg_printk("generating tp info");

        new_trace_id(&tp_p->tp);
        __builtin_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));
    }

    return true;
}

static __always_inline void bpf_sock_ops_set_flags(struct bpf_sock_ops *skops, u8 flags) {
    bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | flags);
}

// Helper that writes in the sock map for a sock_ops program
static __always_inline void bpf_sock_ops_active_est_cb(struct bpf_sock_ops *skops) {
    const u64 cookie = bpf_get_socket_cookie(skops);

    bpf_sock_hash_update(skops, &sock_dir, (void *)&cookie, BPF_ANY);
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

    tp_info_pid_t *tp_pid = bpf_sk_storage_get(&sk_tp_info_pid_map, sk, NULL, 0);

    if (!tp_pid) {
        return;
    }

    const long ret = bpf_reserve_hdr_opt(skops, sizeof(struct tp_option), 0);

    if (ret != 0) {
        bpf_dbg_printk("failed to reserve TCP option: %d", ret);
        return;
    }
}

static __always_inline void bpf_sock_ops_write_hdr_cb(struct bpf_sock_ops *skops) {
    struct bpf_sock *sk = skops->sk;

    if (!sk) {
        return;
    }

    const tp_info_pid_t *tp_pid = bpf_sk_storage_get(&sk_tp_info_pid_map, sk, NULL, 0);

    if (!tp_pid) {
        bpf_dbg_printk("tp info not found");
        return;
    }

    // cleanup the storage to prevent it from being written more than once
    // (including during responses);
    bpf_sk_storage_delete(&sk_tp_info_pid_map, sk);

    struct tp_option opt = {.kind = k_tcp_option_kind_otel, .len = sizeof(struct tp_option)};

    __builtin_memcpy(opt.trace_id, tp_pid->tp.trace_id, sizeof(opt.trace_id));
    __builtin_memcpy(opt.span_id, tp_pid->tp.span_id, sizeof(opt.span_id));

    const long ret = bpf_store_hdr_opt(skops, &opt, sizeof(opt), 0);

    if (ret != 0) {
        bpf_dbg_printk("failed to store option: %d", ret);
    }

    if (g_bpf_debug) {
        const char *tp_str = tp_string_from_opt(&opt);

        if (tp_str) {
            bpf_dbg_printk("written TP to TCP options: %s", tp_str);
        }
    }
}

static __always_inline void bpf_sock_ops_parse_hdr_cb(struct bpf_sock_ops *skops) {
    if (!(inject_flags & k_inject_tcp_options)) {
        return;
    }

    struct tp_option opt = {};
    opt.kind = k_tcp_option_kind_otel;

    const long ret = bpf_load_hdr_opt(skops, &opt, sizeof(opt), 0);

    if (ret == -ENOMSG) {
        return;
    }

    if (ret < 0) {
        bpf_dbg_printk("error parsing TCP option: %d", ret);
        return;
    }

    if (g_bpf_debug) {
        const char *tp_str = tp_string_from_opt(&opt);

        if (tp_str) {
            bpf_dbg_printk("found TP in TCP options: %s", tp_str);
        }
    }

    tp_info_pid_t tp = {};
    tp.valid = 1;

    __builtin_memcpy(tp.tp.trace_id, opt.trace_id, sizeof(tp.tp.trace_id));
    __builtin_memcpy(tp.tp.span_id, opt.span_id, sizeof(tp.tp.span_id));

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
static __always_inline bool fill_msg_buffers(struct sk_msg_md *msg,
                                             const pid_connection_info_t *p_conn,
                                             const egress_key_t *e_key) {
    if (msg->size == 0 || is_ssl_connection(p_conn)) {
        return false;
    }

    msg_buffer_t msg_buf = {
        .pos = 0,
        .real_size = min(msg->size, k_msg_buffer_size_max),
        .cpu_id = bpf_get_smp_processor_id(),
    };

    bpf_probe_read_kernel(msg_buf.fallback_buf, k_kprobes_http2_buf_size, msg->data);

    const u16 copy_bytes = max(msg_buf.real_size, k_kprobes_http2_buf_size);

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

    if (bpf_map_update_elem(&msg_buffers, e_key, &msg_buf, BPF_ANY)) {
        // fail if we can't setup a msg buffer
        return false;
    }

    return true;
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

static __always_inline connection_info_t get_connection_info(struct sk_msg_md *msg) {
    return msg->family == AF_INET6 ? sk_msg_extract_key_ip6(msg) : sk_msg_extract_key_ip4(msg);
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

    *buf++ = '0';
    *buf++ = '0' + (tp->flags & k_flag_sampled);
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

    *buf++ = '0';
    *buf++ = '0' + (tp->flags & k_flag_sampled);
}

static __always_inline bool
extend_and_write_tp(struct sk_msg_md *msg, u32 offset, const tp_info_t *tp) {
    const long err = bpf_msg_push_data(msg, offset, TP_SIZE, 0);

    if (err != 0) {
        bpf_d_printk("failed to push data: %d [%s]", err, __FUNCTION__);
        return false;
    }

    bpf_msg_pull_data(msg, 0, msg->size, 0);
    bpf_dbg_printk(
        "offset to split=%d, available=%u, size=%u", offset, msg->data_end - msg->data, msg->size);

    if (!msg->data) {
        bpf_d_printk("null data [%s]", __FUNCTION__);
        return false;
    }

    unsigned char *ptr = msg->data + offset;

    if ((void *)ptr + TP_SIZE >= msg->data_end) {
        bpf_d_printk("not enough space [%s]", __FUNCTION__);
        return false;
    }

    make_tp_string_skb(ptr, tp, msg->data_end);

    return true;
}

static __always_inline bool write_msg_traceparent(struct sk_msg_md *msg, const tp_info_t *tp) {
    unsigned char *data = ctx_msg_data(msg);

    if (!data) {
        return false;
    }

    const u32 newline_pos = find_first_pos_of(data, ctx_msg_data_end(msg), '\n');

    if (newline_pos == INVALID_POS) {
        return false;
    }

    const u32 write_offset = newline_pos + 1;

    return extend_and_write_tp(msg, write_offset, tp);
}

static __always_inline void schedule_write_tcp_option(struct sk_msg_md *msg, tp_info_pid_t *tp_p) {
    struct bpf_sock *sk = msg->sk;

    if (!sk) {
        return;
    }

    tp_info_pid_t *stp =
        bpf_sk_storage_get(&sk_tp_info_pid_map, sk, NULL, BPF_SK_STORAGE_GET_F_CREATE);

    if (!stp) {
        return;
    }

    // associate it also with this socket for the tcp options program
    *stp = *tp_p;

    tp_p->written = 1;
}

static __always_inline void write_http_traceparent(struct sk_msg_md *msg, tp_info_pid_t *tp_pid) {
    // used for the upcoming tailcall
    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();

    if (!tp_p) {
        return;
    }

    tp_pid->written = 1;
    *tp_p = *tp_pid;

    bpf_tail_call_static(msg, &extender_jump_table, k_tail_write_msg_traceparent);

    bpf_d_printk("tailcall failed [%s]", __FUNCTION__);
}

static __always_inline bool is_http2_preface(const unsigned char *d, const unsigned char *end) {
    return d && (void *)d + k_h2_preface_check_len <= (void *)end && d[0] == 'P' && d[1] == 'R' &&
           d[2] == 'I' && d[3] == ' ';
}

// Skip SSL sockets — payload is encrypted, can't inject HPACK
static __always_inline void wrap_http2_traceparent(struct sk_msg_md *msg,
                                                   const pid_connection_info_t *p_conn) {
    if (msg->size < k_h2_frame_header_len) {
        return;
    }
    if (is_h2_socket(msg) || already_tracked_plain_http2(p_conn)) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_detect_h2);
        return;
    }
    if (msg->size < k_h2_preface_check_len) {
        return;
    }
    if (bpf_msg_pull_data(msg, 0, k_h2_preface_check_len, 0) != 0) {
        return;
    }
    if (is_http2_preface(msg->data, msg->data_end)) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_detect_h2);
    }
}

// HTTP/1 only. Caller must skip this for H2 sockets — connection-scoped tp_pid
// carries the wrong context for multiplexed streams.
static __always_inline bool handle_existing_tp_pid(struct sk_msg_md *msg,
                                                   u64 id,
                                                   const pid_connection_info_t *p_conn,
                                                   const egress_key_t *e_key,
                                                   tp_info_pid_t *tp_pid) {
    if (inject_flags & k_inject_tcp_options) {
        schedule_write_tcp_option(msg, tp_pid);
    }

    // valid==0: SSL or junk — drop it and stop tracking
    if (tp_pid->valid == 0) {
        clear_tp_info_pid(e_key);
        return true;
    }

    bpf_msg_pull_data(msg, 0, msg->size, 0);
    fill_msg_buffers(msg, p_conn, e_key);

    const bool is_http = protocol_detector(msg, id, &p_conn->conn);
    if (is_http) {
        if (inject_flags & k_inject_http_headers) {
            write_http_traceparent(msg, tp_pid);
        } else {
            clear_tp_info_pid(e_key);
        }
        return true;
    }

    clear_tp_info_pid(e_key);
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
    const connection_info_t conn = get_connection_info(msg);
    const egress_key_t e_key = make_egress_key(&conn);

    t_ctx->p_conn.conn = conn;
    sort_connection_info(&t_ctx->p_conn.conn);
    t_ctx->p_conn.pid = pid_from_pid_tgid(id);
    t_ctx->e_key = e_key;
    t_ctx->niter = 0;
    t_ctx->h2_scan_pos = 0;
    t_ctx->h2_frames = 0;

    // skip H2 here — it uses HPACK for per-stream traceparents
    tp_info_pid_t *tp_pid = get_tp_info_pid(&e_key);
    if (tp_pid && !is_h2_socket(msg) &&
        handle_existing_tp_pid(msg, id, &t_ctx->p_conn, &e_key, tp_pid)) {
        return SK_PASS;
    }

    if (is_go_grpc_client_conn(&t_ctx->p_conn)) {
        bpf_msg_pull_data(msg, 0, msg->size, 0);
        fill_msg_buffers(msg, &t_ctx->p_conn, &e_key);
        return SK_PASS;
    }

    if (!valid_pid(id)) {
        return SK_PASS;
    }

    bpf_msg_pull_data(msg, 0, msg->size, 0);
    fill_msg_buffers(msg, &t_ctx->p_conn, &e_key);

    if (is_h2_socket(msg)) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_detect_h2);
        return SK_PASS;
    }

    if (msg->size <= MIN_HTTP_SIZE) {
        return SK_PASS;
    }

    bpf_dbg_printk("MSG=%llx:%d ->", conn.s_ip[3], conn.s_port);
    bpf_dbg_printk("MSG TO=%llx:%d", conn.d_ip[3], conn.d_port);
    bpf_dbg_printk("MSG SIZE=%u", msg->size);

    const bool is_http = protocol_detector(msg, id, &conn);
    if (is_http) {
        bpf_dbg_printk("len=%d, s_port=%d", msg->size, msg->local_port);
        init_tp_ctx_parent_tp(t_ctx);
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_find_existing_tp);
        return SK_PASS;
    }

    wrap_http2_traceparent(msg, &t_ctx->p_conn);
    return SK_PASS;
}

//k_tail_write_msg_traceparent
SEC("sk_msg")
int obi_packet_extender_write_msg_tp(struct sk_msg_md *msg) {
    bpf_dbg_printk("=== sk_msg ===");

    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();

    if (!tp_p) {
        bpf_dbg_printk("empty tp_buf");
        return SK_PASS;
    }

    bpf_msg_pull_data(msg, 0, msg->size, 0);

    if (!write_msg_traceparent(msg, &tp_p->tp)) {
        bpf_d_printk("failed to write traceparent [%s]", __FUNCTION__);
    }

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
    urand_bytes(tp->span_id, SPAN_ID_SIZE_BYTES);
    return true;
}

static __always_inline void
assign_parent_tp(const tailcall_ctx *t_ctx, tp_info_t *tp, unsigned char *span_id) {
    if (apply_parent_tp(t_ctx, tp)) {
        bpf_dbg_printk("detected forwarded TP header, overriding span id");
        encode_hex(span_id, tp->span_id, SPAN_ID_SIZE_BYTES);
    }
}

//k_tail_find_existing_tp
SEC("sk_msg")
int obi_packet_extender_find_existing_tp(struct sk_msg_md *msg) {
    const u32 k_max_iter = 4;          // iterate up to 4KB
    const u32 k_max_chunk_size = 1024; // 1KB chunks per iteration

    tailcall_ctx *t_ctx = tailcall_ctx_mem();

    if (!t_ctx) {
        return SK_PASS;
    }

    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();

    if (!tp_p) {
        return SK_PASS;
    }

    const u32 niter = t_ctx->niter;

    if (niter >= k_max_iter) {
        return SK_PASS;
    }

    unsigned char *b = msg->data;
    const unsigned char *e = msg->data_end;
    unsigned char *ptr = b + (niter * k_max_chunk_size);

    if (ptr >= e) {
        return SK_PASS;
    }

    bpf_dbg_printk("looking for traceparent header (iter=%u)", niter);

    u32 data_size = e - ptr;

    if (data_size > k_max_chunk_size) {
        data_size = k_max_chunk_size;
    }

    for (u32 i = 0; i < data_size; ++i) {
        if ((ptr + TP_SIZE >= e) || is_eoh(ptr)) {
            bpf_tail_call_static(msg, &extender_jump_table, k_tail_create_tp);
            break;
        }

        if (is_traceparent(ptr)) {
            ptr += TP_TID_PREFIX_SIZE;

            decode_hex(tp_p->tp.trace_id, ptr, TRACE_ID_CHAR_LEN);

            ptr += TRACE_ID_CHAR_LEN;

            if (*ptr++ != '-') {
                return SK_PASS;
            }

            decode_hex(tp_p->tp.span_id, ptr, SPAN_ID_CHAR_LEN);

            unsigned char *span_id = ptr;

            ptr += SPAN_ID_CHAR_LEN;

            if (*ptr++ != '-') {
                return SK_PASS;
            }

            decode_hex((unsigned char *)&tp_p->tp.flags, ptr, FLAGS_CHAR_LEN);

            ptr += FLAGS_CHAR_LEN;

            if (*ptr++ != '\r' || *ptr != '\n') {
                return SK_PASS;
            }

            // if we got to this point, we managed to parse a valid
            // 'Traceparent: ...' header that we can utilise

            assign_parent_tp(t_ctx, &tp_p->tp, span_id);

            tp_p->tp.ts = bpf_ktime_get_ns();
            tp_p->tp.flags = 1;
            tp_p->valid = 1;
            tp_p->written = 1;
            tp_p->pid = t_ctx->p_conn.pid;
            tp_p->req_type = EVENT_HTTP_CLIENT;

            print_tp("found TP in headers", &tp_p->tp);

            set_tp_info_pid(&t_ctx->e_key, tp_p);

            if (inject_flags & k_inject_tcp_options) {
                schedule_write_tcp_option(msg, tp_p);
            }

            return SK_PASS;
        }

        ++ptr;
    }

    t_ctx->niter++;

    if (t_ctx->niter < k_max_iter) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_find_existing_tp);
    } else {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_create_tp);
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

    tp_p->written = 1;

    // associate this tp_info to this request
    set_tp_info_pid(&t_ctx->e_key, tp_p);

    if (inject_flags & k_inject_tcp_options) {
        schedule_write_tcp_option(msg, tp_p);
    }

    if (inject_flags & k_inject_http_headers) {
        // write the HTTP headers
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_write_msg_traceparent);
        bpf_d_printk("tailcall failed [%s]", __FUNCTION__);
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

    // Only check preface on the first call (scan_pos == 0). Go gRPC sends
    // the 24-byte preface in its own packet, before any HEADERS frame
    if (pos == 0 && msg_size >= k_h2_preface_check_len) {
        if (bpf_msg_pull_data(msg, 0, k_h2_preface_check_len, 0) == 0) {
            if (is_http2_preface(msg->data, msg->data_end)) {
                mark_h2_socket(msg);
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

    // Scan up to 4 frames for HEADERS+END_HEADERS
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

            tp_info_pid_t *go_tp = get_tp_info_pid(&t_ctx->e_key);
            if (go_tp && go_tp->valid && go_tp->written) {
                h2_resume_after(msg, t_ctx, pos + k_h2_frame_header_len + f.payload_len);
                return SK_PASS;
            }

            bpf_tail_call_static(msg, &extender_jump_table, k_tail_find_existing_h2_tp);
            return SK_PASS;
        }

        pos += k_h2_frame_header_len + f.payload_len;
    }

    return SK_PASS;
}

// Validate the 3 dashes and decode trace_id + span_id into tp.
// Returns true on success.
static __always_inline bool decode_tp_value(const unsigned char *val, tp_info_t *tp) {
    if (val[k_tp_val_dash1] != '-' || val[k_tp_val_dash2] != '-' || val[k_tp_val_dash3] != '-') {
        return false;
    }
    decode_hex(tp->trace_id, &val[k_tp_val_trace_id_start], TRACE_ID_CHAR_LEN);
    decode_hex(tp->span_id, &val[k_tp_val_span_id_start], SPAN_ID_CHAR_LEN);
    tp->flags = 1;
    return true;
}

static __always_inline u32 validate_h2_tp_plain(const unsigned char *p,
                                                const unsigned char *end,
                                                tp_info_t *tp) {
    if ((void *)(p + k_h2_tp_hpack_size) > (void *)end) {
        return 0;
    }
    if (bpf_memcmp(p + k_hpack_tp_name_offset, k_hpack_tp_name, k_hpack_tp_name_len) != 0) {
        return 0;
    }
    if (p[k_hpack_tp_name_offset + k_hpack_tp_name_len] != k_hpack_value_len_tp) {
        return 0;
    }
    if (!decode_tp_value(p + k_hpack_tp_val_offset, tp)) {
        return 0;
    }
    return k_hpack_tp_val_offset + k_tp_val_span_id_start;
}

static __always_inline u32 validate_h2_tp_huffman(const unsigned char *p,
                                                  const unsigned char *end,
                                                  tp_info_t *tp) {
    if ((void *)(p + k_h2_tp_hpack_huffman_size) > (void *)end) {
        return 0;
    }
    if (bpf_memcmp(p + k_hpack_tp_name_offset, k_hpack_tp_huffman, k_hpack_tp_name_huffman_len) !=
        0) {
        return 0;
    }
    if (p[k_hpack_tp_name_offset + k_hpack_tp_name_huffman_len] != k_hpack_value_len_tp) {
        return 0;
    }
    if (!decode_tp_value(p + k_hpack_tp_val_offset_huffman, tp)) {
        return 0;
    }
    return k_hpack_tp_val_offset_huffman + k_tp_val_span_id_start;
}

static __always_inline bool
pull_hpack_window(struct sk_msg_md *msg, const u32 hpack_start, const u32 hpack_len) {
    enum { k_min_entry_plain = k_h2_tp_hpack_size };
    if (hpack_len < k_h2_tp_hpack_huffman_size) {
        return false;
    }
    const u32 pull_len = hpack_len < (k_h2_max_hpack_scan + k_min_entry_plain)
                             ? hpack_len
                             : (k_h2_max_hpack_scan + k_min_entry_plain);
    return bpf_msg_pull_data(msg, hpack_start, hpack_start + pull_len, 0) == 0;
}

// Fingerprints for full traceparent name + value-length byte (0x37).
// Values match what *(u32/u64 *)p loads on the build target, so the comparisons
// work on bpfel and bpfeb.
enum {
    k_h2_nlb_plain = k_hpack_tp_name_len,
    k_h2_nlb_huffman = k_hpack_tp_name_huffman_len | 0x80,
};
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static const u64 k_h2_tp_fp_plain_lo = 0x7261706563617274ULL; // "tracepar"
static const u32 k_h2_tp_fp_plain_hi = 0x37746e65U;           // "ent" + 0x37
static const u64 k_h2_tp_fp_huffman = 0x3fa9851d6b21834dULL;  // huffman("traceparent")
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static const u64 k_h2_tp_fp_plain_lo = 0x7472616365706172ULL; // "tracepar"
static const u32 k_h2_tp_fp_plain_hi = 0x656e7437U;           // "ent" + 0x37
static const u64 k_h2_tp_fp_huffman = 0x4d83216b1d85a93fULL;  // huffman("traceparent")
#else
#error "unsupported __BYTE_ORDER__"
#endif

static __always_inline bool match_h2_tp_plain(const unsigned char *p) {
    return *(const u64 *)(p + k_hpack_tp_name_offset) == k_h2_tp_fp_plain_lo &&
           *(const u32 *)(p + k_hpack_tp_name_offset + 8) == k_h2_tp_fp_plain_hi;
}

static __always_inline bool match_h2_tp_huffman(const unsigned char *p) {
    return *(const u64 *)(p + k_hpack_tp_name_offset) == k_h2_tp_fp_huffman &&
           p[k_hpack_tp_name_offset + k_hpack_tp_name_huffman_len] == k_hpack_value_len_tp;
}

// Returns offset of the traceparent name in HPACK, or k_h2_max_hpack_scan if not found.
static __always_inline u32 find_first_h2_tp_candidate(struct sk_msg_md *msg,
                                                      const u32 hpack_start,
                                                      const u32 hpack_len) {
    enum { k_min_entry_huffman = k_h2_tp_hpack_huffman_size };

    if (!pull_hpack_window(msg, hpack_start, hpack_len)) {
        return k_h2_max_hpack_scan;
    }
    const unsigned char *data = msg->data;
    const unsigned char *end = msg->data_end;
    if (!data) {
        return k_h2_max_hpack_scan;
    }

    for (u32 i = 0; i < k_h2_max_hpack_scan; i++) {
        if (i + k_min_entry_huffman > hpack_len) {
            break;
        }
        const unsigned char *p = data + i;
        if ((void *)(p + k_min_entry_huffman) > (void *)end) {
            break;
        }
        if (p[0] != k_hpack_literal_no_index) {
            continue;
        }
        const u8 nlb = p[1];
        if (nlb == k_h2_nlb_plain && match_h2_tp_plain(p)) {
            return i;
        }
        if (nlb == k_h2_nlb_huffman && match_h2_tp_huffman(p)) {
            return i;
        }
    }
    return k_h2_max_hpack_scan;
}

// Validate via a separate tail call — inlining under the 192-iter scan blows older verifiers.
SEC("sk_msg")
int obi_packet_extender_find_existing_h2_tp(struct sk_msg_md *msg) {
    bpf_dbg_printk("=== sk_msg find existing h2 tp ===");
    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    if (!t_ctx) {
        return SK_PASS;
    }
    t_ctx->h2_tp_candidate_pos =
        find_first_h2_tp_candidate(msg, t_ctx->h2_hpack_offset, t_ctx->h2_hpack_len);
    bpf_tail_call_static(msg, &extender_jump_table, k_tail_validate_h2_tp);
    return SK_PASS;
}

// Walk with a loop counter — pkt pointer offset by a stack-loaded scalar loses its verified range.
SEC("sk_msg")
int obi_packet_extender_validate_h2_tp(struct sk_msg_md *msg) {
    bpf_dbg_printk("=== sk_msg validate h2 tp ===");
    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    if (!t_ctx) {
        return SK_PASS;
    }
    const u32 target = t_ctx->h2_tp_candidate_pos;
    if (target >= k_h2_max_hpack_scan) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_create_h2_tp);
        return SK_PASS;
    }
    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();
    if (!tp_p) {
        return SK_PASS;
    }
    const u32 hpack_start = t_ctx->h2_hpack_offset;
    const u32 hpack_len = t_ctx->h2_hpack_len;
    if (!pull_hpack_window(msg, hpack_start, hpack_len)) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_create_h2_tp);
        return SK_PASS;
    }
    const unsigned char *data = msg->data;
    const unsigned char *end = msg->data_end;
    if (!data) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_create_h2_tp);
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
        init_tp_ctx_parent_tp(t_ctx);
        bpf_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));
        const u32 span_id_offset = hpack_start + target + off;
        if (apply_parent_tp(t_ctx, &tp_p->tp)) {
            if (bpf_msg_pull_data(msg, span_id_offset, span_id_offset + SPAN_ID_CHAR_LEN, 0) == 0) {
                unsigned char *d = msg->data;
                const unsigned char *e = msg->data_end;
                if (d && (void *)d + SPAN_ID_CHAR_LEN <= (void *)e) {
                    encode_hex(d, tp_p->tp.span_id, SPAN_ID_SIZE_BYTES);
                }
            }
        }
        tp_p->tp.ts = bpf_ktime_get_ns();
        tp_p->valid = 1;
        tp_p->written = 1;
        tp_p->pid = t_ctx->p_conn.pid;
        tp_p->req_type = EVENT_HTTP_CLIENT;
        set_tp_info_pid(&t_ctx->e_key, tp_p);
        h2_resume_after(
            msg, t_ctx, t_ctx->h2_frame_offset + k_h2_frame_header_len + t_ctx->h2_payload_len);
        return SK_PASS;
    }

    bpf_tail_call_static(msg, &extender_jump_table, k_tail_create_h2_tp);
    return SK_PASS;
}

// k_tail_create_h2_tp
SEC("sk_msg")
int obi_packet_extender_create_h2_tp(struct sk_msg_md *msg) {
    bpf_dbg_printk("=== sk_msg create h2 tp ===");

    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    if (!t_ctx) {
        return SK_PASS;
    }

    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_info_mem();
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
        set_tp_info_pid(&t_ctx->e_key, tp_p);
    } else {
        init_tp_ctx_parent_tp(t_ctx);
        if (!create_trace_info(t_ctx, tp_p)) {
            return SK_PASS;
        }
        tp_p->written = 1;
        if (bpf_map_update_elem(&outgoing_trace_map, &t_ctx->e_key, tp_p, BPF_NOEXIST) != 0) {
            existing = get_tp_info_pid(&t_ctx->e_key);
            if (existing) {
                bpf_memcpy(tp_p, existing, sizeof(*tp_p));
            }
        }
    }

    if (inject_flags & k_inject_http_headers) {
        bpf_tail_call_static(msg, &extender_jump_table, k_tail_write_h2_traceparent);
    }
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

    // bpf_msg_push_data shifted bytes after inject_offset right by
    // k_h2_tp_hpack_size, so the next batched HEADERS frame is now at
    // frame_offset + 9 + new_payload_len
    h2_resume_after(msg,
                    t_ctx,
                    t_ctx->h2_frame_offset + k_h2_frame_header_len + payload_len +
                        k_h2_tp_hpack_size);
    return SK_PASS;
}
