// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_endian.h>

#include <common/common.h>
#include <common/connection_info.h>
#include <common/egress_key.h>
#include <common/http_buf_size.h>
#include <common/http_types.h>
#include <common/msg_buffer.h>
#include <common/scratch_mem.h>
#include <common/send_args.h>
#include <common/ssl_helpers.h>
#include <common/tc_common.h>
#include <common/tp_info.h>
#include <common/trace_common.h>
#include <common/trace_util.h>
#include <common/tracing.h>

#include <generictracer/protocol_http.h>
#include <generictracer/protocol_tcp.h>
#include <generictracer/protocol_http2.h>

#include <logger/bpf_dbg.h>

#include <maps/incoming_trace_map.h>
#include <maps/msg_buffers.h>
#include <maps/ongoing_http.h>
#include <maps/sock_dir.h>
#include <maps/sock_pids.h>

#include <tpinjector/maps/extender_jump_table.h>
#include <tpinjector/maps/pid_connection_info_mem.h>
#include <tpinjector/maps/sk_tp_info_pid_map.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// Flags to control what tpinjector should inject
enum {
    k_inject_http_headers = 1 << 0, // Bit 0: inject HTTP headers
    k_inject_tcp_options = 1 << 1,  // Bit 1: inject TCP options
};

volatile const u32 inject_flags =
    k_inject_http_headers | k_inject_tcp_options; // default: both enabled

// TCP option kind for OpenTelemetry context propagation
// Kind 25 is unassigned per IANA TCP Parameters registry (released 2000-12-18)
// Better than experimental options (253-254) which must not be shipped as defaults
enum { k_tcp_option_kind_otel = 25 };

enum { k_tail_write_msg_traceparent = 0 };

SCRATCH_MEM_SIZED(tp_str_buf, 64)

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

static __always_inline pid_connection_info_t *pid_conn_info_buf() {
    const int zero = 0;
    return bpf_map_lookup_elem(&pid_connection_info_mem, &zero);
}

static __always_inline egress_key_t make_key(const connection_info_t *conn) {
    egress_key_t e_key = {
        .d_port = conn->d_port,
        .s_port = conn->s_port,
    };

    sort_egress_key(&e_key);

    return e_key;
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

static __always_inline bool
create_trace_info(u64 id, const connection_info_t *conn, tp_info_pid_t *tp_p) {
    bpf_dbg_printk("=== %s ===", __FUNCTION__);

    pid_connection_info_t *p_conn = pid_conn_info_buf();

    if (!p_conn) {
        return false;
    }

    const u32 pid = pid_from_pid_tgid(id);

    p_conn->conn = *conn;
    p_conn->pid = pid;

    tp_p->tp.ts = bpf_ktime_get_ns();
    tp_p->tp.flags = 1;
    tp_p->valid = 1;
    tp_p->written = 0;
    tp_p->pid = pid;
    tp_p->req_type = EVENT_HTTP_CLIENT; //XXX double check

    urand_bytes(tp_p->tp.span_id, SPAN_ID_SIZE_BYTES);

    if (find_trace_for_client_request(p_conn, p_conn->conn.d_port, &tp_p->tp)) {
        bpf_dbg_printk("found existing tp info");
        return true;
    }

    bpf_dbg_printk("generating tp info");

    new_trace_id(&tp_p->tp);
    __builtin_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));

    return true;
}

static __always_inline void bpf_sock_ops_set_flags(struct bpf_sock_ops *skops, u8 flags) {
    bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | flags);
}

// Helper that writes in the sock map for a sock_ops program
static __always_inline void bpf_sock_ops_active_est_cb(struct bpf_sock_ops *skops) {
    connection_info_t conn = get_connection_info_ops(skops);

    bpf_sock_hash_update(skops, &sock_dir, &conn, BPF_ANY);
    bpf_sock_ops_set_flags(skops, BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
}

static __always_inline void bpf_sock_ops_passive_est_cb(struct bpf_sock_ops *skops) {
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
        bpf_dbg_printk("bpf_sock_ops_opt_len_cb: failed to reserve TCP option: %d", ret);
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
        bpf_dbg_printk("bpf_sock_ops_write_hdr_cb: tp info not found");
        return;
    }

    struct tp_option opt = {.kind = k_tcp_option_kind_otel, .len = sizeof(struct tp_option)};

    __builtin_memcpy(opt.trace_id, tp_pid->tp.trace_id, sizeof(opt.trace_id));
    __builtin_memcpy(opt.span_id, tp_pid->tp.span_id, sizeof(opt.span_id));

    const long ret = bpf_store_hdr_opt(skops, &opt, sizeof(opt), 0);

    if (ret != 0) {
        bpf_dbg_printk("bpf_sock_ops_write_hdr_cb: failed to store option: %d", ret);
    }

    if (k_bpf_debug) {
        const char *tp_str = tp_string_from_opt(&opt);

        if (tp_str) {
            bpf_dbg_printk("bpf_sock_ops_write_hdb_cb: written TP to TCP options: %s", tp_str);
        }
    }
}

static __always_inline void bpf_sock_ops_parse_hdr_cb(struct bpf_sock_ops *skops) {
    struct tp_option opt = {};
    opt.kind = k_tcp_option_kind_otel;

    const long ret = bpf_load_hdr_opt(skops, &opt, sizeof(opt), 0);

    if (ret == -ENOMSG) {
        return;
    }

    if (ret < 0) {
        bpf_dbg_printk("bpf_sock_ops_parse_hdr_cb: error parsing TCP option = %d", ret);
        return;
    }

    if (k_bpf_debug) {
        const char *tp_str = tp_string_from_opt(&opt);

        if (tp_str) {
            bpf_dbg_printk("bpf_sock_ops_parse_hdr_cb: found TP in TCP options: %s", tp_str);
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
static __always_inline u8 protocol_detector(struct sk_msg_md *msg,
                                            u64 id,
                                            const connection_info_t *conn,
                                            const egress_key_t *e_key) {
    bpf_dbg_printk("=== [protocol detector] %d size %d===", id, msg->size);

    pid_connection_info_t p_conn = {};
    __builtin_memcpy(&p_conn.conn, conn, sizeof(connection_info_t));

    dbg_print_http_connection_info(&p_conn.conn);
    sort_connection_info(&p_conn.conn);
    p_conn.pid = pid_from_pid_tgid(id);

    if (msg->size == 0 || is_ssl_connection(&p_conn)) {
        return 0;
    }

    msg_buffer_t msg_buf = {
        .pos = 0,
        .real_size = msg->size > k_msg_buffer_size_max ? k_msg_buffer_size_max : msg->size,
        .cpu_id = bpf_get_smp_processor_id(),
    };

    bpf_probe_read_kernel(msg_buf.fallback_buf, k_kprobes_http2_buf_size, msg->data);

    const u16 copy_bytes =
        msg_buf.real_size > k_kprobes_http2_buf_size ? msg_buf.real_size : k_kprobes_http2_buf_size;

    unsigned char **msg_ptr = bpf_map_lookup_elem(&msg_buffer_mem, &(u32){0});

    if (!msg_ptr) {
        bpf_d_printk("protocol_detector: failed to reserve msg_buffer space");
        return 0;
    }

    bpf_probe_read_kernel(msg_ptr, copy_bytes & k_msg_buffer_size_max_mask, msg->data);
    bpf_map_update_elem(&msg_buffer_mem, &(u32){0}, msg_ptr, BPF_ANY);

    // We setup any call that looks like HTTP request to be extended.
    // This must match exactly to what the decision will be for
    // the kprobe program on tcp_sendmsg, which sets up the
    // outgoing_trace_map data used by Traffic Control to write the
    // actual 'Traceparent:...' string.

    if (bpf_map_update_elem(&msg_buffers, e_key, &msg_buf, BPF_ANY)) {
        // fail if we can't setup a msg buffer
        return 0;
    }

    // We should check if we have already seen this request and we've
    // started tracking it. We only want to extend the first packet that
    // looks like HTTP, not something that's passing HTTP in the body.
    if (already_tracked(&p_conn)) {
        bpf_dbg_printk("already extended before, ignoring this packet...");
        return 0;
    }

    if (is_http_request_buf((const unsigned char *)msg_ptr)) {
        bpf_dbg_printk("Setting up request to be extended");

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
    buf = check_pkt_access(buf, EXTEND_SIZE, end);

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
    *buf++ = (tp->flags == 0) ? '0' : '1';
    *buf++ = '\r';
    *buf++ = '\n';

    bpf_dbg_printk("obi_packet_extender: %s", tp_string);
}

static __always_inline bool
extend_and_write_tp(struct sk_msg_md *msg, u32 offset, const tp_info_t *tp) {
    const long err = bpf_msg_push_data(msg, offset, EXTEND_SIZE, 0);

    if (err != 0) {
        bpf_d_printk("failed to push data: %d", err);
        return false;
    }

    bpf_msg_pull_data(msg, 0, msg->size, 0);
    bpf_dbg_printk(
        "offset to split %d, available: %u, size %u", offset, msg->data_end - msg->data, msg->size);

    if (!msg->data) {
        bpf_d_printk("null data");
        return false;
    }

    unsigned char *ptr = msg->data + offset;

    if ((void *)ptr + EXTEND_SIZE >= msg->data_end) {
        bpf_d_printk("not enough space");
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
    tp_info_pid_t *tp_p = tp_buf();

    if (!tp_p) {
        return;
    }

    tp_pid->written = 1;
    *tp_p = *tp_pid;

    bpf_tail_call(msg, &extender_jump_table, k_tail_write_msg_traceparent);

    bpf_d_printk("tailcall failed");
}

static __always_inline void handle_existing_tp_pid(struct sk_msg_md *msg,
                                                   u64 id,
                                                   const connection_info_t *conn,
                                                   const egress_key_t *e_key,
                                                   tp_info_pid_t *tp_pid) {
    if (inject_flags & k_inject_tcp_options) {
        schedule_write_tcp_option(msg, tp_pid);
    }

    // shortcut: if valid == 0, this is not a HTTP request (likely SSL, but
    // could be anything really - don't bother with protocol_detector)
    if (tp_pid->valid == 0) {
        clear_tp_info_pid(e_key);
        return;
    }

    // check if this really is a HTTP request whose headers we can also extend
    // (it could be an SSL packet instead, or just rubbish, for instance)
    const bool is_http = protocol_detector(msg, id, conn, e_key);

    if (is_http) {
        // here we'll leave it for protocol_http clean it up
        if (inject_flags & k_inject_http_headers) {
            write_http_traceparent(msg, tp_pid);
        }
    } else {
        clear_tp_info_pid(e_key);
    }
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

    const u64 id = bpf_get_current_pid_tgid();
    const connection_info_t conn = get_connection_info(msg);
    const egress_key_t e_key = make_key(&conn);

    tp_info_pid_t *tp_pid = get_tp_info_pid(&e_key);

    // Higher-level uprobes have already set the tp_pid for us (either Go, or SSL)
    if (tp_pid) {
        handle_existing_tp_pid(msg, id, &conn, &e_key, tp_pid);
        return SK_PASS;
    }

    // At this stage, there were no previously TP information setup - it's the first
    // time we are seeing this packet - so we need to detect whether this is the start
    // of a new request and perform any injection if so.
    // Valid PID only works for kprobes since Go programs don't add their
    // PIDs to the PID map (we instrument the binaries), handled in the
    // previous check
    if (!valid_pid(id)) {
        return SK_PASS;
    }

    bpf_dbg_printk("MSG %llx:%d ->", conn.s_ip[3], conn.s_port);
    bpf_dbg_printk("MSG TO %llx:%d", conn.d_ip[3], conn.d_port);
    bpf_dbg_printk("MSG SIZE: %u", msg->size);

    if (msg->size <= MIN_HTTP_SIZE) {
        // not enough data to detect anything, bail
        return SK_PASS;
    }

    bpf_msg_pull_data(msg, 0, msg->size, 0);

    // TODO: execute the protocol handlers here with tail calls, don't
    // rely on tcp_sendmsg to do it and record these message buffers.

    const u8 is_http = protocol_detector(msg, id, &conn, &e_key);

    // at this point, we can't handle anything other than HTTP, as we need to be able
    // to tell whether this is the start of a new request
    if (!is_http) {
        return SK_PASS;
    }

    bpf_dbg_printk("len %d, s_port %d, buf: %s", msg->size, msg->local_port, msg->data);
    bpf_dbg_printk("ptr = %llx, end = %llx", ctx_msg_data(msg), ctx_msg_data_end(msg));
    bpf_dbg_printk("BUF: '%s'", ctx_msg_data(msg));

    // we've found the start of a new HTTP request, let's generate new TP info for it
    tp_info_pid_t *tp_p = tp_buf();

    if (!tp_p) {
        return SK_PASS;
    }

    if (!create_trace_info(id, &conn, tp_p)) {
        return SK_PASS;
    }

    tp_p->written = 1;

    // associate this tp_info to this request
    set_tp_info_pid(&e_key, tp_p);

    if (inject_flags & k_inject_tcp_options) {
        schedule_write_tcp_option(msg, tp_p);
    }

    if (inject_flags & k_inject_http_headers) {
        // write the HTTP headers
        bpf_tail_call(msg, &extender_jump_table, k_tail_write_msg_traceparent);
        bpf_d_printk("tailcall failed");
    }

    return SK_PASS;
}

//k_tail_write_msg_traceparent
SEC("sk_msg")
int obi_packet_extender_write_msg_tp(struct sk_msg_md *msg) {
    bpf_dbg_printk("== %s ==", __FUNCTION__);

    tp_info_pid_t *tp_p = tp_buf();

    if (!tp_p) {
        bpf_dbg_printk("empty tp_buf");
        return SK_PASS;
    }

    bpf_msg_pull_data(msg, 0, msg->size, 0);

    if (!write_msg_traceparent(msg, &tp_p->tp)) {
        bpf_d_printk("failed to write traceparent");
    }

    bpf_dbg_printk("BUF = [%s]", msg->data);

    return SK_PASS;
}
