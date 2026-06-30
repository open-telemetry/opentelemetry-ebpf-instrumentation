// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>

#include <common/algorithm.h>
#include <common/connection_info.h>
#include <common/egress_key.h>
#include <common/event_defs.h>
#include <common/go_grpc_client_conn.h>
#include <common/http_buf_size.h>
#include <common/http_types.h>
#include <common/scratch_mem.h>
#include <common/lw_thread.h>
#include <common/tc_common.h>
#include <common/tp_info.h>
#include <common/trace_parent.h>
#include <common/trace_util.h>
#include <common/tracing.h>

#include <logger/bpf_dbg.h>

#include <maps/outgoing_trace_map.h>
#include <maps/sock_dir.h>

#include <pid/pid.h>

#include <shared/obi_ctx.h>

#include <socktracer/common_defs.h>
#include <socktracer/helpers.h>
#include <socktracer/http.h>
#include <socktracer/http2.h>
#include <socktracer/maps/monitored_pids.h>
#include <socktracer/maps/sk_data_map.h>
#include <socktracer/maps/sk_storage_map.h>
#include <socktracer/maps/sk_tp_info_pid_map.h>
#include <socktracer/sk_storage_data.h>
#include <socktracer/socket_data.h>
#include <socktracer/ssl_detect.h>
#include <socktracer/tcp.h>

volatile const u32 track_request_headers = 0; //FIXME implement

char __license[] SEC("license") = "Dual MIT/GPL";

static __always_inline u32 ctx_len(void *ctx) {
    return ((struct sk_msg_md *)ctx)->size;
}

static __always_inline void ctx_pull_data(void *ctx, u32 len) {
    bpf_msg_pull_data(ctx, 0, len, 0);
}

static __always_inline void *ctx_data(void *ctx) {
    return ((struct sk_msg_md *)ctx)->data;
}

static __always_inline void *ctx_data_end(void *ctx) {
    return ((struct sk_msg_md *)ctx)->data_end;
}

static __always_inline pid_connection_info_t
pid_connection_info(const struct socket_data *sk_data) {
    // .pid is the u32 TGID; the raw u64 pid_tgid would truncate to the TID and
    // miss cross-tracer maps keyed by TGID (e.g. go_grpc_client_conns).
    const pid_connection_info_t p_conn = {
        .conn = sk_data->sorted_conn,
        .pid = pid_from_pid_tgid(sk_data->pid_tgid),
    };

    return p_conn;
}

static __always_inline void set_client_trace(const struct socket_data *sk_data,
                                             const tp_info_pid_t *tp_p) {
    set_trace_info_for_connection(&sk_data->sorted_conn, TRACE_TYPE_CLIENT, tp_p);

    obi_ctx__set(sk_data->pid_tgid, &tp_p->tp);
}

static __always_inline void set_trace(const struct socket_data *sk_data,
                                      const tp_info_pid_t *tp_p) {
    set_client_trace(sk_data, tp_p);
}

enum {
    k_inject_http_headers = 1 << 0,
    k_inject_tcp_options = 1 << 1,
};

volatile const u32 inject_flags = k_inject_http_headers | k_inject_tcp_options;

enum {
    k_tail_packet_extender,
    k_tail_write_msg_traceparent,
    k_tail_egress_http_req,
    k_tail_egress_http_create_tp,
    k_tail_egress_http_found_tp,
    k_tail_egress_http2,
    k_tail_egress_h2_detect,
    k_tail_egress_h2_find_existing_tp,
    k_tail_egress_h2_validate_tp,
    k_tail_egress_h2_create_tp,
    k_tail_egress_h2_write_tp,
};

int obi_packet_extender(struct sk_msg_md *msg);
int obi_packet_extender_write_msg_tp(struct sk_msg_md *msg);
int obi_egress_http_req(struct sk_msg_md *msg);
int obi_egress_http_create_tp(struct sk_msg_md *msg);
int obi_egress_http_found_tp(struct sk_msg_md *msg);
int obi_egress_http2(struct sk_msg_md *msg);
int obi_egress_h2_detect(struct sk_msg_md *msg);
int obi_egress_h2_find_existing_tp(struct sk_msg_md *msg);
int obi_egress_h2_validate_tp(struct sk_msg_md *msg);
int obi_egress_h2_create_tp(struct sk_msg_md *msg);
int obi_egress_h2_write_tp(struct sk_msg_md *msg);

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 11);
    __uint(key_size, sizeof(u32));
    __array(values, int(void *));
} obi_egress_progs SEC(".maps") = {
    .values =
        {
            [k_tail_packet_extender] = (void *)&obi_packet_extender,
            [k_tail_write_msg_traceparent] = (void *)&obi_packet_extender_write_msg_tp,
            [k_tail_egress_http_req] = (void *)&obi_egress_http_req,
            [k_tail_egress_http_create_tp] = (void *)&obi_egress_http_create_tp,
            [k_tail_egress_http_found_tp] = (void *)&obi_egress_http_found_tp,
            [k_tail_egress_http2] = (void *)&obi_egress_http2,
            [k_tail_egress_h2_detect] = (void *)&obi_egress_h2_detect,
            [k_tail_egress_h2_find_existing_tp] = (void *)&obi_egress_h2_find_existing_tp,
            [k_tail_egress_h2_validate_tp] = (void *)&obi_egress_h2_validate_tp,
            [k_tail_egress_h2_create_tp] = (void *)&obi_egress_h2_create_tp,
            [k_tail_egress_h2_write_tp] = (void *)&obi_egress_h2_write_tp,
        },
};

static __always_inline void *prog_map() {
    return &obi_egress_progs;
}

static __always_inline u32 tail_http_req() {
    return k_tail_egress_http_req;
}

static __always_inline u32 tail_http_create_tp() {
    return k_tail_egress_http_create_tp;
}

static __always_inline u32 tail_http_found_tp() {
    return k_tail_egress_http_found_tp;
}

static __always_inline u32 tail_http2() {
    return k_tail_egress_http2;
}

static __always_inline unsigned char *tp_span_id_field(tp_info_t *tp) {
    return tp->span_id;
}

// Egress: ctx_data()/ctx_data_end() point into live sk_msg data which may be
// larger than payload_buf, so we need the full multi-chunk loop.
static __always_inline u32 send_large_buffer(void *ctx,
                                             u8 packet_type,
                                             u8 direction,
                                             connection_info_t conn_info,
                                             tp_info_t tp,
                                             u8 action,
                                             u32 max_bytes,
                                             u32 *bytes_sent,
                                             u8 *has_large_buffers) {
    u32 remaining_len = min(ctx_len(ctx), max_bytes - *bytes_sent);

    ctx_pull_data(ctx, remaining_len);

    const unsigned char *data = ctx_data(ctx);
    const unsigned char *data_end = ctx_data_end(ctx);

    tcp_large_buffer_t *buf =
        prepare_large_buffer_header(packet_type, direction, conn_info, tp, action);

    if (!buf) {
        return 0;
    }

    const u32 offset = emit_large_buffer_chunks(buf, data, data_end, remaining_len);

    if (offset > 0) {
        *bytes_sent += offset;
        *has_large_buffers = true;
    }

    return offset;
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

static __always_inline void clear_tp_info_pid(const egress_key_t *e_key) {
    bpf_map_delete_elem(&outgoing_trace_map, e_key);
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

static __always_inline void schedule_write_tcp_option(void *ctx, tp_info_pid_t *tp_p) {
    if (!(inject_flags & k_inject_tcp_options)) {
        return;
    }

    struct sk_msg_md *msg = (struct sk_msg_md *)ctx;

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
    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_buf_mem();

    if (!tp_p) {
        return;
    }

    tp_pid->written = 1;
    *tp_p = *tp_pid;

    bpf_tail_call_static(msg, &obi_egress_progs, k_tail_write_msg_traceparent);

    bpf_d_printk("tailcall failed [%s]", __FUNCTION__);
}

static __always_inline bool backfill_pid_from_current(struct socket_data *sk_data) {
    if (sk_data->pid_tgid != 0) {
        return true;
    }

    const u64 id = bpf_get_current_pid_tgid();

    if (filter_pids && !socktracer_pid_monitored(id)) {
        return false;
    }

    sk_data->pid_tgid = id;
    sk_data->task_tid = get_task_tid();
    task_pid(&sk_data->pid_info);
    task_tid(&sk_data->pid_key);

    return true;
}

static __always_inline bool backfill_pid(struct sk_msg_md *msg,
                                         struct socket_data *sk_data,
                                         const struct sk_storage_data *sk_storage) {
    (void)msg;
    (void)sk_storage;

    // pid not registered yet; leave pid_tgid=0 so a later egress call retries.
    return backfill_pid_from_current(sk_data);
}

static __always_inline void obi_server_egress(struct sk_msg_md *msg, struct socket_data *sk_data) {
    bpf_dbg_enter();

    if (handle_http2(msg, sk_data)) {
        return;
    }

    if (handle_http_res(msg, sk_data)) {
        return;
    }

    handle_tcp(msg, sk_data, k_packet_direction_egress);
}

// checks whether a higher-level uprobe has set a TP for this connection (e.g. SSL or go)
static __always_inline bool handle_uprobe_tp(struct sk_msg_md *msg, struct socket_data *sk_data) {
    const egress_key_t e_key = make_egress_key(&sk_data->conn);
    tp_info_pid_t *tp_pid = get_tp_info_pid(&e_key);

    if (!tp_pid) {
        return false;
    }

    // if valid == 0, this not a HTTP request (likely SSL, but could be anything) so we only
    // inject the TCP options and move on
    if (tp_pid->valid == 0) {
        schedule_write_tcp_option(msg, tp_pid);
        clear_tp_info_pid(&e_key);
        sk_data->request.flags = k_request_uprobe_handled;
        return true;
    }

    // go (valid==1): the go uprobe already generated the span. For Go gRPC it also
    // wrote the traceparent into the HTTP/2 HPACK headers in the user buffer, so
    // writing an HTTP/1 Traceparent header here would corrupt the frame — inject
    // only the TCP option for those. Plain HTTP/1 still gets the header.
    schedule_write_tcp_option(msg, tp_pid);

    const pid_connection_info_t p_conn = pid_connection_info(sk_data);

    if (!is_go_grpc_client_conn(&p_conn) && (inject_flags & k_inject_http_headers)) {
        write_http_traceparent(msg, tp_pid);
    }

    clear_tp_info_pid(&e_key);

    sk_data->request.flags = k_request_uprobe_handled;

    return true;
}

static __always_inline void obi_client_egress(struct sk_msg_md *msg, struct socket_data *sk_data) {
    bpf_dbg_enter();

    const bool is_ssl = sk_data_is_ssl_egress(sk_data, msg);
    const bool uprobe_handled = handle_uprobe_tp(msg, sk_data);

    if (is_ssl || uprobe_handled) {
        return;
    }

    // Generic (non-uprobe) injection is only for kprobe-tracked pids; Go/SSL
    // clients already injected above via handle_uprobe_tp.
    if (filter_pids) {
        pid_data_t owner = {.pid = sk_data->pid_key.pid, .ns = sk_data->pid_key.ns};
        if (!pid_matches(&owner)) {
            return;
        }
    }

    if (handle_http2(msg, sk_data)) {
        return;
    }

    if (handle_http_req(msg, sk_data)) {
        return;
    }

    handle_tcp(msg, sk_data, k_packet_direction_egress);
}

SEC("sk_msg")
int obi_socket_egress(struct sk_msg_md *msg) {
    const struct sk_storage_data *sk_storage =
        bpf_sk_storage_get(&sk_storage_map, msg->sk, NULL, 0);

    if (!sk_storage) {
        return SK_PASS;
    }

    struct socket_data *sk_data = bpf_map_lookup_elem(&sk_data_map, &sk_storage->sk_cookie);

    if (!sk_data) {
        bpf_printk(": cookie=%llu not in sk_dategressa_map, cleaning up storage",
                   sk_storage->sk_cookie);

        bpf_sk_storage_delete(&sk_storage_map, msg->sk);

        return SK_PASS;
    }

    // pid not resolved yet; if backfill cannot claim it for a tracked pid, stop tracking
    if (sk_data->pid_tgid == 0 && !backfill_pid(msg, sk_data, sk_storage)) {
        return SK_PASS;
    }

    bpf_dbg_printk("cookie=%llu, size=%u", sk_storage->sk_cookie, msg->size);

    switch (sk_data->sk_type) {
    case sk_type_server:
        obi_server_egress(msg, sk_data);
        break;
    case sk_type_client:
        obi_client_egress(msg, sk_data);
        break;
    }

    return SK_PASS;
}

SEC("sk_msg")
int obi_packet_extender(struct sk_msg_md *msg) {
    bpf_dbg_enter();

    bpf_tail_call_static(msg, &obi_egress_progs, k_tail_egress_http_req);

    return SK_PASS;
}

//k_tail_write_msg_traceparent
SEC("sk_msg")
int obi_packet_extender_write_msg_tp(struct sk_msg_md *msg) {
    bpf_dbg_enter();

    tp_info_pid_t *tp_p = (tp_info_pid_t *)tp_buf_mem();

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

static __always_inline void
init_span_id(const struct socket_data *sk_data, tp_info_t *tp, unsigned char *span_id) {
    const pid_connection_info_t p_conn = pid_connection_info(sk_data);

    tp_info_t parent_tp = {.ts = bpf_ktime_get_ns(), .flags = 1};

    const bool has_parent = find_parent_trace_for_client_request(
        &p_conn, sk_data->conn.d_port, k_lw_thread_none, &parent_tp);

    if (!has_parent) {
        return;
    }

    // trace ids differ: not the parent of this outgoing span
    if (__bpf_memcmp(tp->trace_id, parent_tp.trace_id, TRACE_ID_SIZE_BYTES) != 0) {
        return;
    }

    __builtin_memcpy(tp->parent_id, parent_tp.span_id, SPAN_ID_SIZE_BYTES);

    // check if the TP we parsed is a legimate one, or a
    // proxy-forwarded header - in which case we need to
    // override it
    if (__bpf_memcmp(tp->span_id, parent_tp.parent_id, SPAN_ID_SIZE_BYTES) != 0) {
        return;
    }

    // at this point, the span id of this outgoing call is equal to the span
    // id of the parent call (i.e. the Traceparent header is the same), which
    // hints it's being forwarded by some kind of proxy - in this case, we
    // generate a new span id and overwrite the header

    bpf_dbg_printk("detected forwarded TP header, overriding span id");

    urand_bytes(tp->span_id, SPAN_ID_SIZE_BYTES);

    encode_hex(span_id, tp->span_id, SPAN_ID_SIZE_BYTES);
}

//k_tail_egress_http_req
SEC("sk_msg")
int obi_egress_http_req(struct sk_msg_md *msg) {
    bpf_dbg_enter();

    return http_find_tp(msg);
}

static __always_inline void init_tp(struct socket_data *sk_data, tp_info_t *tp) {
    const pid_connection_info_t p_conn = pid_connection_info(sk_data);

    tp_info_t parent_tp = {.ts = bpf_ktime_get_ns(), .flags = 1};

    const bool has_parent = find_parent_trace_for_client_request(
        &p_conn, sk_data->conn.d_port, k_lw_thread_none, &parent_tp);

    if (has_parent) {
        __builtin_memcpy(tp->trace_id, &parent_tp.trace_id, TRACE_ID_SIZE_BYTES);
        __builtin_memcpy(tp->parent_id, &parent_tp.span_id, SPAN_ID_SIZE_BYTES);
    } else {
        new_trace_id(tp);
        __builtin_memset(tp->parent_id, 0, SPAN_ID_SIZE_BYTES);
    }
}

static __always_inline void write_tp_http_header(void *ctx, tailcall_ctx *t_ctx) {
    (void)t_ctx;

    if (!(inject_flags & k_inject_http_headers)) {
        return;
    }

    // write the HTTP headers
    bpf_tail_call_static(ctx, &obi_egress_progs, k_tail_write_msg_traceparent);
    bpf_d_printk("tailcall failed [%s]", __FUNCTION__);
}

// Included here (not at the top): the HTTP/2 injection chain calls init_tp,
// init_span_id, get_tp_info_pid and schedule_write_tcp_option, which are defined
// above as __always_inline statics and so must be visible before use.
#include <socktracer/http2_inject.h>

//k_tail_egress_http_create_tp
SEC("sk_msg")
int obi_egress_http_create_tp(struct sk_msg_md *msg) {
    bpf_dbg_enter();

    return http_create_tp(msg);
}

//k_tail_egress_http_found_tp
SEC("sk_msg")
int obi_egress_http_found_tp(struct sk_msg_md *msg) {
    bpf_dbg_enter();

    return http_found_tp(msg);
}

SEC("sk_msg")
int obi_egress_http2(struct sk_msg_md *msg) {
    bpf_dbg_enter();

    tailcall_ctx *t_ctx = tailcall_ctx_mem();

    if (!t_ctx) {
        return SK_PASS;
    }

    const u64 cookie = t_ctx->sock_cookie;

    struct socket_data *sk_data = bpf_map_lookup_elem(&sk_data_map, &cookie);

    if (!sk_data) {
        return SK_PASS;
    }

    tp_info_t emitted_tp = {0};
    emit_http2_buffer(msg, sk_data, k_packet_direction_egress, &emitted_tp);

    // Inject HPACK on the client side only; responses/server push must not be rewritten.
    if (sk_data->sk_type != sk_type_client) {
        return SK_PASS;
    }

    t_ctx->p_conn = pid_connection_info(sk_data);

    // Go gRPC clients inject HPACK via the gotracer uprobe; don't double-inject.
    if (is_go_grpc_client_conn(&t_ctx->p_conn)) {
        return SK_PASS;
    }

    // Carry the emitted client span's tp so the inject chain reuses it (one tp per
    // stream for both the span and the wire, like the generictracer).
    __builtin_memcpy(t_ctx->emit_trace_id, emitted_tp.trace_id, TRACE_ID_SIZE_BYTES);
    __builtin_memcpy(t_ctx->emit_span_id, emitted_tp.span_id, SPAN_ID_SIZE_BYTES);

    t_ctx->e_key = make_egress_key(&sk_data->conn);
    t_ctx->h2_frames = 0;
    t_ctx->h2_scan_pos = 0;

    bpf_tail_call_static(msg, &obi_egress_progs, k_tail_egress_h2_detect);

    return SK_PASS;
}

// HTTP/2 HPACK traceparent injection chain (client egress only); logic in
// socktracer/http2_inject.h. Kept as separate tail-call stages for the verifier.
SEC("sk_msg")
int obi_egress_h2_detect(struct sk_msg_md *msg) {
    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    if (!t_ctx) {
        return SK_PASS;
    }
    return obi_egress_h2_detect_step(msg, t_ctx);
}

SEC("sk_msg")
int obi_egress_h2_find_existing_tp(struct sk_msg_md *msg) {
    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    if (!t_ctx) {
        return SK_PASS;
    }
    return obi_egress_h2_find_existing_step(msg, t_ctx);
}

SEC("sk_msg")
int obi_egress_h2_validate_tp(struct sk_msg_md *msg) {
    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    if (!t_ctx) {
        return SK_PASS;
    }
    return obi_egress_h2_validate_step(msg, t_ctx);
}

SEC("sk_msg")
int obi_egress_h2_create_tp(struct sk_msg_md *msg) {
    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    if (!t_ctx) {
        return SK_PASS;
    }
    return obi_egress_h2_create_step(msg, t_ctx);
}

SEC("sk_msg")
int obi_egress_h2_write_tp(struct sk_msg_md *msg) {
    tailcall_ctx *t_ctx = tailcall_ctx_mem();
    if (!t_ctx) {
        return SK_PASS;
    }
    return obi_egress_h2_write_step(msg, t_ctx);
}
