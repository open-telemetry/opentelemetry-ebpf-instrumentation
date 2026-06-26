// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/runtime.h>
#include <common/scratch_mem.h>
#include <common/tp_info.h>
#include <common/trace_key.h>
#include <common/tracing.h>

#include <logger/bpf_dbg.h>

#include <maps/incoming_trace_map.h>
#include <maps/server_traces.h>

#include <shared/obi_ctx.h>

#include <socktracer/common_defs.h>
#include <socktracer/helpers.h>
#include <socktracer/http.h>
#include <socktracer/http2.h>
#include <socktracer/http2_extract.h>
#include <socktracer/maps/listener_pid_map.h>
#include <socktracer/maps/sk_data_map.h>
#include <socktracer/socket_data.h>
#include <socktracer/ssl_detect.h>
#include <socktracer/tcp.h>

char __license[] SEC("license") = "Dual MIT/GPL";

enum {
    k_payload_buf_size = 4096,
    k_payload_buf_mask = k_payload_buf_size - 1,
};

_Static_assert((k_payload_buf_size & k_payload_buf_mask) == 0,
               "k_payload_buf_size must be a power of two");

struct payload_buf {
    unsigned char data[k_payload_buf_size];
    u32 size;
    u32 payload_offset;
    u32 payload_len;
};

SCRATCH_MEM_TYPED(payload_buf, struct payload_buf);

typedef struct {
    connection_info_part_t conn_part;
    trace_key_t t_key;
} server_trace_scratch_t;

SCRATCH_MEM_TYPED(server_trace_scratch, server_trace_scratch_t);

// cgroup_skb/ingress: data pointer starts at the IP header (L3).
// We compute the TCP payload offset once in the entry program, store it in
// skb->cb[0], and all ctx_* helpers use it to hide the L3/L4 headers from the
// protocol parsers (which expect data to start at the TCP payload).

enum {
    k_ipproto_hopopts = 0,
    k_ipproto_routing = 43,
    k_ipproto_fragment = 44,
    k_ipproto_dstopts = 60,
};

static __always_inline u32 ctx_compute_payload_offset_v4(struct __sk_buff *skb) {
    void *data = ctx_skb_data(skb);
    void *data_end = ctx_skb_data_end(skb);

    const struct iphdr *ip = data;

    if ((void *)(ip + 1) > data_end) {
        return 0;
    }

    if (ip->version != 4 || ip->protocol != IPPROTO_TCP) {
        return 0;
    }

    const u32 ip_hlen = (u32)ip->ihl * 4;
    if (ip_hlen < sizeof(struct iphdr)) {
        return 0;
    }

    const struct tcphdr *tcp = data + ip_hlen;
    if ((void *)(tcp + 1) > data_end) {
        return 0;
    }

    const u32 tcp_hlen = (u32)tcp->doff * 4;
    if (tcp_hlen < sizeof(struct tcphdr)) {
        return 0;
    }

    return ip_hlen + tcp_hlen;
}

static __always_inline u32 ctx_compute_payload_offset_v6(struct __sk_buff *skb) {
    void *data = ctx_skb_data(skb);
    void *data_end = ctx_skb_data_end(skb);

    const struct ipv6hdr *ip6 = data;

    if ((void *)(ip6 + 1) > data_end) {
        return 0;
    }

    if (ip6->version != 6) {
        return 0;
    }

    const void *ptr = (const void *)(ip6 + 1);
    u8 curr_hdr = ip6->nexthdr;

    // iterate at most 4 extension headers
    for (u8 i = 0; i < 4; i++) {
        if (curr_hdr == IPPROTO_TCP) {
            break;
        }

        const struct ipv6_opt_hdr *opt_hdr = ptr;

        if ((const void *)(opt_hdr + 1) > data_end) {
            return 0;
        }

        switch (curr_hdr) {
        case k_ipproto_hopopts:
        case k_ipproto_routing:
        case k_ipproto_dstopts:
            ptr += ((u32)opt_hdr->hdrlen + 1) * 8;
            break;
        case k_ipproto_fragment:
            ptr += 8;
            break;
        default:
            return 0;
        }

        curr_hdr = opt_hdr->nexthdr;
    }

    if (curr_hdr != IPPROTO_TCP) {
        return 0;
    }

    const struct tcphdr *tcp = ptr;

    if ((const void *)(tcp + 1) > data_end) {
        return 0;
    }

    const u32 tcp_hlen = (u32)tcp->doff * 4;
    if (tcp_hlen < sizeof(struct tcphdr)) {
        return 0;
    }

    return (u32)(ptr - data) + tcp_hlen;
}

static __always_inline u32 ctx_compute_payload_offset(struct __sk_buff *skb) {
    if (skb->protocol == bpf_htons(ETH_P_IP)) {
        return ctx_compute_payload_offset_v4(skb);
    }

    if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
        return ctx_compute_payload_offset_v6(skb);
    }

    return 0;
}

static __always_inline u32 ctx_len(void *ctx) {
    (void)ctx;
    struct payload_buf *pb = payload_buf_mem();
    if (!pb) {
        return 0;
    }
    return pb->payload_len;
}

static __always_inline void ctx_pull_data(void *ctx, u32 len) {
    if (len == 0) {
        return;
    }

    struct payload_buf *pb = payload_buf_mem();

    if (!pb) {
        return;
    }

    if (pb->size >= len) {
        return;
    }

    if (len > pb->payload_len) {
        len = pb->payload_len;
    }

    if (len > sizeof(pb->data)) {
        len = sizeof(pb->data);
    }

    if (len == 0) {
        return;
    }

    if (bpf_skb_load_bytes(ctx, pb->payload_offset, pb->data, len) == 0) {
        pb->size = len;
    }
}

static __always_inline void *ctx_data(void *ctx) {
    (void)ctx;

    struct payload_buf *pb = payload_buf_mem();

    if (!pb) {
        return NULL;
    }

    return pb->data;
}

static __always_inline void *ctx_data_end(void *ctx) {
    (void)ctx;

    struct payload_buf *pb = payload_buf_mem();

    if (!pb) {
        return NULL;
    }

    return pb->data + pb->size;
}

static __always_inline void schedule_write_tcp_option(void *ctx, tp_info_pid_t *tp_p) {
    (void)ctx;
    (void)tp_p;
    // no-op - we never inject options on ingress
}

static __always_inline trace_key_t trace_key(const struct socket_data *sk_data) {
    trace_key_t t_key = {};
    t_key.p_key = sk_data->pid_key;
    t_key.extra_id = extra_runtime_id();

    return t_key;
}

static __always_inline void set_server_trace(const struct socket_data *sk_data,
                                             const tp_info_pid_t *tp_p) {
    set_trace_info_for_connection(&sk_data->sorted_conn, TRACE_TYPE_SERVER, tp_p);

    server_trace_scratch_t *scratch = server_trace_scratch_mem();

    if (!scratch) {
        return;
    }

    __builtin_memset(&scratch->conn_part, 0, sizeof(scratch->conn_part));

    populate_ephemeral_info(&scratch->conn_part,
                            &sk_data->sorted_conn,
                            sk_data->conn.d_port,
                            sk_data->pid_tgid,
                            FD_SERVER);

    bpf_dbg_printk("Saving connection server span for pid=%u, tid=%u, ephemeral_port=%u",
                   sk_data->pid_key.pid,
                   sk_data->pid_key.tid,
                   scratch->conn_part.port);

    bpf_map_update_elem(&server_traces_aux, &scratch->conn_part, tp_p, BPF_ANY);

    scratch->t_key = trace_key(sk_data);

    tp_info_pid_t *existing = bpf_map_lookup_elem(&server_traces, &scratch->t_key);

    if (existing && existing->req_type == tp_p->req_type && tp_p->req_type == EVENT_HTTP_REQUEST) {
        existing->valid = 0;
        bpf_dbg_printk("Found conflicting thread server span, marking it invalid.");
        return;
    }

    bpf_dbg_printk("Saving thread server span for ns=%u, extra_id=%llx",
                   scratch->t_key.p_key.ns,
                   scratch->t_key.extra_id);

    bpf_map_update_elem(&server_traces, &scratch->t_key, tp_p, BPF_ANY);

    obi_ctx__set(sk_data->pid_tgid, &tp_p->tp);
}

static __always_inline void set_trace(const struct socket_data *sk_data,
                                      const tp_info_pid_t *tp_p) {
    set_server_trace(sk_data, tp_p);
}

enum {
    k_tail_ingress_http_req,
    k_tail_ingress_http_create_tp,
    k_tail_ingress_http_found_tp,
    k_tail_ingress_http2,
    k_tail_ingress_tcp,
    k_tail_ingress_tcp_req,
    k_tail_ingress_h2_extract,
};

int obi_ingress_http_req(struct __sk_buff *skb);
int obi_ingress_http_create_tp(struct __sk_buff *skb);
int obi_ingress_http_found_tp(struct __sk_buff *skb);
int obi_ingress_http2(struct __sk_buff *skb);
int obi_ingress_tcp(struct __sk_buff *skb);
int obi_ingress_tcp_req(struct __sk_buff *skb);
int obi_ingress_h2_extract(struct __sk_buff *skb);

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 7);
    __uint(key_size, sizeof(u32));
    __array(values, int(void *));
} obi_ingress_progs SEC(".maps") = {
    .values = {[k_tail_ingress_http_req] = (void *)&obi_ingress_http_req,
               [k_tail_ingress_http_create_tp] = (void *)&obi_ingress_http_create_tp,
               [k_tail_ingress_http_found_tp] = (void *)&obi_ingress_http_found_tp,
               [k_tail_ingress_http2] = (void *)&obi_ingress_http2,
               [k_tail_ingress_tcp] = (void *)&obi_ingress_tcp,
               [k_tail_ingress_tcp_req] = (void *)&obi_ingress_tcp_req,
               [k_tail_ingress_h2_extract] = (void *)&obi_ingress_h2_extract},
};

static __always_inline void *prog_map() {
    return &obi_ingress_progs;
}

static __always_inline u32 tail_http_req() {
    return k_tail_ingress_http_req;
}

static __always_inline u32 tail_http_create_tp() {
    return k_tail_ingress_http_create_tp;
}

static __always_inline u32 tail_http_found_tp() {
    return k_tail_ingress_http_found_tp;
}

static __always_inline u32 tail_http2() {
    // Extract any incoming traceparent (HPACK) before emitting the buffer, so the
    // server span adopts the client's trace; obi_ingress_h2_extract tail-calls on
    // to k_tail_ingress_http2.
    return k_tail_ingress_h2_extract;
}

static __always_inline unsigned char *tp_span_id_field(tp_info_t *tp) {
    return tp->parent_id;
}

// Ingress: ctx_data()/ctx_data_end() are bounded by payload_buf (≤ 4096 bytes),
// which is less than k_large_buf_payload_max_size (16K), so at most one chunk
// is ever emitted. No loop needed — avoids verifier instruction explosion.
static __always_inline u32 send_large_buffer(void *ctx,
                                             u8 packet_type,
                                             u8 direction,
                                             connection_info_t conn_info,
                                             tp_info_t tp,
                                             u8 action,
                                             u32 max_bytes,
                                             u32 *bytes_sent,
                                             u8 *has_large_buffers) {
    const u32 remaining_len = min(ctx_len(ctx), max_bytes - *bytes_sent);

    if (remaining_len == 0) {
        return 0;
    }

    ctx_pull_data(ctx, remaining_len);

    const unsigned char *data = ctx_data(ctx);
    const unsigned char *data_end = ctx_data_end(ctx);

    if (!data || data >= data_end) {
        return 0;
    }

    tcp_large_buffer_t *buf =
        prepare_large_buffer_header(packet_type, direction, conn_info, tp, action);

    if (!buf) {
        return 0;
    }

    const u32 read_len = remaining_len & k_payload_buf_mask;
    const u32 payload_size = max(read_len, (u32)sizeof(void *));
    const u32 total_size = sizeof(tcp_large_buffer_t) + payload_size;

    if (data + read_len > data_end) {
        return 0;
    }

    bpf_probe_read_kernel(buf->buf, read_len, data);
    buf->len = read_len;

    if (bpf_ringbuf_output(&events, buf, total_size, get_flags()) != 0) {
        return 0;
    }

    *bytes_sent += read_len;
    *has_large_buffers = true;

    return read_len;
}

static __always_inline const tp_info_pid_t *
find_parent_trace_for_server_request(const connection_info_t *conn, const tp_info_t *tp) {
    //TODO: rename incoming_trace_map to something like incoming_tcp_opts
    const tp_info_pid_t *tcp_opt_tp = bpf_map_lookup_elem(&incoming_trace_map, conn);

    if (tcp_opt_tp) {
        return tcp_opt_tp;
    }

    if (disable_black_box_cp) {
        return NULL;
    }

    tp_info_pid_t *parent_tp = trace_info_for_connection(conn, TRACE_TYPE_CLIENT);

    if (!parent_tp || !correlated_requests(tp, parent_tp)) {
        return NULL;
    }

    if (parent_tp->req_type != EVENT_HTTP_CLIENT) {
        return NULL;
    }

    // We ensure that server requests match the client type, otherwise SSL
    // can often be confused with TCP.
    // TODO: really?
    parent_tp->valid = 0;

    return parent_tp;
}

static __always_inline void init_tp(struct socket_data *sk_data, tp_info_t *tp) {
    const tp_info_pid_t *parent_tp =
        find_parent_trace_for_server_request(&sk_data->sorted_conn, tp);

    if (parent_tp) {
        __builtin_memcpy(tp->trace_id, parent_tp->tp.trace_id, TRACE_ID_SIZE_BYTES);
        __builtin_memcpy(tp->parent_id, parent_tp->tp.span_id, SPAN_ID_SIZE_BYTES);
    } else {
        new_trace_id(tp);
        __builtin_memset(tp->parent_id, 0, SPAN_ID_SIZE_BYTES);
    }
}

static __always_inline void write_tp_http_header(void *ctx, tailcall_ctx *t_ctx) {
    (void)ctx;
    (void)t_ctx;
}

// k_tail_ingress_http_create_tp
SEC("cgroup_skb/ingress")
int obi_ingress_http_create_tp(struct __sk_buff *skb) {
    bpf_dbg_enter();

    return http_create_tp(skb);
}

static __always_inline void
init_span_id(const struct socket_data *sk_data, tp_info_t *tp, unsigned char *span_id) {
    (void)sk_data;
    (void)span_id;

    urand_bytes(tp->span_id, SPAN_ID_SIZE_BYTES);
}

SEC("cgroup_skb/ingress")
int obi_ingress_http_req(struct __sk_buff *skb) {
    bpf_dbg_enter();

    return http_find_tp(skb);
}

SEC("cgroup_skb/ingress")
int obi_ingress_http2(struct __sk_buff *skb) {
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

    emit_http2_buffer(skb, sk_data, k_packet_direction_ingress, NULL);

    return SK_PASS;
}

// k_tail_ingress_h2_extract: reads an incoming traceparent from the HTTP/2 HPACK
// headers and registers it as this connection's parent trace, so the server span
// emitted by obi_ingress_http2 adopts the client's trace. Non-Go servers have no
// uprobe to do this; on client-side ingress (a response) the scan finds nothing.
SEC("cgroup_skb/ingress")
int obi_ingress_h2_extract(struct __sk_buff *skb) {
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

    tp_info_t parent_tp = {0};

    if (scan_h2_ingress_tp(skb, &parent_tp)) {
        tp_info_pid_t tp_p = {0};
        tp_p.tp = parent_tp;
        tp_p.tp.ts = bpf_ktime_get_ns();
        tp_p.valid = 1;
        tp_p.written = 1;
        tp_p.pid = sk_data->pid_tgid;
        tp_p.req_type = request_type(sk_data);

        print_tp("h2: extracted ingress TP", &tp_p.tp);

        bpf_map_update_elem(&incoming_trace_map, &sk_data->sorted_conn, &tp_p, BPF_ANY);
        set_trace(sk_data, &tp_p);
    }

    bpf_tail_call_static(skb, &obi_ingress_progs, k_tail_ingress_http2);

    return SK_PASS;
}

// k_tail_ingress_http_found_tp
SEC("cgroup_skb/ingress")
int obi_ingress_http_found_tp(struct __sk_buff *skb) {
    bpf_dbg_enter();

    return http_found_tp(skb);
}

// Resolves PID info for a newly accepted socket whose pid_tgid is not yet set.
// Looks up {netns_cookie, local_port} in listener_pid_map, which is populated
// by post_bind (BPF) and backfillPidForSockets (userspace).
static __always_inline const struct listener_pid_val *
resolve_listener_pid_val(struct __sk_buff *skb) {
    const struct listener_pid_key key = {
        .netns_cookie = bpf_get_netns_cookie(skb),
        .local_port = skb->local_port,
    };

    const struct listener_pid_val *val = bpf_map_lookup_elem(&listener_pid_map, &key);

    if (val) {
        bpf_dbg_printk("resolve_pid: found pid_tgid=%llu for netns=%llu port=%u",
                       val->pid_tgid,
                       key.netns_cookie,
                       key.local_port);
    }

    return val;
}

static __always_inline void tail_call_handle_tcp(struct __sk_buff *skb,
                                                 struct socket_data *sk_data) {
    tailcall_ctx *t_ctx = tailcall_ctx_mem();

    if (!t_ctx) {
        return;
    }

    t_ctx->sock_cookie = sk_data->cookie;

    bpf_tail_call_static(skb, prog_map(), k_tail_ingress_tcp);
}

static __always_inline void obi_server_ingress(struct __sk_buff *skb, struct socket_data *sk_data) {
    bpf_dbg_enter();

    if (handle_http2(skb, sk_data)) {
        return;
    }

    if (handle_http_req(skb, sk_data)) {
        return;
    }

    tail_call_handle_tcp(skb, sk_data);
}

static __always_inline void obi_client_ingress(struct __sk_buff *skb, struct socket_data *sk_data) {
    bpf_dbg_enter();

    if (handle_http2(skb, sk_data)) {
        return;
    }

    if (handle_http_res(skb, sk_data)) {
        return;
    }

    tail_call_handle_tcp(skb, sk_data);
}

static __always_inline void update_pid(struct __sk_buff *skb, struct socket_data *sk_data) {
    if (sk_data->pid_tgid != 0) {
        return;
    }

    const struct listener_pid_val *pid_val = resolve_listener_pid_val(skb);

    if (!pid_val) {
        return;
    }

    sk_data->pid_tgid = pid_val->pid_tgid;
    sk_data->pid_info = pid_val->pid_info;
    sk_data->pid_key = pid_val->pid_key;
}

static __always_inline bool init_payload_buf(u32 payload_offset, u32 skb_len) {
    struct payload_buf *pb = payload_buf_mem();

    if (!pb) {
        return false;
    }

    pb->size = 0;
    pb->payload_offset = payload_offset;
    pb->payload_len = skb_len - payload_offset;

    return true;
}

SEC("cgroup_skb/ingress")
int obi_socket_ingress(struct __sk_buff *skb) {
    const u32 payload_offset = ctx_compute_payload_offset(skb);

    if (payload_offset == 0) {
        // not TCP
        return SK_PASS;
    }

    const u32 skb_len = skb->len & k_payload_buf_mask;

    if (skb_len == 0) {
        return SK_PASS;
    }

    if (payload_offset >= skb_len) {
        return SK_PASS;
    }

    const u64 cookie = bpf_get_socket_cookie(skb);

    struct socket_data *sk_data = bpf_map_lookup_elem(&sk_data_map, &cookie);

    if (!sk_data) {
        return SK_PASS;
    }

    update_pid(skb, sk_data);

    if (sk_data->pid_tgid == 0) {
        return SK_PASS;
    }

    if (!init_payload_buf(payload_offset, skb_len)) {
        return SK_PASS;
    }

    if (sk_data_is_ssl_ingress(sk_data, skb)) {
        bpf_dbg_printk("ingress: cookie=%llu ssl, skipping", cookie);
        return SK_PASS;
    }

    bpf_dbg_printk(
        "cookie=%llu, payload_len=%u, payload_offset=%u", cookie, ctx_len(skb), payload_offset);

    switch (sk_data->sk_type) {
    case sk_type_server:
        obi_server_ingress(skb, sk_data);
        break;
    case sk_type_client:
        obi_client_ingress(skb, sk_data);
        break;
    }

    return SK_PASS;
}

// obi_ingress_tcp handles the ongoing and response paths inline (lightweight),
// and tail-calls obi_ingress_tcp_req for new requests to avoid exceeding the
// 512-byte BPF stack limit (handle_tcp_req inlines init_tp + set_trace which
// together with the response path locals would overflow the stack).
SEC("cgroup_skb/ingress")
int obi_ingress_tcp(struct __sk_buff *skb) {
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

    // New request: tail call to keep handle_tcp_req's stack separate.
    if (sk_data->request.flags == 0) {
        bpf_tail_call_static(skb, prog_map(), k_tail_ingress_tcp_req);
        return SK_PASS;
    }

    if (sk_data->request.flags == EVENT_TCP_REQUEST) {
        tcp_req_t *tcp = &sk_data->request.tcp;
        const u8 cur_direction = tcp_direction(sk_data, k_packet_direction_ingress);

        if (tcp->direction != cur_direction) {
            handle_tcp_res(skb, sk_data);
            return SK_PASS;
        }

        // Ongoing TCP session.
        const u32 len = ctx_len(skb);
        tcp->len += len;
        tcp->end_monotime_ns = bpf_ktime_get_ns();
        send_tcp_large_buffer(skb, sk_data, k_packet_type_request, k_large_buf_action_append);
    }

    return SK_PASS;
}

SEC("cgroup_skb/ingress")
int obi_ingress_tcp_req(struct __sk_buff *skb) {
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

    handle_tcp_req(skb, sk_data, k_packet_direction_ingress);

    return SK_PASS;
}
