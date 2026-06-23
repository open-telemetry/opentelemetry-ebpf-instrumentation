// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_endian.h>

#include <common/connection_info.h>
#include <common/scratch_mem.h>
#include <common/tp_info.h>
#include <common/trace_util.h>

#include <logger/bpf_dbg.h>

#include <maps/incoming_trace_map.h>
#include <maps/sock_dir.h>

#include <pid/pid.h>

#include <socktracer/http_core.h>
#include <socktracer/tcp_core.h>
#include <socktracer/maps/listener_pid_map.h>
#include <socktracer/maps/sk_data_map.h>
#include <socktracer/maps/sk_storage_map.h>
#include <socktracer/maps/sk_tp_info_pid_map.h>
#include <socktracer/sk_storage_data.h>
#include <socktracer/socket_data.h>

static const struct socket_data _sock_data_zero = {};

char __license[] SEC("license") = "Dual MIT/GPL";

// Flags to control what socktracer should inject
enum {
    k_inject_http_headers = 1 << 0, // Bit 0: inject HTTP headers
    k_inject_tcp_options = 1 << 1,  // Bit 1: inject TCP options
};

volatile const u32 inject_flags = k_inject_http_headers | k_inject_tcp_options;

// TCP option kind for OpenTelemetry context propagation
// Kind 25 is unassigned per IANA TCP Parameters registry (released 2000-12-18)
// Better than experimental options (253-254) which must not be shipped as defaults
enum { k_tcp_option_kind_otel = 25 };

#ifndef ENOMSG
#define ENOMSG 42
#endif

SCRATCH_MEM_SIZED(tp_str_buf, 64)

static __always_inline void dbg_print_sockops_conn(const char *label, struct bpf_sock_ops *skops) {
    const u32 lip = skops->local_ip4;
    const u32 rip = skops->remote_ip4;

    bpf_printk("%s local=%u.%u.%u.%u:%u",
               label,
               lip & 0xFF,
               (lip >> 8) & 0xFF,
               (lip >> 16) & 0xFF,
               (lip >> 24) & 0xFF,
               skops->local_port);
    bpf_printk("%s remote=%u.%u.%u.%u:%u",
               label,
               rip & 0xFF,
               (rip >> 8) & 0xFF,
               (rip >> 16) & 0xFF,
               (rip >> 24) & 0xFF,
               bpf_ntohl(skops->remote_port));
}

static __always_inline struct socket_data *init_sock_data(u64 cookie) {
    // struct socket_data is too big to fit on the stack, so we 0 initialise
    // from a static (map) value
    bpf_map_update_elem(&sk_data_map, &cookie, &_sock_data_zero, BPF_ANY);

    return bpf_map_lookup_elem(&sk_data_map, &cookie);
}

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
static __always_inline connection_info_t sk_ops_extract_key_ip6(volatile struct bpf_sock_ops *ops) {
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

static __always_inline void bpf_sock_ops_tcp_connect_cb(struct bpf_sock_ops *skops) {
    const u64 cookie = bpf_get_socket_cookie(skops);
    const u64 id = bpf_get_current_pid_tgid();

    dbg_print_sockops_conn("TCP_CONNECT_CB", skops);

    if (!valid_pid(id)) {
        return;
    }

    struct bpf_sock *sk = skops->sk;

    if (!sk) {
        return;
    }

    struct socket_data *data = init_sock_data(cookie);

    if (!data) {
        return;
    }

    data->pid_tgid = id;
    data->cookie = cookie;
    data->conn = get_connection_info_ops(skops);
    data->sorted_conn = data->conn;

    sort_connection_info(&data->sorted_conn);

    data->sk_type = sk_type_client;
    data->task_tid = get_task_tid();

    task_pid(&data->pid_info);
    task_tid(&data->pid_key);

    struct sk_storage_data sk_data = {.sk_cookie = cookie};

    if (!bpf_sk_storage_get(&sk_storage_map, sk, &sk_data, BPF_SK_STORAGE_GET_F_CREATE)) {
        bpf_dbg_printk("failed to store sk_data");
    }

    bpf_dbg_printk("added socket to storage");
}

static __always_inline void bpf_sock_ops_set_flags(struct bpf_sock_ops *skops, u8 flags) {
    bpf_dbg_enter();

    bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | flags);
}

static __always_inline void bpf_sock_ops_active_est_cb(struct bpf_sock_ops *skops) {
    bpf_dbg_enter();

    const u64 cookie = bpf_get_socket_cookie(skops);

    // only track sockets that tcp_connect_cb already validated and set up
    if (!bpf_map_lookup_elem(&sk_data_map, &cookie)) {
        return;
    }

    bpf_sock_hash_update(skops, &sock_dir, (void *)&cookie, BPF_ANY);
    bpf_sock_ops_set_flags(skops, BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG | BPF_SOCK_OPS_STATE_CB_FLAG);
}

static __always_inline const struct listener_pid_val *listener_pid(struct bpf_sock_ops *skops) {
    const struct listener_pid_key lkey = {
        .netns_cookie = bpf_get_netns_cookie(skops),
        .local_port = skops->local_port,
    };

    return bpf_map_lookup_elem(&listener_pid_map, &lkey);
}

static __always_inline void bpf_sock_ops_passive_est_cb(struct bpf_sock_ops *skops) {
    struct bpf_sock *sk = skops->sk;

    if (!sk) {
        return;
    }

    // check if this socket's local port belongs to a tracked process
    const struct listener_pid_val *pid_val = listener_pid(skops);

    // we are not tracking this socket
    if (!pid_val) {
        return;
    }

    const u64 cookie = bpf_get_socket_cookie(skops);

    struct socket_data *data = init_sock_data(cookie);

    if (!data) {
        return;
    }

    data->cookie = cookie;
    data->conn = get_connection_info_ops(skops);
    data->sorted_conn = data->conn;

    sort_connection_info(&data->sorted_conn);

    data->sk_type = sk_type_server;
    data->pid_tgid = pid_val->pid_tgid;
    data->pid_info = pid_val->pid_info;
    data->pid_key = pid_val->pid_key;

    // store cookie in socket storage for sk_msg
    struct sk_storage_data sk_data = {.sk_cookie = cookie};

    if (!bpf_sk_storage_get(&sk_storage_map, sk, &sk_data, BPF_SK_STORAGE_GET_F_CREATE)) {
        bpf_dbg_printk("failed to store sk_data");
        bpf_map_delete_elem(&sk_data_map, &cookie);
        return;
    }

    bpf_sock_hash_update(skops, &sock_dir, (void *)&cookie, BPF_NOEXIST);

    bpf_sock_ops_set_flags(skops,
                           BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG | BPF_SOCK_OPS_STATE_CB_FLAG);
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

    bpf_dbg_return();
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

    bpf_dbg_return();
}

static __always_inline void bpf_sock_ops_parse_hdr_cb(struct bpf_sock_ops *skops) {
    bpf_dbg_enter();

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

    bpf_dbg_return();
}

static __always_inline bool is_sock_closing(struct bpf_sock_ops *skops) {
    switch (skops->args[1]) {
    case BPF_TCP_CLOSE:
    case BPF_TCP_CLOSE_WAIT:
    case BPF_TCP_FIN_WAIT1:
    case BPF_TCP_FIN_WAIT2:
    case BPF_TCP_LAST_ACK:
        return true;
    default:
        return false;
    }

    return false;
}

static __always_inline void bpf_sock_ops_state_cb(struct bpf_sock_ops *skops) {
    if (!is_sock_closing(skops)) {
        return;
    }

    const u64 cookie = bpf_get_socket_cookie(skops);
    bpf_printk("STATE_CB closing cookie=%llu state=%d", cookie, skops->args[1]);

    struct socket_data *sk_data = bpf_map_lookup_elem(&sk_data_map, &cookie);

    if (!sk_data) {
        return;
    }

    switch (sk_data->request.flags) {
    case EVENT_K_HTTP_REQUEST:
        finish_http_req(sk_data);
        break;
    case EVENT_TCP_REQUEST:
        finish_tcp(sk_data);
    default:
        break;
    }

    bpf_map_delete_elem(&sk_data_map, &cookie);
}

SEC("sockops")
int obi_sockmap_tracker(struct bpf_sock_ops *skops) {
    struct bpf_sock *sk = skops->sk;

    if (!sk) {
        return 1;
    }

    switch (skops->op) {
    case BPF_SOCK_OPS_TCP_CONNECT_CB:
        bpf_sock_ops_tcp_connect_cb(skops);
        break;
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
    case BPF_SOCK_OPS_STATE_CB:
        bpf_sock_ops_state_cb(skops);
        break;
    default:
        break;
    }

    return 1;
}

static __always_inline void post_bind(struct bpf_sock *sk, u32 local_port) {
    if (!sk) {
        return;
    }

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return;
    }

    const struct listener_pid_key key = {
        .netns_cookie = bpf_get_netns_cookie(sk),
        .local_port = local_port,
    };

    struct listener_pid_val val = {.pid_tgid = id};
    task_pid(&val.pid_info);
    task_tid(&val.pid_key);

    bpf_dbg_printk(
        "post_bind: netns=%llu port=%u pid_tgid=%llu", key.netns_cookie, key.local_port, id);

    bpf_map_update_elem(&listener_pid_map, &key, &val, BPF_ANY);
}

SEC("cgroup/post_bind4")
int obi_post_bind4(struct bpf_sock *sk) {
    post_bind(sk, sk->src_port);
    return 1;
}

SEC("cgroup/post_bind6")
int obi_post_bind6(struct bpf_sock *sk) {
    post_bind(sk, sk->src_port);
    return 1;
}
