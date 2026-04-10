// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/backup_buffer.h>
#include <common/common.h>
#include <common/connection_info.h>
#include <common/http_types.h>
#include <common/iov_iter.h>
#include <common/msg_buffer.h>
#include <common/protocol_defs.h>
#include <common/sock_port_ns.h>
#include <common/sockaddr.h>
#include <common/ssl_connection.h>
#include <common/ssl_helpers.h>
#include <common/tc_common.h>
#include <common/tcp_info.h>
#include <common/tracked_connection.h>

#include <generictracer/dns.h>
#include <generictracer/k_send_receive.h>
#include <generictracer/k_tracer_defs.h>
#include <generictracer/k_unix_sock.h>
#include <generictracer/maps/active_accept_args.h>
#include <generictracer/maps/active_connect_args.h>
#include <generictracer/maps/listening_ports.h>
#include <generictracer/maps/sock_filter_buffers.h>
#include <generictracer/maps/tcp_connection_map.h>
#include <generictracer/protocol_common.h>
#include <generictracer/protocol_http.h>
#include <generictracer/protocol_http2.h>
#include <generictracer/protocol_mysql.h>
#include <generictracer/protocol_postgres.h>
#include <generictracer/protocol_tcp.h>
#include <generictracer/ssl_defs.h>

#include <maps/ongoing_http2_connections.h>

#include <logger/bpf_dbg.h>

#include <maps/connection_tracker.h>
#include <maps/fd_map.h>
#include <maps/filter_ports.h>
#include <maps/fd_to_connection.h>
#include <maps/msg_buffers.h>
#include <maps/sock_pids.h>
#include <maps/unreadable_buffer_ports.h>
#include <pid/pid.h>

#include <shared/obi_ctx.h>

SCRATCH_MEM_TYPED(backup_buffer, backup_buffer_t)

// Used by accept to grab the sock details
SEC("kprobe/security_socket_accept")
int BPF_KPROBE(obi_kprobe_security_socket_accept, struct socket *sock, struct socket *newsock) {
    (void)ctx;
    (void)sock;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== kprobe/security_socket_accept id=%llx ===", id);

    const u64 addr = (u64)newsock;

    sock_args_t args = {0};

    args.addr = addr;

    // The socket->sock is not valid until accept finishes, therefore
    // we don't extract ->sock here, we remember the address of socket
    // and parse in sys_accept
    bpf_map_update_elem(&active_accept_args, &id, &args, BPF_ANY);

    return 0;
}

// We tap into both sys_accept and sys_accept4.
// We don't care about the accept entry arguments, since we get only peer information
// we don't have the full picture for the socket.
//
// Note: A current limitation is that likely we won't capture the first accept request. The
// process may have already reached accept, before the instrumenter has launched.
SEC("kretprobe/sys_accept4")
int BPF_KRETPROBE(obi_kretprobe_sys_accept4, s32 fd) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();
    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== kretprobe/sys_accept4 id=%d, fd=%d ===", id, fd);

    // The file descriptor is the value returned from the accept4 syscall.
    // If we got a negative file descriptor we don't have a connection
    if (fd < 0) {
        goto cleanup;
    }

    sock_args_t *args = bpf_map_lookup_elem(&active_accept_args, &id);
    if (!args) {
        bpf_dbg_printk("No accept sock info, id=%d", id);
        goto cleanup;
    }

    struct socket *sock = (struct socket *)args->addr;
    struct sock *sk = BPF_CORE_READ(sock, sk);
    struct sock_port_ns np = sock_port_ns_from_sk(sk);

    bpf_dbg_printk("port=%d, ns=%d", np.port, np.netns);

    bpf_map_update_elem(&listening_ports, &np, &(bool){true}, BPF_ANY);
    bpf_map_update_elem(&filter_ports, &np.port, &(bool){true}, BPF_ANY);

    ssl_pid_connection_info_t info = {};

    if (parse_accept_socket_info(args, &info.p_conn.conn)) {
        const u32 host_pid = pid_from_pid_tgid(id);
        // store fd to connection mapping
        store_accept_fd_info(host_pid, fd, &info.p_conn.conn);

        const u16 orig_dport = info.p_conn.conn.d_port;
        dbg_print_http_connection_info(&info.p_conn.conn);
        sort_connection_info(&info.p_conn.conn);
        info.p_conn.pid = host_pid;
        info.orig_dport = orig_dport;

        // to support SSL on missing handshake
        bpf_map_update_elem(&pid_tid_to_conn, &id, &info, BPF_ANY);

        const fd_key key = {.pid_tgid = id, .fd = fd};

        // used by nodejs to track the fd of incoming connections - see
        // find_nodejs_parent_trace() for usage
        // TODO: try to merge with store_accept_fd_info() above
        bpf_map_update_elem(&fd_to_connection, &key, &info.p_conn.conn, BPF_ANY);

        tracked_connection_t t_conn = {
            .time = bpf_ktime_get_ns(),
            .direction = TCP_RECV,
        };

        bpf_map_update_elem(&connection_tracker, &info.p_conn.conn, &t_conn, BPF_ANY);
    } else {
        bpf_dbg_printk("Failed to parse accept socket info");
    }

cleanup:
    bpf_map_delete_elem(&active_accept_args, &id);
    return 0;
}

SEC("kprobe/sys_connect")
int BPF_KPROBE(obi_kprobe_sys_connect) {
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    // unwrap fd because of sys call
    int fd;
    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    bpf_probe_read(&fd, sizeof(int), (void *)&PT_REGS_PARM1(__ctx));

    bpf_dbg_printk("=== kprobe/sys_connect id=%d, fd=%d ===", id, fd);

    sock_args_t args = {0};
    args.fd = fd;
    args.ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&active_connect_args, &id, &args, BPF_ANY);

    return 0;
}

static __always_inline void store_sock_pid(struct sock *sk) {
    connection_info_t conn;
    if (parse_sock_info(sk, &conn)) {
        sort_connection_info(&conn);

        conn_pid_t conn_pid = {0};
        task_pid(&conn_pid.p_info);
        task_tid(&conn_pid.p_key);
        conn_pid.id = bpf_get_current_pid_tgid();
        conn_pid.ts = bpf_ktime_get_ns();

        bpf_map_update_elem(&sock_pids, &conn, &conn_pid, BPF_ANY);
    }
}

// Used by connect so that we can grab the sock details
SEC("kprobe/tcp_connect")
int BPF_KPROBE(obi_kprobe_tcp_connect, struct sock *sk) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    store_sock_pid(sk);

    sock_args_t *args = bpf_map_lookup_elem(&active_connect_args, &id);

    bpf_dbg_printk("=== kprobe/tcp_connect id=%llx, args=%llx ===", id, args);

    if (args) {
        pid_connection_info_t p_conn = {0};
        if (parse_connect_sock_info(args, &p_conn.conn)) {
            const u32 host_pid = pid_from_pid_tgid(id);
            p_conn.pid = host_pid;
            // clean-up any stale connect info
            bpf_map_delete_elem(&cp_support_connect_info, &p_conn);
        }

        args->addr = (u64)sk;
    }

    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(obi_kprobe_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== kprobe/udp_sendmsg id=%llx, sock=%llx, len=%d ===", id, sk, len);

    store_sock_pid(sk);

    send_args_t s_args = {.size = len};

    if (parse_sock_info(sk, &s_args.p_conn.conn)) {
        const u16 orig_dport = s_args.p_conn.conn.d_port;
        dbg_print_http_connection_info(&s_args.p_conn.conn);
        if (is_dns(&s_args.p_conn.conn)) {
            sort_connection_info(&s_args.p_conn.conn);
            s_args.p_conn.pid = pid_from_pid_tgid(id);
            s_args.orig_dport = orig_dport;

            unsigned char *buf = iovec_memory();
            if (buf) {
                len = read_msghdr_buf(msg, buf, len);
                if (len) {
                    bpf_dbg_printk("Got buffer with len: %d", len);
                    handle_dns_buf(buf, len, &s_args.p_conn, orig_dport);
                }
            }
        }
    }

    return 0;
}

static __always_inline void cp_support_established(pid_connection_info_t *p_conn) {
    cp_support_data_t *cp_support = bpf_map_lookup_elem(&cp_support_connect_info, p_conn);
    if (cp_support) {
        cp_support->established = 1;
    }
}

// This helper sets up a map for tracking server to client calls, when
// the connection between the two is unclear by just tracking the threads.
// With thread pools, often times the connect call happens on the same thread
// as the one serving the server request, and it's later delegated to another
// thread to handle the client request.
static __always_inline void setup_cp_support_conn_info(pid_connection_info_t *p_conn,
                                                       u8 real_client) {
    cp_support_data_t ct = {
        .real_client = real_client,
        .established = 0,
        .failed = 0,
    };

    if (!real_client) {
        ct.established = 1;
    }

    task_tid(&ct.t_key.p_key);
    ct.t_key.extra_id = extra_runtime_id();
    ct.ts = bpf_ktime_get_ns();

    // Support connection thread pools
    bpf_map_update_elem(&cp_support_connect_info, p_conn, &ct, BPF_ANY);
}

// We tap into sys_connect so we can track properly the processes doing
// HTTP client calls
SEC("kretprobe/sys_connect")
int BPF_KRETPROBE(obi_kretprobe_sys_connect, int res) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk(
        "=== kretprobe/sys_connect id=%d, pid=%d, res=%d ===", id, pid_from_pid_tgid(id), res);

    // The file descriptor is the value returned from the connect syscall.
    // If we got a negative file descriptor we don't have a connection, unless we are in progress
    if (res < 0 && (res != -EINPROGRESS)) {
        goto cleanup;
    }

    sock_args_t *args = bpf_map_lookup_elem(&active_connect_args, &id);
    if (!args) {
        bpf_dbg_printk("No sock info, id=%d", id);
        goto cleanup;
    }

    ssl_pid_connection_info_t info = {};

    if (parse_connect_sock_info(args, &info.p_conn.conn)) {
        const u32 host_pid = pid_from_pid_tgid(id);
        info.p_conn.pid = host_pid;
        bpf_dbg_printk("id=%d, pid=%d, fd=%d", id, host_pid, args->fd);
        store_connect_fd_info(host_pid, args->fd, &info.p_conn.conn);

        const u16 orig_dport = info.p_conn.conn.d_port;
        dbg_print_http_connection_info(&info.p_conn.conn);
        sort_connection_info(&info.p_conn.conn);
        info.orig_dport = orig_dport;

        bpf_map_update_elem(&pid_tid_to_conn, &id, &info, BPF_ANY); // Support SSL lookup

        setup_cp_support_conn_info(&info.p_conn, true);

        tracked_connection_t t_conn = {
            .time = bpf_ktime_get_ns(),
            .direction = TCP_SEND,
        };

        bpf_map_update_elem(&connection_tracker, &info.p_conn.conn, &t_conn, BPF_ANY);

        if (args->failed) {
            cp_support_data_t *cp_data =
                bpf_map_lookup_elem(&cp_support_connect_info, &info.p_conn);
            bpf_dbg_printk("args=%llx, failed=%d, cp_data=%llx", args, args->failed, cp_data);
            if (cp_data) {
                cp_data->failed = 1;
            }
        }
    }

cleanup:
    bpf_map_delete_elem(&active_connect_args, &id);
    return 0;
}

static __always_inline void
tcp_send_ssl_check(u64 id, void *ssl, pid_connection_info_t *p_conn, u16 orig_dport) {
    bpf_dbg_printk("id=%d, ssl=%llx", id, ssl);
    if (!ssl) {
        return;
    }
    ssl_pid_connection_info_t *s_conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);
    if (s_conn) {
        finish_possible_delayed_tls_http_request(&s_conn->p_conn, ssl);
    }
    ssl_pid_connection_info_t ssl_conn = {
        .orig_dport = orig_dport,
    };
    __builtin_memcpy(&ssl_conn.p_conn, p_conn, sizeof(pid_connection_info_t));
    bpf_map_update_elem(&ssl_to_conn, &ssl, &ssl_conn, BPF_ANY);
}

static __always_inline void
setup_connection_to_pid_mapping(u64 id, pid_connection_info_t *p_conn, u16 orig_dport) {
    ssl_pid_connection_info_t *prev_info = bpf_map_lookup_elem(&pid_tid_to_conn, &id);
    // We only update here when we don't know the direction if we haven't previously
    // set the information in sys_accept or sys_connect
    if (!prev_info || (prev_info->p_conn.conn.d_port != p_conn->conn.d_port) ||
        (prev_info->p_conn.conn.s_port != p_conn->conn.s_port)) {
        ssl_pid_connection_info_t ssl_conn = {0};
        ssl_conn.orig_dport = orig_dport;
        ssl_conn.p_conn = *p_conn;

        bpf_map_update_elem(&pid_tid_to_conn, &id, &ssl_conn, BPF_ANY);
    }
}

// Main HTTP read and write operations are handled with tcp_sendmsg and tcp_recvmsg

// The size argument here will be always the total response size.
// However, the return value of tcp_sendmsg tells us how much it sent. When the
// response is large it will get chunked, so we have to use a kretprobe to
// finish the request event, otherwise we won't get accurate timings.
// The problem is that kretprobes can be skipped, otherwise we could always just
// finish the request on the return of tcp_sendmsg. Therefore for any request less
// than 1MB we just finish the request on the kprobe path.
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(obi_kprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== kprobe/tcp_sendmsg id=%d, sock=%llx, size=%d ===", id, sk, size);

    send_args_t s_args = {.size = size, .buffer_read = 0};

    if (parse_sock_info(sk, &s_args.p_conn.conn)) {
        const u16 orig_dport = s_args.p_conn.conn.d_port;
        dbg_print_http_connection_info(
            &s_args.p_conn.conn); // commented out since GitHub CI doesn't like this call
        // Create the egress key before we sort the connection info.
        egress_key_t e_key = make_egress_key(&s_args.p_conn.conn);
        sort_connection_info(&s_args.p_conn.conn);
        s_args.p_conn.pid = pid_from_pid_tgid(id);
        s_args.orig_dport = orig_dport;

        cp_support_established(&s_args.p_conn);
        connect_ssl_to_connection(id, &s_args.p_conn, TCP_SEND, orig_dport);
        setup_connection_to_pid_mapping(id, &s_args.p_conn, orig_dport);

        u64 *ssl = is_ssl_connection(&s_args.p_conn);
        if (size > 0) {
            if (!ssl) {
                unsigned char *buf = iovec_memory();
                if (buf) {
                    size = read_msghdr_buf(msg, buf, size);

                    // If a sock_msg program is installed, this kprobe will fail to
                    // read anything, because the data is in bvec physical pages. However,
                    // the sock_msg will setup a buffer for us if this is the case. We
                    // look up this buffer and use it instead of what we'd get from
                    // calling read_msghdr_buf.
                    if (!size) {
                        msg_buffer_t *m_buf = bpf_map_lookup_elem(&msg_buffers, &e_key);
                        bpf_dbg_printk("No size, m_buf=%llx", m_buf);
                        if (m_buf) {
                            const u32 cpu_id = bpf_get_smp_processor_id();
                            if (m_buf->cpu_id != cpu_id) {
                                bpf_dbg_printk(
                                    "cpu id mismatch, using stack-allocated fallback buffer");
                                buf = m_buf->fallback_buf;
                            } else {
                                buf = bpf_map_lookup_elem(&msg_buffer_mem, &(u32){0});
                                if (!buf) {
                                    bpf_dbg_printk("failed to get msg_buffer");
                                    return 0;
                                }
                            }

                            // The buffer setup for us by a sock_msg program is always the
                            // full buffer, but when we extend a packet to be able to inject
                            // a Traceparent field, it will actually be split in 3 chunks:
                            // [before the injected header],[70 bytes for 'Traceparent...'],[the rest].
                            // We don't want the handle_buf_with_connection logic to run more than
                            // once on the same data, so if we find a buf we send all of it to the
                            // handle_buf_with_connection logic and then mark it as seen by making
                            // m_buf->pos be the size of the buffer.
                            if (!m_buf->pos) {
                                size = m_buf->real_size;
                                m_buf->pos = size;
                                bpf_dbg_printk("msg_buffer: size=%d, buf=[%s]", size, buf);
                            } else {
                                size = 0;
                            }
                        }
                    }

                    // We couldn't find a buffer, for now we just mark the arguments as failed
                    // and see if on the kretprobe we'll have a backup buffer setup for us
                    // by the socket filter program.
                    if (!size) {
                        s_args.size = -1;
                        bpf_map_update_elem(&active_send_args, &id, &s_args, BPF_ANY);
                        // At this point send_msg couldn't read the buffer, likely it's
                        // kernel bvec. We inform the socket filter that it needs to capture
                        // the buffer for us by storing into the backup buffers map, and
                        // then the return probe on send_msg will finish the work.
                        backup_buffer_t backup_buf = {0};
                        bpf_map_update_elem(
                            &sock_filter_buffers, &s_args.p_conn.conn, &backup_buf, BPF_ANY);

                        bpf_dbg_printk("can't find iovec ptr in msghdr, not tracking sendmsg");
                        return 0;
                    }
                    s_args.buffer_read = 1;

                    const u64 sock_p = (u64)sk;
                    bpf_map_update_elem(&active_send_args, &id, &s_args, BPF_ANY);
                    bpf_map_update_elem(&active_send_sock_args, &sock_p, &s_args, BPF_ANY);

                    bpf_map_delete_elem(&msg_buffers, &e_key);
                    // Logically last for !ssl.
                    handle_buf_with_connection(
                        ctx, &s_args.p_conn, buf, size, NO_SSL, TCP_SEND, orig_dport);
                }
                bpf_map_delete_elem(&msg_buffers, &e_key);
            } else {
                bpf_dbg_printk("identified SSL connection, ignoring...");
            }
        }

        if (!ssl) {
            return 0;
        }

        tcp_send_ssl_check(id, (void *)(*ssl), &s_args.p_conn, orig_dport);
        bpf_map_delete_elem(&active_send_args, &id);
    }

    return 0;
}

// This is a backup path kprobe in case tcp_sendmsg doesn't fire, which
// happens on certain kernels if sk_msg is attached.
SEC("kprobe/tcp_rate_check_app_limited")
int BPF_KPROBE(obi_kprobe_tcp_rate_check_app_limited, struct sock *sk) {
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== kprobe/tcp_rate_check_app_limited(sendmsg) id=%d, sock=%llx ===", id, sk);

    send_args_t s_args = {
        .buffer_read = 0,
    };

    if (parse_sock_info(sk, &s_args.p_conn.conn)) {
        const u16 orig_dport = s_args.p_conn.conn.d_port;
        dbg_print_http_connection_info(&s_args.p_conn.conn);
        egress_key_t e_key = make_egress_key(&s_args.p_conn.conn);

        sort_connection_info(&s_args.p_conn.conn);
        s_args.p_conn.pid = pid_from_pid_tgid(id);
        s_args.orig_dport = orig_dport;

        connect_ssl_to_connection(id, &s_args.p_conn, TCP_SEND, orig_dport);
        setup_connection_to_pid_mapping(id, &s_args.p_conn, orig_dport);
        cp_support_established(&s_args.p_conn);

        u64 *ssl = is_ssl_connection(&s_args.p_conn);
        if (!ssl) {
            msg_buffer_t *m_buf = bpf_map_lookup_elem(&msg_buffers, &e_key);
            if (m_buf) {
                unsigned char *buf = NULL;
                const u32 cpu_id = bpf_get_smp_processor_id();
                if (m_buf->cpu_id != cpu_id) {
                    bpf_dbg_printk("cpu id mismatch, using stack-allocated fallback buffer");
                    buf = m_buf->fallback_buf;
                } else {
                    buf = bpf_map_lookup_elem(&msg_buffer_mem, &(u32){0});
                    if (!buf) {
                        bpf_dbg_printk("failed to get msg_buffer");
                        return 0;
                    }
                }

                // The buffer setup for us by a sock_msg program is always the
                // full buffer, but when we extend a packet to be able to inject
                // a Traceparent field, it will actually be split in 3 chunks:
                // [before the injected header],[70 bytes for 'Traceparent...'],[the rest].
                // We don't want the handle_buf_with_connection logic to run more than
                // once on the same data, so if we find a buf we send all of it to the
                // handle_buf_with_connection logic and then mark it as seen by making
                // m_buf->pos be the size of the buffer.
                if (!m_buf->pos) {
                    s_args.buffer_read = 1;
                    const u16 size = m_buf->real_size;
                    m_buf->pos = size;
                    s_args.size = size;
                    bpf_dbg_printk("msg_buffer: size %d, buf=[%s]", size, buf);
                    const u64 sock_p = (u64)sk;
                    bpf_map_update_elem(&active_send_args, &id, &s_args, BPF_ANY);
                    bpf_map_update_elem(&active_send_sock_args, &sock_p, &s_args, BPF_ANY);

                    bpf_map_delete_elem(&msg_buffers, &e_key);
                    // Logically last for !ssl.
                    handle_buf_with_connection(
                        ctx, &s_args.p_conn, buf, size, NO_SSL, TCP_SEND, orig_dport);
                }
                bpf_map_delete_elem(&msg_buffers, &e_key);
            }
        } else {
            tcp_send_ssl_check(id, (void *)(*ssl), &s_args.p_conn, orig_dport);
        }
    }

    return 0;
}

// This is really a fallback for the kprobe to ensure we send a large request if it was
// delayed. The code under the `if (size < KPROBES_LARGE_RESPONSE_LEN) {` block should do it
// but it's possible that the kernel sends the data in smaller chunks.
SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(obi_kretprobe_tcp_sendmsg, int sent_len) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== kretprobe/tcp_sendmsg id=%d, sent_len=%d ===", id, sent_len);

    send_args_t *s_args = bpf_map_lookup_elem(&active_send_args, &id);
    if (s_args) {
        if (sent_len > 0) {
            update_http_sent_len(&s_args->p_conn, sent_len);
        }
        if (sent_len <
            MIN_HTTP_SIZE) { // Sometimes app servers don't send close, but small responses back
            finish_possible_delayed_http_request(&s_args->p_conn);
        }

        if (!s_args->buffer_read) {
            backup_buffer_t *backup =
                bpf_map_lookup_elem(&sock_filter_buffers, &s_args->p_conn.conn);
            if (backup) {
                bpf_map_delete_elem(&active_send_args, &id);
                // Don't delete the sock filter buffer, there might be a receive message that will
                // need it.

                // Logically last, doesn't return it tail calls
                handle_buf_with_connection(ctx,
                                           &s_args->p_conn,
                                           backup->buf,
                                           s_args->size,
                                           NO_SSL,
                                           TCP_SEND,
                                           s_args->orig_dport);
            }
        }
    }

    bpf_map_delete_elem(&active_send_args, &id);
    return 0;
}

static __always_inline bool is_port_unreadable(u16 port) {
    if (port == 0) {
        return false;
    }

    const bool *unreadable = bpf_map_lookup_elem(&unreadable_buffer_ports, &port);

    return unreadable && *unreadable;
}

static __always_inline bool is_conn_unreadable(const connection_info_t *conn) {
    return is_port_unreadable(conn->d_port) || is_port_unreadable(conn->s_port);
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(obi_kprobe_tcp_close, struct sock *sk, long timeout) {
    (void)ctx;
    (void)timeout;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    u64 sock_p = (u64)sk;

    bpf_dbg_printk("=== kprobe/tcp_close id=%d, sock=%llx ===", id, sk);

    pid_connection_info_t info = {};
    const bool success = parse_sock_info(sk, &info.conn);

    if (success) {
        const u16 orig_dport = info.conn.d_port;
        sort_connection_info(&info.conn);
        info.pid = pid_from_pid_tgid(id);

        dbg_print_http_connection_info(&info.conn);

        if (is_tcp_socket_never_connected(sk)) {
            cp_support_data_t *ct = bpf_map_lookup_elem(&cp_support_connect_info, &info);
            bpf_dbg_printk("possibly never connected sock: id=%d, sock=%llx, ct=%llx", id, sk, ct);

            if (g_bpf_debug && ct) {
                bpf_dbg_printk("established=%d, already failed=%d", ct->established, ct->failed);
            }

            if (ct && !ct->established && !ct->failed) {
                dbg_print_http_connection_info(&info.conn);
                failed_to_connect_event(&info, orig_dport, ct->ts);
            }
        }
        bpf_map_delete_elem(&cp_support_connect_info, &info);
    }

    bool unreadable = false;
    if (success) {
        unreadable = is_conn_unreadable(&info.conn);
    }

    force_sent_event(id, &sock_p, &info, unreadable);

    if (success) {
        //dbg_print_http_connection_info(&info.conn);
        info.pid = pid_from_pid_tgid(id);
        terminate_http_request_if_needed(&info);
        finish_ongoing_tcp_req(&info);
        bpf_map_delete_elem(&connection_tracker, &info.conn);
    }

    bpf_map_delete_elem(&active_send_args, &id);
    bpf_map_delete_elem(&active_send_sock_args, &sock_p);

    return 0;
}

SEC("kprobe/sock_def_error_report")
int BPF_KPROBE(obi_kprobe_sock_def_error_report, struct sock *sk) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    sock_args_t *args = bpf_map_lookup_elem(&active_connect_args, &id);

    bpf_dbg_printk(
        "=== kprobe/sock_def_error_report id=%d, sock=%llx, args=%llx ===", id, sk, args);

    pid_connection_info_t info = {};
    if (parse_sock_info(sk, &info.conn)) {
        info.pid = pid_from_pid_tgid(id);
        const u16 orig_dport = info.conn.d_port;
        sort_connection_info(&info.conn);

        if (args) {
            if (!args->failed) {
                dbg_print_http_connection_info(&info.conn);
                failed_to_connect_event(&info, orig_dport, args->ts);
                // mark the args and cp_support_info as failed so we don't duplicate the event
                cp_support_data_t *cp_data = bpf_map_lookup_elem(&cp_support_connect_info, &info);
                if (cp_data) {
                    cp_data->failed = 1;
                }
                args->failed = 1;
            }
        } else {
            conn_pid_t *conn_pid = bpf_map_lookup_elem(&sock_pids, &info.conn);
            if (conn_pid && conn_pid->id == id) {
                dbg_print_http_connection_info(&info.conn);
                failed_to_connect_event(&info, orig_dport, conn_pid->ts);
            }
        }
    }

    return 0;
}

static __always_inline void setup_recvmsg(u64 id, struct sock *sk, struct msghdr *msg) {
    // Make sure we don't have stale event from earlier socket connection if they are
    // sent through the same socket. This mainly happens if the server overlays virtual
    // threads in the runtime.
    u64 sock_p = (u64)sk;
    ensure_sent_event(id, &sock_p, TCP_RECV);
    connect_ssl_to_sock(id, sk, TCP_RECV);

    recv_args_t args = {
        .sock_ptr = (u64)sk,
    };

    struct iov_iter___dummy *iov_iter = (struct iov_iter___dummy *)&msg->msg_iter;
    get_iovec_ctx((iovec_iter_ctx *)&args.iovec_ctx, iov_iter);

    bpf_map_update_elem(&active_recv_args, &id, &args, BPF_ANY);
}

//int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)
SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(obi_kprobe_tcp_recvmsg,
               struct sock *sk,
               struct msghdr *msg,
               size_t len,
               int flags,
               int *addr_len) { //NOLINT(readability-non-const-parameter)
    (void)ctx;
    (void)len;
    (void)flags;
    (void)addr_len;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== kprobe/tcp_recvmsg id=%d, sock=%llx ===", id, sk);

    setup_recvmsg(id, sk, msg);

    return 0;
}

// This is a duplicated setup functionality from tcp_recvmsg because when
// the sock_msg filter is installed, the tcp_recvmsg doesn't trigger for
// peek into socket channels. We need to track the peek so we can support
// the context propagation. This probe happens before tcp_recvmsg and wraps it
// so if tcp_recvmsg happens, it will overwrite the data in the args.
SEC("kprobe/sock_recvmsg")
int BPF_KPROBE(obi_kprobe_sock_recvmsg, struct socket *sock, struct msghdr *msg, int flags) {
    (void)ctx;
    (void)flags;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    struct sock *sk = 0;
    BPF_CORE_READ_INTO(&sk, sock, sk);

    bpf_dbg_printk("=== kprobe/sock_recvmsg sock=%llx, socket=%llx ===", sk, sock);
    if (sk) {
        setup_recvmsg(id, sk, msg);
    }

    return 0;
}

// This is a duplicated setup functionality from tcp_recvmsg because when
// the sock_msg filter is installed, the tcp_recvmsg doesn't trigger for
// peek into socket channels. We need to track the peek so we can support
// the context propagation. When tcp_recvmsg happened, the args would be
// cleaned up by that probe and this kprobe won't do anything.
SEC("kretprobe/sock_recvmsg")
int BPF_KRETPROBE(obi_kretprobe_sock_recvmsg, int copied_len) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    recv_args_t *args = bpf_map_lookup_elem(&active_recv_args, &id);

    bpf_dbg_printk(
        "=== kretprobe/sock_recvmsg id=%d, args=%llx, copied_len=%d ===", id, args, copied_len);

    if (!args) {
        return 0;
    }

    pid_connection_info_t info = {};

    void *sock_ptr = (void *)args->sock_ptr;

    if (sock_ptr) {
        if (parse_sock_info((struct sock *)sock_ptr, &info.conn)) {
            const u16 orig_dport = info.conn.d_port;
            sort_connection_info(&info.conn);
            info.pid = pid_from_pid_tgid(id);
            setup_cp_support_conn_info(&info, false);
            setup_connection_to_pid_mapping(id, &info, orig_dport);

            if (is_dns(&info.conn)) {
                sort_connection_info(&info.conn);

                iovec_iter_ctx *iov_ctx = (iovec_iter_ctx *)&args->iovec_ctx;

                if (!iov_ctx->iov && !iov_ctx->ubuf) {
                    bpf_dbg_printk("iovec_ptr found in kprobe is NULL, ignoring this sock_recvmsg");

                    goto done;
                }

                unsigned char *buf = iovec_memory();
                if (buf) {
                    copied_len = read_iovec_ctx(iov_ctx, buf, copied_len);
                    if (!copied_len) {
                        bpf_dbg_printk("Not copied anything");
                    } else {
                        bpf_d_printk(
                            "Got potential dns buffer with len: %d [%s]", copied_len, __FUNCTION__);
                        handle_dns_buf(buf, copied_len, &info, orig_dport);
                    }
                }
            }
        }
    }

done:
    bpf_map_delete_elem(&active_recv_args, &id);

    return 0;
}

static __always_inline void mark_port_unreadable(u16 port) {
    if (port > 0) {
        bpf_map_update_elem(&unreadable_buffer_ports, &port, &(bool){true}, BPF_ANY);
    }
}

static __always_inline int return_recvmsg(void *ctx, struct sock *in_sock, u64 id, int copied_len) {
    recv_args_t *args = bpf_map_lookup_elem(&active_recv_args, &id);

    bpf_dbg_printk("id=%d, args=%llx, copied_len=%d", id, args, copied_len);

    pid_connection_info_t info = {};

    if (!args && !in_sock) {
        return 0;
    }

    void *sock_ptr = in_sock;
    if (!sock_ptr) {
        if (args) {
            sock_ptr = (void *)args->sock_ptr;
        } else {
            return 0;
        }
    }

    if (copied_len <= 0) {
        if (parse_sock_info((struct sock *)sock_ptr, &info.conn)) {
            const u16 orig_dport = info.conn.d_port;
            sort_connection_info(&info.conn);
            info.pid = pid_from_pid_tgid(id);
            setup_cp_support_conn_info(&info, false);
            cp_support_established(&info);
            setup_connection_to_pid_mapping(id, &info, orig_dport);
        }
        // Don't clean-up. This is called as backup path for the retprobe from
        // tcp_cleanup_rbuf which can come in with 0 bytes and we'll delete
        // the data for completing the request.
        return 0;
    }

    // We want the full response (or most of it) to be able to parse HTTP headers/body.
    // Avoid processing 0 or 1 byte packets (eg. AWS api's response to PUT requests) as
    // they would end the request tracking prematurely.
    if (copied_len <= 1) {
        return 0;
    }

    unsigned char *buf = 0;
    if (args) {
        iovec_iter_ctx *iov_ctx = (iovec_iter_ctx *)&args->iovec_ctx;

        if (!iov_ctx->iov && !iov_ctx->ubuf) {
            bpf_dbg_printk("iovec_ptr found in kprobe is NULL, ignoring this tcp_recvmsg");

            goto done;
        }

        buf = iovec_memory();
        if (buf) {
            copied_len = read_iovec_ctx(iov_ctx, buf, copied_len);
            if (!copied_len) {
                bpf_dbg_printk("Not copied anything");
            }
        }
    }

    if (parse_sock_info((struct sock *)sock_ptr, &info.conn)) {
        const u16 orig_dport = info.conn.d_port;
        d_print_http_connection_info(&info.conn);
        sort_connection_info(&info.conn);
        info.pid = pid_from_pid_tgid(id);

        if (!buf) {
            // We couldn't find any buffer to do the work for the recvmsg.
            // This typically means the application layer isn't using tcp_recvmsg
            // but something like pipe splicing. We need to lookup to see if
            // we have a buffer captured for us by the socket filter, but also
            // mark the server ports as problematic, so that the socket filter
            // can help us.

            backup_buffer_t *backup = bpf_map_lookup_elem(&sock_filter_buffers, &info.conn);
            if (backup) {
                buf = backup->buf;
                bpf_dbg_printk("found backup buf=%llx", buf);
                // delete right away to avoid duplicate responses. If a sendmsg needs this buffer
                // they've already set it up, since sendmsg buffers are captured between the probe/retprobe.
                bpf_map_delete_elem(&sock_filter_buffers, &info.conn);
            } else {
                // We have anunreadable connection, we mark both ports as unreadable.
                // Tecnically we have information in tracked connection if this was connect or accept,
                // however if OBI tracks both processes, we'll see connect and accept on the same pair
                // and last one wins.
                bpf_dbg_printk(
                    "setting unreadable buffer ports=%d,%d", info.conn.d_port, info.conn.s_port);
                mark_port_unreadable(info.conn.d_port);
                mark_port_unreadable(info.conn.s_port);
            }
        }

        cp_support_established(&info);
        setup_connection_to_pid_mapping(id, &info, orig_dport);

        u64 *ssl = is_ssl_connection(&info);

        if (!ssl) {
            bpf_dbg_printk("buf=[%llx], copied_len=%d", buf, copied_len);

            if (buf && copied_len) {
                bpf_map_delete_elem(&active_recv_args, &id);
                // doesn't return must be logically last statement
                handle_buf_with_connection(
                    ctx, &info, buf, copied_len, NO_SSL, TCP_RECV, orig_dport);
            }
        } else {
            bpf_dbg_printk("identified SSL connection, ignoring: [%llx]...", *ssl);
        }
    }

done:
    bpf_map_delete_elem(&active_recv_args, &id);

    return 0;
}

// backup path for the retprobe of recv msg not firing
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(obi_kprobe_tcp_cleanup_rbuf, struct sock *sk, int copied) {
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== kprobe/tcp_cleanup_rbuf(recvmsg) id=%d, copied_len=%d ===", id, copied);

    if (g_bpf_debug) {
        connection_info_t conn = {};

        if (parse_sock_info(sk, &conn)) {
            sort_connection_info(&conn);
            dbg_print_http_connection_info(&conn);
        }
    }

    return return_recvmsg(ctx, sk, id, copied);
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(obi_kretprobe_tcp_recvmsg, int copied_len) {
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== kretprobe_tcp_recvmsg id=%d, copied_len=%d ===", id, copied_len);

    return return_recvmsg(ctx, 0, id, copied_len);
}

static __always_inline unsigned char *new_empty_capture_buffer(connection_info_t *conn,
                                                               protocol_info_t *tcp) {
    backup_buffer_t *bbuf = backup_buffer_mem();
    if (bbuf) {
        bbuf->tcp_seq = tcp->seq;
        bpf_map_update_elem(&sock_filter_buffers, conn, bbuf, BPF_ANY);
        backup_buffer_t *back_buf = bpf_map_lookup_elem(&sock_filter_buffers, conn);

        return back_buf->buf;
    }

    return NULL;
}

enum { k_tail_capture_sock_buf };

int obi_socket_flt_buf(struct __sk_buff *skb);

enum { k_tail_socket_filter_dns = 0 };

int obi_socket__http_dns_filter(struct __sk_buff *skb);

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __array(values, int(void *));
} sock_jump_table SEC(".maps") = {
    .values =
        {
            [k_tail_capture_sock_buf] = (void *)&obi_socket_flt_buf,
        },
};

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(u32));
    __array(values, int(void *));
} jump_table_skb SEC(".maps") = {
    .values =
        {
            [k_tail_socket_filter_dns] = (void *)&obi_socket__http_dns_filter,
        },
};

typedef struct sock_tailcall_ctx {
    connection_info_t conn;
    protocol_info_t tcp;
    egress_key_t e_key;
    u8 niter;
    bool has_parent_tp;
    u8 pad[2];
} sock_tailcall_ctx;

SCRATCH_MEM(sock_tailcall_ctx);

SEC("socket/http_filter")
int obi_socket_flt_buf(struct __sk_buff *skb) {
    (void)skb;

    sock_tailcall_ctx *t_ctx = sock_tailcall_ctx_mem();

    if (!t_ctx) {
        return 0;
    }

    // Save the original destination port before sorting. For incoming connections this is the
    // local server port.
    const u16 orig_dport = t_ctx->conn.d_port;

    //d_print_http_connection_info(&conn);

    sort_connection_info(&t_ctx->conn);

    // Check if this is a connection we should be looking at.
    // For outgoing connections, connect() populates connection_tracker before any data flows.
    // For incoming connections, the socket filter fires before accept(), so connection_tracker
    // won't have the entry yet. We fall back to checking filter_ports (listening port, no netns
    // because we can't find it here in the socket filter).
    //
    // By definition we'll miss the first accept connection buffers.
    tracked_connection_t *t_conn = bpf_map_lookup_elem(&connection_tracker, &t_ctx->conn);
    if (!t_conn) {
        bool *fp = bpf_map_lookup_elem(&filter_ports, &orig_dport);
        if (!fp) {
            // We finally check if we've missed the accept, but we have asked for backup buffer
            // in tcp_sendmsg
            backup_buffer_t *back_buf = bpf_map_lookup_elem(&sock_filter_buffers, &t_ctx->conn);
            if (!back_buf) {
                return 0;
            }
        }
    }

    // we don't want to read the whole buffer for every packed that passes our checks, we read only a bit and check if it's truly HTTP request/response.
    unsigned char buf[MIN_HTTP_SIZE] = {0};
    bpf_skb_load_bytes(skb, t_ctx->tcp.hdr_len, (void *)buf, sizeof(buf));
    // technically the read should be reversed, but eBPF verifier complains on read with variable length
    u32 len = skb->len - t_ctx->tcp.hdr_len;
    if (len > MIN_HTTP_SIZE) {
        len = MIN_HTTP_SIZE;
    }

    u8 packet_type = 0;
    if (is_http(
            buf,
            len,
            &packet_type)) { // we must check tcp_close second, a packet can be a close and a response
        // this can be very verbose
        //bpf_d_printk("http buf=[%s] [%s]", buf, __FUNCTION__);
        //d_print_http_connection_info(&conn);
        if (packet_type == PACKET_TYPE_REQUEST) {
            const u64 cookie = bpf_get_socket_cookie(skb);
            //bpf_dbg_printk("cookie=%llx, len=%d, buf=[%s]", cookie, len, buf);
            //dbg_print_http_connection_info(&conn);

            // The code below is looking to see if we have recorded black-box trace info on
            // another interface. We do this for client calls, where essentially the original
            // request may go out on one interface, but then get re-routed to another, which is
            // common with some k8s environments.
            partial_connection_info_t partial = {
                .d_port = t_ctx->conn.d_port,
                .s_port = t_ctx->conn.s_port,
                .tcp_seq = t_ctx->tcp.seq,
            };
            __builtin_memcpy(partial.s_addr, t_ctx->conn.s_addr, sizeof(partial.s_addr));

            tp_info_pid_t *trace_info = trace_info_for_connection(&t_ctx->conn, TRACE_TYPE_CLIENT);
            if (trace_info) {
                if (cookie) { // we have an actual socket associated
                    bpf_map_update_elem(&tcp_connection_map, &partial, &t_ctx->conn, BPF_ANY);
                }
            } else if (!cookie) { // no actual socket for this skb, relayed to another interface
                connection_info_t *prev_conn = bpf_map_lookup_elem(&tcp_connection_map, &partial);

                if (prev_conn) {
                    tp_info_pid_t *trace_info =
                        trace_info_for_connection(prev_conn, TRACE_TYPE_CLIENT);
                    if (trace_info) {
                        if (current_immediate_epoch(trace_info->tp.ts) ==
                            current_immediate_epoch(bpf_ktime_get_ns())) {
                            //bpf_dbg_printk("Found trace info on another interface, setting it up for this connection");
                            tp_info_pid_t other_info = {0};
                            __builtin_memcpy(&other_info, trace_info, sizeof(tp_info_pid_t));
                            set_trace_info_for_connection(
                                &t_ctx->conn, TRACE_TYPE_CLIENT, &other_info);
                        }
                    }
                }
            }
        }
    }

    // We check here for problematic buffer captures
    // There are two situations:
    //   1. The sendmsg couldn't capture the buffer, we need to do it for them.
    //      This is the lookup by connection
    //   2. We have problematic receive port recorded. These are receive buffers we
    //      couldn't read, but since the socket filter runs before the receive probe
    //      we rely on a prior port connection recorded by tcp_close which saw an
    //      incomplete request.
    unsigned char *capture_buf = 0;

    backup_buffer_t *back_buf = bpf_map_lookup_elem(&sock_filter_buffers, &t_ctx->conn);
    if (back_buf) { // Scenario 1.
        // if we've seen this before, don't capture it again.
        if (back_buf->tcp_seq == t_ctx->tcp.seq) {
            return 0;
        }
        back_buf->tcp_seq = t_ctx->tcp.seq;
        capture_buf = back_buf->buf;
    } else { // Scenario 2.
        bool unreadable = is_conn_unreadable(&t_ctx->conn);
        bpf_map_lookup_elem(&unreadable_buffer_ports, &t_ctx->conn.d_port);

        if (unreadable) {
            capture_buf = new_empty_capture_buffer(&t_ctx->conn, &t_ctx->tcp);
        }
    }

    if (capture_buf) {
        read_skb_bytes(skb, t_ctx->tcp.hdr_len, (void *)capture_buf, k_backup_buffer_len);

        bpf_d_printk("captured fallback buffer %s", capture_buf);
    }

    return 0;
}
SEC("socket/http_filter")
int obi_socket__http_filter(struct __sk_buff *skb) {
    protocol_info_t tcp = {};
    connection_info_t conn = {};

    const u8 success = read_sk_buff(skb, &tcp, &conn);

    if (is_dns(&conn)) {
        bpf_tail_call_static(skb, &jump_table_skb, k_tail_socket_filter_dns);
        return 0;
    }

    if (!success) {
        return 0;
    }

    // ignore empty packets, unless it's TCP FIN or TCP RST
    if (!tcp_close(&tcp) && tcp_empty(&tcp, skb)) {
        return 0;
    }

    sock_tailcall_ctx *t_ctx = sock_tailcall_ctx_mem();

    if (!t_ctx) {
        return 0;
    }

    t_ctx->conn = conn;
    t_ctx->tcp = tcp;

    bpf_tail_call_static(skb, &sock_jump_table, k_tail_capture_sock_buf);

    return 0;
}

// k_tail_socket_filter_dns
SEC("socket/http_dns_filter")
int obi_socket__http_dns_filter(struct __sk_buff *skb) {
    protocol_info_t tcp = {};
    connection_info_t conn = {};

    read_sk_buff(skb, &tcp, &conn);
    handle_dns(skb, &conn, &tcp);
    return 0;
}

/*
    The tracking of the clones is complicated by the fact that in container environments
    the tid returned by the sys_clone call is the namespaced tid, not the host tid which
    bpf sees normally. To mitigate this we work exclusively with namespaces. Only the clone_map
    and server_traces are keyed off the namespace:pid.
*/
SEC("kretprobe/sys_clone")
int BPF_KRETPROBE(obi_kretprobe_sys_clone, int tid) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id) || tid < 0) {
        return 0;
    }

    pid_key_t parent = {0};
    task_tid(&parent);

    pid_key_t child = {
        .tid = (u32)tid,
        .ns = parent.ns,
        .pid = parent.pid,
    };

    bpf_dbg_printk("=== kretprobe/sys_clone id->tid: %d -> %d ===", id, tid);
    bpf_map_update_elem(&clone_map, &child, &parent, BPF_ANY);

    return 0;
}

SEC("kprobe/sys_exit")
int BPF_KPROBE(obi_kprobe_sys_exit, int status) {
    (void)ctx;
    (void)status;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    trace_key_t task = {0};
    task_tid(&task.p_key);

    bpf_dbg_printk("=== kprobe/sys_exit id=%d, pid=%d, valid_pid(id)=%d ===",
                   id,
                   pid_from_pid_tgid(id),
                   valid_pid(id));

    bpf_map_delete_elem(&clone_map, &task.p_key);
    // This won't delete trace ids for traces with extra_id, like NodeJS. But,
    // we expect that it doesn't matter, since NodeJS main thread won't exit.
    bpf_map_delete_elem(&server_traces, &task);
    obi_ctx__del(id);

    return 0;
}

SEC("kprobe/inet_csk_listen_stop")
int BPF_KPROBE(obi_kprobe_inet_csk_listen_stop, struct sock *sk) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();
    (void)id;

    bpf_dbg_printk("=== kprobe/inet_csk_listen_stop id=%d ===", id);

    struct sock_port_ns np = sock_port_ns_from_sk(sk);
    bpf_map_delete_elem(&listening_ports, &np);
    bpf_map_delete_elem(&filter_ports, &np.port);
    return 0;
}
