// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <socktracer/socket_data.h>
#include <socktracer/tailcall_ctx.h>

enum : u8 { k_packet_type_request = 1, k_packet_type_response = 2 };
enum : u8 { k_request_uprobe_handled = 0xff };

static __always_inline u32 ctx_len(void *ctx);
static __always_inline void ctx_pull_data(void *ctx, u32 len);
static __always_inline void *ctx_data(void *ctx);
static __always_inline void *ctx_data_end(void *ctx);

static __always_inline void *prog_map();

static __always_inline u32 tail_http_req();
static __always_inline u32 tail_http_create_tp();
static __always_inline u32 tail_http_found_tp();
static __always_inline u32 tail_http2();

static __always_inline void set_trace(const struct socket_data *sk_data, const tp_info_pid_t *tp_p);

static __always_inline void schedule_write_tcp_option(void *ctx, tp_info_pid_t *tp_p);

static __always_inline unsigned char *tp_span_id_field(tp_info_t *tp);

static __always_inline void
init_span_id(const struct socket_data *sk_data, tp_info_t *tp, unsigned char *span_id);

static __always_inline void init_tp(struct socket_data *sk_data, tp_info_t *tp);
static __always_inline void write_tp_http_header(void *ctx, tailcall_ctx *t_ctx);

static __always_inline u32 send_large_buffer(void *ctx,
                                             u8 packet_type,
                                             u8 direction,
                                             connection_info_t conn_info,
                                             tp_info_t tp,
                                             u8 action,
                                             u32 max_bytes,
                                             u32 *bytes_sent,
                                             u8 *has_large_buffers);
