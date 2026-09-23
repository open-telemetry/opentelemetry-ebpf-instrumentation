// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

// entries only one tracer defines, set before including this header
#ifndef OBI_JUMP_TABLE_EXTRA_ENTRIES
#define OBI_JUMP_TABLE_EXTRA_ENTRIES(entry)
#endif

// One list drives the slot names, the forward declarations and both tables, so a
// slot cannot exist without its program and the two tables cannot diverge. Both
// tables must hold the same program at the same index: a tail call reaches one or
// the other depending on the attach type of the program making it
// clang-format off
#define OBI_JUMP_TABLE_ENTRIES(entry)                                                              \
    /* HTTP/1 */                                                                                   \
    entry(k_tail_protocol_http, obi_protocol_http, struct pt_regs *)                               \
    entry(k_tail_continue_protocol_http, obi_continue_protocol_http, struct pt_regs *)             \
    entry(k_tail_continue2_protocol_http, obi_continue2_protocol_http, struct pt_regs *)           \
    entry(k_tail_continue_protocol_http_tp, obi_continue_protocol_http_tp, struct pt_regs *)       \
    /* TCP */                                                                                      \
    entry(k_tail_protocol_tcp, obi_protocol_tcp, void *)                                           \
    /* Generic */                                                                                  \
    entry(k_tail_handle_buf_with_args, obi_handle_buf_with_args, void *)                           \
    /* HTTP/2 + gRPC */                                                                            \
    entry(k_tail_protocol_http2, obi_protocol_http2, void *)                                       \
    entry(k_tail_protocol_http2_grpc_frames, obi_protocol_http2_grpc_frames, void *)               \
    entry(k_tail_protocol_http2_grpc_handle_start_frame,                                           \
          obi_protocol_http2_grpc_handle_start_frame,                                              \
          void *)                                                                                  \
    entry(k_tail_protocol_http2_grpc_handle_end_frame,                                             \
          obi_protocol_http2_grpc_handle_end_frame,                                                \
          void *)                                                                                  \
    entry(k_tail_protocol_http2_grpc_handle_start_frame_server,                                    \
          obi_protocol_http2_grpc_handle_start_frame_server,                                       \
          void *)                                                                                  \
    entry(k_tail_protocol_http2_grpc_handle_start_frame_server_finalize,                           \
          obi_protocol_http2_grpc_handle_start_frame_server_finalize,                              \
          void *)                                                                                  \
    /* Large buffer multi-batch emission */                                                        \
    entry(k_tail_large_buf_emit_continue, obi_large_buf_emit_continue, struct pt_regs *)           \
    entry(k_tail_protocol_http2_grpc_handle_start_frame_server_commit,                             \
          obi_protocol_http2_grpc_handle_start_frame_server_commit,                                \
          void *)                                                                                  \
    entry(k_tail_protocol_http2_grpc_handle_start_frame_server_huffman,                            \
          obi_protocol_http2_grpc_handle_start_frame_server_huffman,                               \
          void *)                                                                                  \
    entry(k_tail_protocol_http2_grpc_handle_start_frame_server_huffscan,                           \
          obi_protocol_http2_grpc_handle_start_frame_server_huffscan,                              \
          void *)                                                                                  \
    OBI_JUMP_TABLE_EXTRA_ENTRIES(entry)
// clang-format on

#define OBI_JUMP_TABLE_SLOT(slot, prog, ctx_type) slot,
enum { OBI_JUMP_TABLE_ENTRIES(OBI_JUMP_TABLE_SLOT) k_tail_count };
#undef OBI_JUMP_TABLE_SLOT

#define OBI_JUMP_TABLE_DECL(slot, prog, ctx_type) int prog(ctx_type);
OBI_JUMP_TABLE_ENTRIES(OBI_JUMP_TABLE_DECL)
#undef OBI_JUMP_TABLE_DECL

#define OBI_JUMP_TABLE_VALUE(slot, prog, ctx_type) [slot] = (void *)&prog,
#define OBI_JUMP_TABLE_VALUES {OBI_JUMP_TABLE_ENTRIES(OBI_JUMP_TABLE_VALUE)}

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, k_tail_count);
    __uint(key_size, sizeof(u32));
    __array(values, int(void *));
} jump_table SEC(".maps") = {
    .values = OBI_JUMP_TABLE_VALUES,
};

// uprobe_multi programs tail-call through this copy, the loader fills it with
// uprobe_multi copies of the same programs
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, k_tail_count);
    __uint(key_size, sizeof(u32));
    __array(values, int(void *));
} jump_table_um SEC(".maps") = {
    .values = OBI_JUMP_TABLE_VALUES,
};
