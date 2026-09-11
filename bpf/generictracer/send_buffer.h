// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/backup_buffer.h>
#include <common/protocol_defs.h>
#include <common/send_args.h>

#include <generictracer/k_tracer_defs.h>

#include <generictracer/maps/active_send_args.h>
#include <generictracer/maps/sock_filter_buffers.h>

// Hands the socket filter's captured buffer to the protocol parser when a send
// completed without one having been read inline. The socket comes from send_args_t,
// recorded by the entry kprobe: a kretprobe sees only the return value, so it has none
// of its own to pass.
static __always_inline void flush_backup_send_buffer(void *ctx, u64 id, send_args_t *s_args) {
    if (s_args->buffer_read) {
        return;
    }

    backup_buffer_t *backup = bpf_map_lookup_elem(&sock_filter_buffers, &s_args->p_conn.conn);
    if (!backup) {
        return;
    }

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
                               s_args->orig_dport,
                               (struct sock *)s_args->sock_ptr);
}
