// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <generictracer/frida.h>
#include <generictracer/k_tracer_defs.h>
#include <maps/active_ssl_connections.h>

enum { k_frida_payload_ioctl = 0x0b10f2, k_frida_max_payload = 1 << 20 };

typedef struct frida_payload {
    connection_info_t conn;
    u32 length;
    u64 buffer;
    u8 direction;
    u8 padding[7];
} frida_payload_t;

_Static_assert(sizeof(frida_payload_t) == 56, "Frida payload ABI size");
_Static_assert(__builtin_offsetof(frida_payload_t, buffer) == 40,
               "Frida payload ABI buffer offset");

static __always_inline int frida_payload_request(void *ctx, const u64 id, const void *arg) {
    frida_payload_t payload = {};
    if (bpf_probe_read_user(&payload, sizeof(payload), arg) != 0 || !payload.buffer ||
        !payload.length || payload.length > k_frida_max_payload ||
        (payload.direction != TCP_SEND && payload.direction != TCP_RECV)) {
        return 0;
    }
    unsigned char *buffer = (unsigned char *)payload.buffer;
    unsigned char first = 0;
    unsigned char last = 0;
    if (bpf_probe_read_user(&first, sizeof(first), buffer) != 0 ||
        bpf_probe_read_user(&last, sizeof(last), buffer + payload.length - 1) != 0) {
        return 0;
    }
    pid_connection_info_t connection = {.conn = payload.conn, .pid = pid_from_pid_tgid(id)};
    // Agent endpoints are always local then peer, including received data.
    const u16 orig_dport = payload.conn.d_port;
    sort_connection_info(&connection.conn);
    const u64 zero = 0;
    bpf_map_update_elem(&active_ssl_connections, &connection, &zero, BPF_ANY);
    handle_buf_with_connection(
        ctx, &connection, buffer, payload.length, WITH_SSL, payload.direction, orig_dport, 0);
    return 0;
}
