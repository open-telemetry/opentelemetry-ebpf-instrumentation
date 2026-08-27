// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>

#include <maps/active_ssl_connections.h>
#include <maps/ssl_to_conn.h>

// Stands in for the real set_active_ssl_connection, which additionally records
// the reverse mapping in active_ssl_connections. Only the ssl_to_conn side
// matters to the correlation tests, and keeping the stub narrow avoids pulling
// the socket parsing helpers into a host build.
static __always_inline void set_active_ssl_connection(ssl_pid_connection_info_t *ssl_conn,
                                                      void *ssl) {
    bpf_map_update_elem(&ssl_to_conn, &ssl, ssl_conn, 0);
}
