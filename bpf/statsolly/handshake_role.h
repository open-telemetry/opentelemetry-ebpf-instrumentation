// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <statsolly/types.h>

static __always_inline enum tcp_handshake_role
failed_connection_role(const int oldstate, const enum tcp_handshake_role stored_role) {
    // a stored role can belong to an earlier connection of the same socket
    if (oldstate == TCP_SYN_SENT) {
        return role_client;
    }

    if (oldstate == TCP_SYN_RECV) {
        return role_server;
    }

    return stored_role;
}
