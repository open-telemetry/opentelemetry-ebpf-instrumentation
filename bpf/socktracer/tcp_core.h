// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/common.h>
#include <common/ringbuf.h>

#include <logger/bpf_dbg.h>

#include <shared/obi_ctx.h>

#include <socktracer/helpers.h>
#include <socktracer/socket_data.h>

static __always_inline void finish_tcp(struct socket_data *sk_data) {
    bpf_dbg_enter();

    tcp_req_t *info = &sk_data->request.tcp;

    print_tp("finishing TCP request", &info->tp);
    bpf_ringbuf_output(&events, info, sizeof(*info), get_flags());

    obi_ctx__del(sk_data->pid_tgid);

    __builtin_memset(&sk_data->request, 0, sizeof(sk_data->request));
}
