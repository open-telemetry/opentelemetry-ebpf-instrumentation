// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/pkt_access.h>
#include <common/ringbuf.h>
#include <common/tc_common.h>
#include <common/tp_info.h>
#include <common/trace_util.h>
#include <common/tracing.h>

#include <logger/bpf_dbg.h>

#include <common/scratch_mem.h>

#include <pid/pid_helpers.h>

#include <socktracer/socket_data.h>

SCRATCH_MEM_TYPED(tp_buf, tp_info_pid_t)

static __always_inline void print_tp(const char *msg, const tp_info_t *tp) {
    if (!g_bpf_debug) {
        return;
    }

    unsigned char tp_buf_str[TP_MAX_VAL_LENGTH];
    make_tp_string(tp_buf_str, tp);
    bpf_dbg_printk("%s: %s", msg, tp_buf_str);
}

static __always_inline u8 request_type(const struct socket_data *sk_data) {
    return sk_data->sk_type == sk_type_client ? EVENT_HTTP_CLIENT : EVENT_HTTP_REQUEST;
}

static __always_inline void
make_tp_string_skb(unsigned char *buf, const tp_info_t *tp, const unsigned char *end) {
    buf = check_pkt_access(buf, TP_SIZE, end);

    if (!buf) {
        return;
    }

    const __attribute__((unused)) unsigned char *tp_string = buf;

    *buf++ = 'T';
    *buf++ = 'r';
    *buf++ = 'a';
    *buf++ = 'c';
    *buf++ = 'e';
    *buf++ = 'p';
    *buf++ = 'a';
    *buf++ = 'r';
    *buf++ = 'e';
    *buf++ = 'n';
    *buf++ = 't';
    *buf++ = ':';
    *buf++ = ' ';

    // Version
    *buf++ = '0';
    *buf++ = '0';
    *buf++ = '-';

    // Trace ID
    encode_hex(buf, tp->trace_id, TRACE_ID_SIZE_BYTES);
    buf += TRACE_ID_CHAR_LEN;

    *buf++ = '-';

    // SpanID
    encode_hex(buf, tp->span_id, SPAN_ID_SIZE_BYTES);
    buf += SPAN_ID_CHAR_LEN;

    *buf++ = '-';

    *buf++ = '0';
    *buf++ = (tp->flags == 0) ? '0' : '1';
    *buf++ = '\r';
    *buf++ = '\n';

    bpf_dbg_printk("tp_string=%s", tp_string);
}
