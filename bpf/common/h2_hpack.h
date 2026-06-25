// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_builtins.h>

#include <common/h2_defs.h>
#include <common/http_types.h>
#include <common/pkt_access.h>
#include <common/trace_util.h>

// Generic HTTP/2 HPACK traceparent byte logic shared by the egress injectors
// (tpinjector, socktracer). Pure functions over struct sk_msg_md*/offsets/tp_info_t
// with no tracer-specific maps or tail-call state.

// Encodes a literal-never-indexed "traceparent" HPACK entry into buf.
static __always_inline void
make_h2_tp_hpack(unsigned char *buf, const tp_info_t *tp, const unsigned char *end) {
    buf = check_pkt_access(buf, k_h2_tp_hpack_size, end);

    if (!buf) {
        return;
    }

    *buf++ = k_hpack_literal_no_index;
    *buf++ = k_hpack_tp_name_len;

    *buf++ = 't';
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

    *buf++ = k_hpack_value_len_tp;

    // Version
    *buf++ = '0';
    *buf++ = '0';
    *buf++ = '-';

    // Trace ID
    encode_hex(buf, tp->trace_id, TRACE_ID_SIZE_BYTES);
    buf += TRACE_ID_CHAR_LEN;

    *buf++ = '-';

    // Span ID
    encode_hex(buf, tp->span_id, SPAN_ID_SIZE_BYTES);
    buf += SPAN_ID_CHAR_LEN;

    *buf++ = '-';

    *buf++ = '0';
    *buf++ = '0' + (tp->flags & k_flag_sampled);
}

// Validate the 3 dashes and decode trace_id + span_id into tp.
// Returns true on success.
static __always_inline bool decode_tp_value(const unsigned char *val, tp_info_t *tp) {
    if (val[k_tp_val_dash1] != '-' || val[k_tp_val_dash2] != '-' || val[k_tp_val_dash3] != '-') {
        return false;
    }
    decode_hex(tp->trace_id, &val[k_tp_val_trace_id_start], TRACE_ID_CHAR_LEN);
    decode_hex(tp->span_id, &val[k_tp_val_span_id_start], SPAN_ID_CHAR_LEN);
    tp->flags = 1;
    return true;
}

static __always_inline u32 validate_h2_tp_plain(const unsigned char *p,
                                                const unsigned char *end,
                                                tp_info_t *tp) {
    if ((void *)(p + k_h2_tp_hpack_size) > (void *)end) {
        return 0;
    }
    if (bpf_memcmp(p + k_hpack_tp_name_offset, k_hpack_tp_name, k_hpack_tp_name_len) != 0) {
        return 0;
    }
    if (p[k_hpack_tp_name_offset + k_hpack_tp_name_len] != k_hpack_value_len_tp) {
        return 0;
    }
    if (!decode_tp_value(p + k_hpack_tp_val_offset, tp)) {
        return 0;
    }
    return k_hpack_tp_val_offset + k_tp_val_span_id_start;
}

static __always_inline u32 validate_h2_tp_huffman(const unsigned char *p,
                                                  const unsigned char *end,
                                                  tp_info_t *tp) {
    if ((void *)(p + k_h2_tp_hpack_huffman_size) > (void *)end) {
        return 0;
    }
    if (bpf_memcmp(p + k_hpack_tp_name_offset, k_hpack_tp_huffman, k_hpack_tp_name_huffman_len) !=
        0) {
        return 0;
    }
    if (p[k_hpack_tp_name_offset + k_hpack_tp_name_huffman_len] != k_hpack_value_len_tp) {
        return 0;
    }
    if (!decode_tp_value(p + k_hpack_tp_val_offset_huffman, tp)) {
        return 0;
    }
    return k_hpack_tp_val_offset_huffman + k_tp_val_span_id_start;
}

static __always_inline bool
pull_hpack_window(struct sk_msg_md *msg, const u32 hpack_start, const u32 hpack_len) {
    enum { k_min_entry_plain = k_h2_tp_hpack_size };
    if (hpack_len < k_h2_tp_hpack_huffman_size) {
        return false;
    }
    const u32 pull_len = hpack_len < (k_h2_max_hpack_scan + k_min_entry_plain)
                             ? hpack_len
                             : (k_h2_max_hpack_scan + k_min_entry_plain);
    return bpf_msg_pull_data(msg, hpack_start, hpack_start + pull_len, 0) == 0;
}

// Fingerprints for full traceparent name + value-length byte (0x37).
// Values match what *(u32/u64 *)p loads on the build target, so the comparisons
// work on bpfel and bpfeb.
enum {
    k_h2_nlb_plain = k_hpack_tp_name_len,
    k_h2_nlb_huffman = k_hpack_tp_name_huffman_len | 0x80,
};
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static const u64 k_h2_tp_fp_plain_lo = 0x7261706563617274ULL; // "tracepar"
static const u32 k_h2_tp_fp_plain_hi = 0x37746e65U;           // "ent" + 0x37
static const u64 k_h2_tp_fp_huffman = 0x3fa9851d6b21834dULL;  // huffman("traceparent")
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static const u64 k_h2_tp_fp_plain_lo = 0x7472616365706172ULL; // "tracepar"
static const u32 k_h2_tp_fp_plain_hi = 0x656e7437U;           // "ent" + 0x37
static const u64 k_h2_tp_fp_huffman = 0x4d83216b1d85a93fULL;  // huffman("traceparent")
#else
#error "unsupported __BYTE_ORDER__"
#endif

static __always_inline bool match_h2_tp_plain(const unsigned char *p) {
    return *(const u64 *)(p + k_hpack_tp_name_offset) == k_h2_tp_fp_plain_lo &&
           *(const u32 *)(p + k_hpack_tp_name_offset + 8) == k_h2_tp_fp_plain_hi;
}

static __always_inline bool match_h2_tp_huffman(const unsigned char *p) {
    return *(const u64 *)(p + k_hpack_tp_name_offset) == k_h2_tp_fp_huffman &&
           p[k_hpack_tp_name_offset + k_hpack_tp_name_huffman_len] == k_hpack_value_len_tp;
}

// Returns offset of the traceparent name in HPACK, or k_h2_max_hpack_scan if not found.
static __always_inline u32 find_first_h2_tp_candidate(struct sk_msg_md *msg,
                                                      const u32 hpack_start,
                                                      const u32 hpack_len) {
    enum { k_min_entry_huffman = k_h2_tp_hpack_huffman_size };

    if (!pull_hpack_window(msg, hpack_start, hpack_len)) {
        return k_h2_max_hpack_scan;
    }
    const unsigned char *data = msg->data;
    const unsigned char *end = msg->data_end;
    if (!data) {
        return k_h2_max_hpack_scan;
    }

    for (u32 i = 0; i < k_h2_max_hpack_scan; i++) {
        if (i + k_min_entry_huffman > hpack_len) {
            break;
        }
        const unsigned char *p = data + i;
        if ((void *)(p + k_min_entry_huffman) > (void *)end) {
            break;
        }
        if (p[0] != k_hpack_literal_no_index) {
            continue;
        }
        const u8 nlb = p[1];
        if (nlb == k_h2_nlb_plain && match_h2_tp_plain(p)) {
            return i;
        }
        if (nlb == k_h2_nlb_huffman && match_h2_tp_huffman(p)) {
            return i;
        }
    }
    return k_h2_max_hpack_scan;
}
