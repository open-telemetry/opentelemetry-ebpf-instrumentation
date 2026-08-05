// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wint-conversion"
#pragma clang diagnostic ignored "-Wint-to-pointer-cast"

#undef BPF_CORE_READ
#define BPF_CORE_READ(src, ...) ((void)(src), 0)

struct pt_regs {
    unsigned long bx;
    unsigned long sp;
};

#define GO_PARAM2(ctx) ((void *)(ctx)->bx)
#define PT_REGS_SP(ctx) ((ctx)->sp)

static inline unsigned int bpf_get_prandom_u32(void) {
    return 0;
}

static inline unsigned long long bpf_ktime_get_ns(void) {
    return 0;
}

static inline long bpf_loop(unsigned int nr_loops,
                            int (*callback_fn)(unsigned int, void *),
                            void *callback_ctx,
                            unsigned long long flags) {
    (void)nr_loops;
    (void)callback_fn;
    (void)callback_ctx;
    (void)flags;
    return 0;
}

static void *test_map_lookup(void *map, const void *key);
static long test_map_update(void *map, const void *key, const void *val, unsigned long long flags);
static long test_map_delete(void *map, const void *key);
static long test_probe_read(void *dst, unsigned int size, const void *src);
static unsigned long long test_current_pid_tgid(void);
static unsigned long long test_process_start_time(void);

#define BPF_ANY 0
#define BPF_NOEXIST 1
#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete
#define bpf_probe_read test_probe_read
#define bpf_probe_read_kernel test_probe_read
#define bpf_get_current_pid_tgid test_current_pid_tgid
#define OBI_CURRENT_PROCESS_START_TIME_NS test_process_start_time

#include <gotracer/go_common.h>
#include <gotracer/go_http2_server.h>

#undef OBI_CURRENT_PROCESS_START_TIME_NS
#undef bpf_get_current_pid_tgid
#undef bpf_probe_read_kernel
#undef bpf_probe_read
#undef bpf_map_delete_elem
#undef bpf_map_update_elem
#undef bpf_map_lookup_elem
#undef BPF_NOEXIST
#undef BPF_ANY
#undef PT_REGS_SP
#undef GO_PARAM2
#undef BPF_CORE_READ

#pragma clang diagnostic pop

typedef struct fake_meta_headers_frame {
    void *headers;
    grpc_header_field_t *fields;
    u64 fields_len;
    u64 fields_cap;
    u8 truncated;
} fake_meta_headers_frame_t;

typedef struct fake_frame_header {
    u64 prefix;
    u32 stream_id;
} fake_frame_header_t;

typedef struct fake_http2_stream {
    void *server_conn;
    u32 stream_id;
} fake_http2_stream_t;

typedef struct fake_response_writer_state {
    fake_http2_stream_t *stream;
} fake_response_writer_state_t;

typedef struct fake_response_writer {
    fake_response_writer_state_t *rws;
} fake_response_writer_t;

static unsigned int failures;
static off_table_t offsets;

static void *test_map_lookup(void *map, const void *key) {
    if (map == &go_offsets_map && *(const u64 *)key == 0) {
        return &offsets;
    }
    return 0;
}

static long test_map_update(void *map, const void *key, const void *val, unsigned long long flags) {
    (void)map;
    (void)key;
    (void)val;
    (void)flags;
    return -1;
}

static long test_map_delete(void *map, const void *key) {
    (void)map;
    (void)key;
    return -1;
}

static long test_probe_read(void *dst, unsigned int size, const void *src) {
    if (!src) {
        return -1;
    }
    memcpy(dst, src, size);
    return 0;
}

static unsigned long long test_current_pid_tgid(void) {
    return 0;
}

static unsigned long long test_process_start_time(void) {
    return 0;
}

static void assert_bool(int want, int got, const char *message) {
    if (want == got) {
        return;
    }
    fprintf(stderr, "%s: want %d, got %d\n", message, want, got);
    failures++;
}

static void assert_bytes(const void *want, const void *got, size_t len, const char *message) {
    if (memcmp(want, got, len) == 0) {
        return;
    }
    fprintf(stderr, "%s: byte sequences differ\n", message);
    failures++;
}

static grpc_header_field_t header_field(const unsigned char *name,
                                        size_t name_len,
                                        const unsigned char *value,
                                        size_t value_len) {
    return (grpc_header_field_t){
        .key_ptr = (u8 *)name,
        .key_len = name_len,
        .val_ptr = (u8 *)value,
        .val_len = value_len,
    };
}

static void process_fields(grpc_header_field_t *fields, size_t fields_len, tp_info_t *tp) {
    offsets.table[_meta_headers_frame_fields_ptr_pos] = offsetof(fake_meta_headers_frame_t, fields);
    fake_meta_headers_frame_t frame = {
        .fields = fields,
        .fields_len = fields_len,
    };
    process_meta_frame_headers(&frame, tp);
}

static enum go_http1_traceparent_scan_result
process_h2_fields(grpc_header_field_t *fields, size_t fields_len, tp_info_t *tp) {
    offsets.table[_meta_headers_frame_fields_ptr_pos] = offsetof(fake_meta_headers_frame_t, fields);
    fake_meta_headers_frame_t frame = {
        .fields = fields,
        .fields_len = fields_len,
    };
    return go_http2_process_meta_frame_headers(&frame, tp);
}

static void test_single_traceparent_is_decoded(void) {
    static const unsigned char name[] = "traceparent";
    static const unsigned char value[] = "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01";
    static const unsigned char trace_id[] = {
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
        0x10,
    };
    static const unsigned char parent_id[] = {
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
    };
    grpc_header_field_t fields[] = {
        header_field(name, sizeof(name) - 1, value, sizeof(value) - 1),
    };
    tp_info_t tp = {};

    process_fields(fields, 1, &tp);

    assert_bytes(trace_id, tp.trace_id, sizeof(trace_id), "decode single trace ID");
    assert_bytes(parent_id, tp.parent_id, sizeof(parent_id), "decode single parent ID");
    assert_bool(1, tp.flags, "decode single trace flags");
}

static void test_http2_server_shape_is_normalized(void) {
    static const unsigned char name[] = "traceparent";
    static const unsigned char value[] = "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01";
    static const unsigned char trace_id[] = {
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
        0x10,
    };
    static const unsigned char remote_span_id[] = {
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
    };
    grpc_header_field_t fields[] = {
        header_field(name, sizeof(name) - 1, value, sizeof(value) - 1),
    };
    tp_info_t tp = {};

    const enum go_http1_traceparent_scan_result state = process_h2_fields(fields, 1, &tp);

    assert_bool(k_go_http1_traceparent_scan_found, state, "classify normalized traceparent");
    assert_bytes(trace_id, tp.trace_id, sizeof(trace_id), "normalized trace ID");
    assert_bytes(remote_span_id, tp.span_id, sizeof(remote_span_id), "normalized remote span ID");
    assert_bytes(remote_span_id, tp.parent_id, sizeof(remote_span_id), "retain decoded parent ID");
    assert_bool(1, tp.parent_remote, "normalized parent is remote");
    assert_bool(1, tp.flags, "normalized trace flags");
}

static void test_http2_server_classification(void) {
    static const unsigned char name[] = "traceparent";
    static const unsigned char invalid_value[] =
        "00-z102030405060708090a0b0c0d0e0f10-1112131415161718-01";
    grpc_header_field_t invalid[] = {
        header_field(name, sizeof(name) - 1, invalid_value, sizeof(invalid_value) - 1),
    };
    tp_info_t tp = {};

    assert_bool(k_go_http1_traceparent_scan_absent,
                process_h2_fields(NULL, 0, &tp),
                "empty complete block is absent");
    assert_bool(k_go_http1_traceparent_scan_present,
                process_h2_fields(invalid, 1, &tp),
                "invalid traceparent is present");

    offsets.table[_meta_headers_frame_fields_ptr_pos] = offsetof(fake_meta_headers_frame_t, fields);
    fake_meta_headers_frame_t truncated = {
        .fields = invalid,
        .fields_len = 1,
        .fields_cap = 1,
        .truncated = 1,
    };
    assert_bool(k_go_http1_traceparent_scan_unknown,
                go_http2_process_meta_frame_headers(&truncated, &tp),
                "truncated header block is unknown");
}

static void test_http2_stream_layout_helpers(void) {
    fake_frame_header_t headers = {.stream_id = 17};
    fake_meta_headers_frame_t frame = {.headers = &headers};
    fake_http2_stream_t stream = {.server_conn = (void *)0x1234, .stream_id = 23};
    fake_response_writer_state_t rws = {.stream = &stream};
    fake_response_writer_t rw = {.rws = &rws};
    u32 stream_id = 0;

    assert_bool(1,
                go_http2_meta_headers_stream_id(&frame, &stream_id),
                "MetaHeadersFrame pointer chain is readable");
    assert_bool(17, stream_id, "MetaHeadersFrame stream ID");
    stream_id = 0;
    assert_bool(1,
                go_http2_handler_stream_id(&rw, stream.server_conn, &stream_id),
                "responseWriter pointer chain is readable");
    assert_bool(23, stream_id, "responseWriter stream ID");
    assert_bool(0,
                go_http2_handler_stream_id(&rw, (void *)0x5678, &stream_id),
                "responseWriter stream must belong to the probed serverConn");
}

static void test_duplicate_valid_traceparents_are_rejected(void) {
    static const unsigned char first_name[] = "traceparent";
    static const unsigned char second_name[] = "TraceParent";
    static const unsigned char first_value[] =
        "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01";
    static const unsigned char second_value[] =
        "00-2122232425262728292a2b2c2d2e2f30-3132333435363738-00";
    grpc_header_field_t fields[] = {
        header_field(first_name, sizeof(first_name) - 1, first_value, sizeof(first_value) - 1),
        header_field(second_name, sizeof(second_name) - 1, second_value, sizeof(second_value) - 1),
    };
    tp_info_t tp;
    memset(&tp, 0x5a, sizeof(tp));
    const tp_info_t original = tp;

    process_fields(fields, 2, &tp);

    assert_bytes(&original, &tp, sizeof(tp), "reject duplicate valid traceparents");
}

static void test_valid_and_invalid_traceparents_are_rejected(void) {
    static const unsigned char name[] = "traceparent";
    static const unsigned char valid_value[] =
        "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01";
    static const unsigned char invalid_value[] =
        "00-z102030405060708090a0b0c0d0e0f10-1112131415161718-01";
    grpc_header_field_t fields[] = {
        header_field(name, sizeof(name) - 1, valid_value, sizeof(valid_value) - 1),
        header_field(name, sizeof(name) - 1, invalid_value, sizeof(invalid_value) - 1),
    };
    tp_info_t tp;
    memset(&tp, 0x5a, sizeof(tp));
    const tp_info_t original = tp;

    process_fields(fields, 2, &tp);

    assert_bytes(&original, &tp, sizeof(tp), "reject valid and invalid traceparents");
}

static void test_traceparent_beyond_scan_bound_is_non_authoritative(void) {
    static const unsigned char name[] = "traceparent";
    static const unsigned char first_value[] =
        "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01";
    static const unsigned char final_value[] =
        "00-2122232425262728292a2b2c2d2e2f30-3132333435363738-00";
    grpc_header_field_t fields[k_go_meta_headers_max_fields + 1] = {};
    fields[0] = header_field(name, sizeof(name) - 1, first_value, sizeof(first_value) - 1);
    fields[k_go_meta_headers_max_fields] =
        header_field(name, sizeof(name) - 1, final_value, sizeof(final_value) - 1);
    tp_info_t tp;
    memset(&tp, 0x5a, sizeof(tp));
    const tp_info_t original = tp;

    process_fields(fields, k_go_meta_headers_max_fields + 1, &tp);

    assert_bytes(&original, &tp, sizeof(tp), "reject traceparent beyond scan bound");
}

int main(void) {
    test_single_traceparent_is_decoded();
    test_http2_server_shape_is_normalized();
    test_http2_server_classification();
    test_http2_stream_layout_helpers();
    test_duplicate_valid_traceparents_are_rejected();
    test_valid_and_invalid_traceparents_are_rejected();
    test_traceparent_beyond_scan_bound_is_non_authoritative();
    return failures == 0 ? 0 : 1;
}
