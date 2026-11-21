// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>

#include <common/algorithm.h>
#include <common/h2_defs.h>
#include <common/http1_traceparent.h>
#include <common/http_trace_parent.h>
#include <common/preempt_guard.h>
#include <common/rust_abi.h>
#include <common/rust_http_buffer.h>
#include <common/rust_task.h>
#include <common/sampling.h>
#include <common/tc_common.h>
#include <common/trace_helpers.h>
#include <common/tracing.h>

#include <generictracer/protocol_common.h>

#include <maps/ongoing_http2_grpc.h>
#include <maps/tp_char_buf_mem.h>
#include <shared/obi_ctx.h>
#include <tpinjector/maps/otel_traces_pids.h>

enum {
    k_rust_max_headers = 64,
    k_rust_invalid_hex_digit = 0xff,
    k_rust_h2_method_none = 0xff,
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, rust_http_args_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_http_args SEC(".maps");

SCRATCH_MEM_TYPED(rust_http_request, rust_http_request_t)
SCRATCH_MEM_TYPED(rust_http_args, rust_http_args_t)
SCRATCH_MEM_SIZED(rust_http_header, TP_SIZE)

static __noinline bool rust_existing_header(u64 headers,
                                            const rust_protocol_config_t *config,
                                            rust_http_request_t *request);

static __always_inline void rust_new_client_request(u64 id, rust_http_request_t *request) {
    __builtin_memset(request, 0, sizeof(*request));
    const tp_info_pid_t *parent = rust_client_context_enabled(id) ? rust_current_context(id) : NULL;

    if (parent && parent->valid) {
        request->parent = *parent;
        request->wire = parent->tp;
        __builtin_memcpy(request->wire.parent_id, parent->tp.span_id, SPAN_ID_SIZE_BYTES);
        urand_bytes(request->wire.span_id, SPAN_ID_SIZE_BYTES);
        request->wire.ts = bpf_ktime_get_ns();
    } else {
        bpf_dbg_printk("rust client parent unavailable; starting root");
        init_new_trace(&request->wire);
    }

    request->inject = 1;
}

static __always_inline void rust_publish_wire_parent(u64 id, const rust_http_request_t *request) {
    if (request->parent.valid) {
        rust_save_wire_parent(id, &request->wire, &request->parent);
    }
}

static __always_inline u64 rust_http1_request_data(u64 vector,
                                                   const rust_protocol_config_t *config,
                                                   u64 len) {
    // Hyper also uses these formatters for trailers; classify before publishing ownership.
    u64 ptr = 0;
    if (!rust_read_u64(vector, config->vec_ptr, &ptr)) {
        bpf_dbg_printk("rust http1 request buffer unavailable vector=%llx", vector);
        return 0;
    }

    unsigned char prefix[MIN_HTTP_SIZE];
    if (len < sizeof(prefix)) {
        bpf_dbg_printk("rust http1 request prefix too short len=%llu", len);
        return 0;
    }

    const long read_result = bpf_probe_read_user(prefix, sizeof(prefix), (void *)ptr);
    if (read_result != 0) {
        bpf_dbg_printk("rust http1 request prefix unavailable buffer=%llx", vector);
        return 0;
    }

    if (!is_http_request_buf(prefix)) {
        bpf_dbg_printk("rust http1 expected HTTP request buffer=%llx", vector);
        return 0;
    }

    return ptr;
}

static __always_inline bool rust_http1_append(
    u64 vector, const rust_protocol_config_t *config, u64 ptr, u64 len, const tp_info_t *wire) {
    u64 cap = 0;
    unsigned char *header = rust_http_header_mem();
    if (!header || !rust_read_u64(vector, config->vec_cap, &cap) ||
        len > (TRACE_BUF_SIZE - TP_SIZE) || cap > k_rust_max_buffer || cap < len ||
        (cap - len) < TP_SIZE || (ptr + cap) < ptr) {
        bpf_dbg_printk(
            "rust http1 buffer rejected buffer=%llx len=%llu cap=%llu", vector, len, cap);
        return false;
    }

    __builtin_memcpy(header, TP_LOWER, TP_LOWER_SIZE);
    make_tp_string(header + TP_LOWER_SIZE, wire);
    header[TP_SIZE - 2] = '\r';
    header[TP_SIZE - 1] = '\n';

    const u64 dest = ptr + len;
    const long result = bpf_probe_write_user((void *)dest, header, TP_SIZE);

    if (result != 0) {
        bpf_dbg_printk("rust http1 append dst=%llx len=%u err=%ld", dest, (u32)TP_SIZE, result);
        return false;
    }

    const u64 new_len = len + TP_SIZE;
    const long commit =
        bpf_probe_write_user((void *)(vector + config->vec_len), &new_len, sizeof(new_len));
    if (commit != 0) {
        bpf_dbg_printk("rust http1 length commit failed err=%ld", commit);
        return false;
    }

    bpf_dbg_printk("rust traceparent appended buffer=%llx len=%llu", vector, new_len);
    return true;
}

static __always_inline bool rust_http1_ends_with_request_line(u64 ptr, u64 len) {
    unsigned char suffix[sizeof(" HTTP/1.1\r\n") - 1];
    if (len < sizeof(suffix)) {
        return false;
    }

    const u64 start = ptr + len - sizeof(suffix);
    if (bpf_probe_read_user(suffix, sizeof(suffix), (void *)start) != 0) {
        return false;
    }

    return __builtin_memcmp(suffix, " HTTP/1.1\r\n", sizeof(suffix)) == 0 ||
           __builtin_memcmp(suffix, " HTTP/1.0\r\n", sizeof(suffix)) == 0;
}

static __always_inline void rust_http1_entry(u64 id, u64 vector, u64 headers) {
    const rust_protocol_config_t *config = rust_protocol_config(id);
    if (!config || !config->http1 || !config->inject || !rust_process_instrumented(id)) {
        return;
    }

    rust_http_args_t *args = rust_http_args_mem();
    if (!args) {
        return;
    }

    __builtin_memset(args, 0, sizeof(*args));
    args->buffer = vector;
    if (!rust_read_u64(vector, config->vec_len, &args->start_len)) {
        return;
    }
    bpf_dbg_printk("rust h1 headers buffer=%llx", vector);
    rust_new_client_request(id, &args->request);

    if (!rust_existing_header(headers, config, &args->request)) {
        bpf_dbg_printk("rust h1 header layout unreadable map=%llx", headers);
        args->request.inject = 0;
    }

    // Hyper has written the request line. Inserting here can fit on a resident
    // page even when appending after the application's headers would fault.
    if (args->request.inject && g_bpf_probe_write_user_enabled && !exports_otel_traces()) {
        const u64 ptr = rust_http1_request_data(vector, config, args->start_len);
        if (ptr && rust_http1_ends_with_request_line(ptr, args->start_len) &&
            rust_http1_append(vector, config, ptr, args->start_len, &args->request.wire)) {
            args->request.injection_result = k_rust_injection_succeeded;
        }
    }
    bpf_map_update_elem(&rust_http_args, &id, args, BPF_ANY);
}

// Snapshot the task context and HeaderMap and try insertion before Hyper's
// standard and title-case formatters write the application headers.
SEC("uprobe/rust:http1_headers")
int GUARDED_PROG(obi_rust_http1_headers, struct pt_regs *, ctx) {
    rust_http1_entry(bpf_get_current_pid_tgid(), PT_REGS_PARM2(ctx), PT_REGS_PARM1(ctx));
    return 0;
}

// Cover Hyper's original-case formatter too. Its extra HeaderCaseMap argument
// moves the output Vec to the third argument slot.
SEC("uprobe/rust:http1_headers_original")
int GUARDED_PROG(obi_rust_http1_headers_original, struct pt_regs *, ctx) {
    rust_http1_entry(bpf_get_current_pid_tgid(), PT_REGS_PARM3(ctx), PT_REGS_PARM1(ctx));
    return 0;
}

static __always_inline int rust_http1_headers_return(bool use_bpf_loop) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_protocol_config_t *config = rust_protocol_config(id);
    const rust_http_args_t *saved = bpf_map_lookup_elem(&rust_http_args, &id);

    if (!saved || !config || !rust_process_instrumented(id)) {
        return 0;
    }

    rust_http_args_t args = *saved;
    bpf_map_delete_elem(&rust_http_args, &id);

    u64 len = 0;
    if (!rust_read_u64(args.buffer, config->vec_len, &len)) {
        bpf_dbg_printk("rust http1 request length unavailable buffer=%llx", args.buffer);
        return 0;
    }
    const u64 ptr = rust_http1_request_data(args.buffer, config, len);
    if (!ptr) {
        return 0;
    }

    rust_save_request(id, &args.request);
    rust_publish_wire_parent(id, &args.request);
    if (args.request.injection_result == k_rust_injection_succeeded) {
        return 0;
    }
    if (exports_otel_traces()) {
        bpf_dbg_printk("rust http exporter header insertion skipped");
        return 0;
    }

    if (args.request.forwarded) {
        if (g_bpf_probe_write_user_enabled && args.start_len <= len &&
            rust_http1_rewrite_traceparent(
                ptr + args.start_len, len - args.start_len, &args.request.wire, use_bpf_loop)) {
            args.request.injection_result = k_rust_injection_succeeded;
            rust_save_request(id, &args.request);
            bpf_dbg_printk("rust forwarded h1 traceparent rewritten");
        } else {
            bpf_dbg_printk("rust forwarded h1 user rewrite unavailable");
        }
        return 0;
    }

    if (!args.request.inject || !g_bpf_probe_write_user_enabled) {
        bpf_dbg_printk("rust h1 header insertion skipped");
        return 0;
    }

    if (rust_http1_append(args.buffer, config, ptr, len, &args.request.wire)) {
        args.request.injection_result = k_rust_injection_succeeded;
        rust_save_request(id, &args.request);
    }
    return 0;
}

// Publish ownership, rewrite forwarded headers, or retry an append after Hyper grows the Vec.
SEC("uretprobe/rust:http1_headers")
int GUARDED_PROG(obi_rust_http1_headers_ret, struct pt_regs *, ctx) {
    (void)ctx;
    return rust_http1_headers_return(true);
}

// A separate entry keeps bpf_loop callbacks out of older kernels' func_info.
SEC("uretprobe/rust:http1_headers_legacy")
int GUARDED_PROG(obi_rust_http1_headers_ret_legacy, struct pt_regs *, ctx) {
    (void)ctx;
    return rust_http1_headers_return(false);
}

// Find an application-supplied traceparent so injection can preserve it.
// The http crate's HeaderName has two internal storage variants:
//   Standard(StandardHeader): a compact enum for built-in names such as "host".
//   Custom(ByteStr): name bytes, used for "traceparent" in supported http versions.
//
// A name match disables injection even if the value is invalid.
// Return true when the name scan completes (including no match), or false when
// the map/name layout or memory cannot be read safely.
static __noinline bool rust_existing_header(u64 headers,
                                            const rust_protocol_config_t *config,
                                            rust_http_request_t *request) {
    u64 entries = 0;
    u64 count = 0;
    u64 found = 0;
    if (!rust_read_u64(headers, config->header_entries, &entries) ||
        !rust_read_u64(headers, config->header_count, &count) || count > k_rust_max_headers) {
        bpf_dbg_printk("rust header map rejected addr=%llx count=%llu", headers, count);
        return false;
    }

    for (u32 i = 0; i < k_rust_max_headers; i++) {
        if (i >= count) {
            break;
        }

        const u64 bucket = entries + i * config->bucket_size;
        u64 name = 0;
        u64 len = 0;
        if (!rust_read_u64(bucket, config->name_len, &len)) {
            return false;
        }

        if (len != TP_HEADER_SIZE) {
            continue;
        }

        if (!rust_read_u64(bucket, config->name_ptr, &name)) {
            return false;
        }

        unsigned char text[TP_HEADER_SIZE] __attribute__((aligned(8)));
        if (bpf_probe_read_user(text, sizeof(text), (void *)name) != 0) {
            return false;
        }

        if (bpf_memcmp(text, TP_HEADER, TP_HEADER_SIZE) == 0) {
            found = bucket;
            break;
        }
    }

    if (!found) {
        return true;
    }

    request->inject = 0;
    request->injection_result = k_rust_injection_application_owned;
    bpf_dbg_printk("rust application traceparent found map=%llx", headers);
    u64 value = 0;
    u64 len = 0;
    unsigned char tp[TP_MAX_VAL_LENGTH];
    if (!rust_read_u64(found, config->value_len, &len) || len != sizeof(tp) ||
        !rust_read_u64(found, config->value_ptr, &value) ||
        bpf_probe_read_user(tp, sizeof(tp), (void *)value) != 0) {
        return true;
    }

    for (u32 pos = 0; pos < sizeof(tp); pos++) {
        if (pos == k_tp_val_dash1 || pos == k_tp_val_dash2 || pos == k_tp_val_dash3) {
            if (tp[pos] != '-') {
                return true;
            }
        } else if (reverse_hex[tp[pos]] == k_rust_invalid_hex_digit) {
            return true;
        }
    }

    if ((tp[0] | k_ascii_lowercase_bit) == 'f' && (tp[1] | k_ascii_lowercase_bit) == 'f') {
        return true;
    }

    tp_info_t wire = request->wire;
    decode_hex(wire.trace_id, tp + k_tp_val_trace_id_start, TRACE_ID_CHAR_LEN);
    decode_hex(wire.span_id, tp + k_tp_val_span_id_start, SPAN_ID_CHAR_LEN);
    decode_hex(&wire.flags, tp + k_tp_val_flags_start, 2);
    if (!valid_trace(wire.trace_id) || !valid_span(wire.span_id)) {
        return true;
    }

    if (bpf_memcmp(wire.trace_id, request->parent.tp.trace_id, TRACE_ID_SIZE_BYTES) != 0) {
        __builtin_memset(&request->parent, 0, sizeof(request->parent));
        __builtin_memset(wire.parent_id, 0, sizeof(wire.parent_id));
    }

    // A header forwarded unchanged names the server's own caller. Keep the new client
    // span: adopting the caller's ID would make the server and client each other's parent.
    if (request->parent.valid &&
        bpf_memcmp(wire.span_id, request->parent.tp.parent_id, SPAN_ID_SIZE_BYTES) == 0) {
        request->forwarded = 1;
        bpf_dbg_printk("rust forwarded traceparent, keeping a distinct client span");
        return true;
    }

    request->wire = wire;
    return true;
}

// Captures the context when h2 queues request headers. We store the snapshot by sender and
// stream so the connection driver can recover each request's parent independently.
SEC("uprobe/rust:h2_send_headers")
int GUARDED_PROG(obi_rust_h2_send_headers, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_protocol_config_t *config = rust_protocol_config(id);
    if (!config || !config->http2 || !rust_process_instrumented(id)) {
        return 0;
    }

    rust_h2_key_t key = {.pid = obi_pid(id), .sender = PT_REGS_PARM1(ctx)};
    const u64 headers = PT_REGS_PARM2(ctx);
    u8 method = k_rust_h2_method_none;
    if (bpf_probe_read_user(&method, sizeof(method), (void *)(headers + config->h2_method)) != 0 ||
        method == k_rust_h2_method_none) {
        return 0;
    }

    rust_http_request_t *request = rust_http_request_mem();
    if (!request || bpf_probe_read_user(&key.stream_id,
                                        sizeof(key.stream_id),
                                        (void *)(headers + config->h2_stream_id)) != 0) {
        return 0;
    }

    rust_new_client_request(id, request);
    if (!rust_existing_header(headers + config->h2_fields, config, request)) {
        request->inject = 0;
    }

    bpf_map_update_elem(&rust_h2_requests, &key, request, BPF_ANY);
    bpf_dbg_printk("rust h2 request sender=%llx stream=%u parent=%u",
                   key.sender,
                   key.stream_id,
                   request->parent.valid);
    return 0;
}

static __always_inline void rust_h2_sender(u64 id, u64 sender) {
    if (!rust_process_instrumented(id)) {
        return;
    }

    bpf_map_update_elem(&rust_h2_senders, &id, &sender, BPF_ANY);
    bpf_dbg_printk("rust h2 driver sender=%llx", sender);
    rust_task_key_t task = {};

    if (rust_current_task(id, &task)) {
        bpf_map_update_elem(&rust_h2_tasks, &task, &sender, BPF_ANY);
    }
}

// Associates the pending-frame encoding with its Send connection. Also binds the current
// Tokio task to that sender, so that later socket writes can resolve stream ownership.
SEC("uprobe/rust:h2_buffer_pending")
int GUARDED_PROG(obi_rust_h2_buffer_pending, struct pt_regs *, ctx) {
    rust_h2_sender(bpf_get_current_pid_tgid(), rust_sret_arg1(ctx));
    return 0;
}

// Creates the Send association during flushing, covering builds that
// inline buffer_pending and retain only the poll_complete boundary.
SEC("uprobe/rust:h2_poll_complete")
int GUARDED_PROG(obi_rust_h2_poll_complete, struct pt_regs *, ctx) {
    rust_h2_sender(bpf_get_current_pid_tgid(), PT_REGS_PARM1(ctx));
    return 0;
}

// A fallback when Send::buffer_pending is inlined. We recover the enclosing Send from
// its Prioritize field so encoding still uses the same connection/stream keys.
SEC("uprobe/rust:h2_prioritize_pending")
int GUARDED_PROG(obi_rust_h2_prioritize_pending, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_protocol_config_t *config = rust_protocol_config(id);

    if (config) {
        rust_h2_sender(id, rust_sret_arg1(ctx) - config->h2_prioritize);
    }

    return 0;
}

// Covers an inlined Send::poll_complete through Prioritize::poll_complete, using
// the recorded field offset to recover the enclosing Send connection.
SEC("uprobe/rust:h2_prioritize_complete")
int GUARDED_PROG(obi_rust_h2_prioritize_complete, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_protocol_config_t *config = rust_protocol_config(id);

    if (config) {
        rust_h2_sender(id, PT_REGS_PARM1(ctx) - config->h2_prioritize);
    }

    return 0;
}

// Shared return hook for all four inlined boundaries above. Clears the synchronous
// encoder association, so the task's sender binding remains for later socket writes.
SEC("uretprobe/rust:h2_buffer_pending")
int GUARDED_PROG(obi_rust_h2_buffer_pending_ret, struct pt_regs *, ctx) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&rust_h2_senders, &id);

    return 0;
}

// Matches Headers::encode to its saved request and record the output buffer's start
// position, so the return hook can locate and extend the newly encoded frame.
SEC("uprobe/rust:h2_encode")
int GUARDED_PROG(obi_rust_h2_encode, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_protocol_config_t *config = rust_protocol_config(id);
    const u64 *sender = bpf_map_lookup_elem(&rust_h2_senders, &id);

    if (!config || !config->http2 || !sender || !rust_process_instrumented(id)) {
        return 0;
    }

    rust_h2_key_t key = {.pid = obi_pid(id), .sender = *sender};
    if (bpf_probe_read_user(&key.stream_id,
                            sizeof(key.stream_id),
                            (void *)(rust_sret_arg1(ctx) + config->h2_stream_id)) != 0) {
        return 0;
    }

    const rust_http_request_t *request = bpf_map_lookup_elem(&rust_h2_requests, &key);
    rust_http_args_t *args = rust_http_args_mem();
    if (!request || !args) {
        bpf_dbg_printk(
            "rust h2 encode context missing sender=%llx stream=%u", key.sender, key.stream_id);
        return 0;
    }

    __builtin_memset(args, 0, sizeof(*args));
    args->request = *request;
    args->stream_id = key.stream_id;
    args->sender = key.sender;
    args->limit = rust_sret_arg3(ctx);
    if (rust_read_u64(args->limit, config->limit_inner, &args->buffer) &&
        rust_read_u64(args->buffer, config->bytes_len, &args->start_len)) {
        bpf_dbg_printk("rust h2 encode sender=%llx stream=%u len=%llu",
                       key.sender,
                       key.stream_id,
                       args->start_len);
        bpf_map_update_elem(&rust_http_args, &id, args, BPF_ANY);
    }

    return 0;
}

// Sets up the wire parent for generic header capture. If the inner HPACK hook did not
// insert traceparent, we try the complete HEADERS frame and record injection ownership.
SEC("uretprobe/rust:h2_encode")
int GUARDED_PROG(obi_rust_h2_encode_ret, struct pt_regs *, ctx) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();
    const rust_protocol_config_t *config = rust_protocol_config(id);
    const rust_http_args_t *saved = bpf_map_lookup_elem(&rust_http_args, &id);
    if (!saved || !config || !rust_process_instrumented(id)) {
        return 0;
    }

    rust_http_args_t args = *saved;
    bpf_map_delete_elem(&rust_http_args, &id);
    rust_publish_wire_parent(id, &args.request);
    if (exports_otel_traces()) {
        bpf_dbg_printk("rust h2 exporter header insertion skipped");
        return 0;
    }

    if (!config->inject || !g_bpf_probe_write_user_enabled) {
        return 0;
    }

    if (args.request.inject) {
        args.request.injection_result = rust_http2_append(&args, config)
                                            ? k_rust_injection_succeeded
                                            : k_rust_injection_skipped;
    }

    bpf_dbg_printk(
        "rust h2 injection stream=%u result=%u", args.stream_id, args.request.injection_result);
    const rust_h2_key_t key = {
        .pid = obi_pid(id), .sender = args.sender, .stream_id = args.stream_id};
    bpf_map_update_elem(&rust_h2_requests, &key, &args.request, BPF_ANY);

    return 0;
}

// Remembers the HPACK output buffer while Headers::encode is active, allowing the
// return hook to extend the header block before the outer frame length is committed.
SEC("uprobe/rust:h2_hpack")
int GUARDED_PROG(obi_rust_h2_hpack, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    rust_http_args_t *args = bpf_map_lookup_elem(&rust_http_args, &id);

    if (args && rust_process_instrumented(id)) {
        args->hpack_buffer = PT_REGS_PARM3(ctx);
    }

    return 0;
}

// Appends a non-indexed traceparent literal before the frame encoder publishes its
// length, then we mark it as handled so frame-level and socket injection do not duplicate it.
SEC("uretprobe/rust:h2_hpack")
int GUARDED_PROG(obi_rust_h2_hpack_ret, struct pt_regs *, ctx) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();
    rust_http_args_t *args = bpf_map_lookup_elem(&rust_http_args, &id);
    const rust_protocol_config_t *config = rust_protocol_config(id);

    if (exports_otel_traces()) {
        bpf_dbg_printk("rust hpack exporter header insertion skipped");
        return 0;
    }

    if (args && rust_process_instrumented(id) && config && config->inject &&
        g_bpf_probe_write_user_enabled && args->request.inject && rust_hpack_append(args, config)) {
        args->request.inject = 0;
        args->request.injection_result = k_rust_injection_succeeded;
        bpf_dbg_printk("rust hpack traceparent appended stream=%u", args->stream_id);
    }

    return 0;
}

typedef struct rust_h2_server_args {
    http2_conn_stream_t stream;
    u32 _pad;
    u64 output;
} rust_h2_server_args_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, rust_h2_server_args_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_h2_server_args SEC(".maps");

static __always_inline int rust_h2_server_request(u64 id, u64 address, u32 offset, u64 output) {
    const rust_protocol_config_t *config = rust_protocol_config(id);
    rust_task_key_t task = {};
    if (!config || !config->h2_server || !rust_current_task(id, &task)) {
        return 0;
    }

    const tp_info_pid_t empty = {};
    rust_set_context(id, &empty);
    const ssl_pid_connection_info_t *conn = bpf_map_lookup_elem(&rust_io_connections, &task);
    if (!conn) {
        bpf_dbg_printk("rust h2 server connection missing task=%llx", task.addr);
        return 0;
    }

    rust_h2_server_args_t args = {.stream = {.pid_conn = conn->p_conn}, .output = output};

    if (bpf_probe_read_user(&args.stream.stream_id,
                            sizeof(args.stream.stream_id),
                            (void *)(address + offset)) == 0) {
        bpf_dbg_printk(
            "rust h2 server dispatch task=%llx stream=%u", task.addr, args.stream.stream_id);
        bpf_map_update_elem(&rust_h2_server_args, &id, &args, BPF_ANY);
    }

    return 0;
}

// Captures Recv's incoming stream and return-buffer identity before it hands over
// the decoded request. We clear the current task's previous parent until it is resolved.
SEC("uprobe/rust:h2_take_request")
int GUARDED_PROG(obi_rust_h2_take_request, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_protocol_config_t *config = rust_protocol_config(id);
    return config ? rust_h2_server_request(
                        id, rust_sret_arg2(ctx), config->h2_store_stream_id, rust_sret(ctx))
                  : 0;
}

// Alternative dispatch boundary when Recv::take_request is unavailable. StreamRef
// supplies the stream ID needed to find the same generic server-span record.
SEC("uprobe/rust:h2_take_stream_request")
int GUARDED_PROG(obi_rust_h2_take_stream_request, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_protocol_config_t *config = rust_protocol_config(id);
    return config && config->h2_stream_ref_id
               ? rust_h2_server_request(
                     id, rust_sret_arg1(ctx), config->h2_stream_ref_id, rust_sret(ctx))
               : 0;
}

// Shared return hook for both dispatch APIs. We use the decoded HeaderMap to recover
// the remote parent and install this stream's server span on the receiving Tokio
// task, right before application handlers issue downstream requests.
SEC("uretprobe/rust:h2_take_request")
int GUARDED_PROG(obi_rust_h2_take_request_ret, struct pt_regs *, ctx) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();
    const rust_protocol_config_t *config = rust_protocol_config(id);
    const rust_h2_server_args_t *saved = bpf_map_lookup_elem(&rust_h2_server_args, &id);
    if (!config || !saved || !rust_process_instrumented(id)) {
        return 0;
    }

    const rust_h2_server_args_t args = *saved;
    bpf_map_delete_elem(&rust_h2_server_args, &id);
    http2_grpc_request_t *info = bpf_map_lookup_elem(&ongoing_http2_grpc, &args.stream);
    rust_http_request_t *header = rust_http_request_mem();
    if (!info || !header || info->type != k_event_type_http_request) {
        bpf_dbg_printk("rust h2 server state unavailable stream=%u", args.stream.stream_id);
        return 0;
    }

    __builtin_memset(header, 0, sizeof(*header));
    rust_existing_header(args.output + config->request_headers, config, header);
    if (valid_trace(header->wire.trace_id)) {
        unsigned char provisional_trace_id[TRACE_ID_SIZE_BYTES];
        __builtin_memcpy(provisional_trace_id, info->tp.trace_id, sizeof(provisional_trace_id));

        __builtin_memcpy(info->tp.trace_id, header->wire.trace_id, sizeof(info->tp.trace_id));
        __builtin_memcpy(info->tp.parent_id, header->wire.span_id, sizeof(info->tp.parent_id));
        info->tp.flags = header->wire.flags;
        sample_remote_child(&info->tp);
        bpf_dbg_printk("rust h2 server remote parent stream=%u", args.stream.stream_id);

        // The stream was indexed under its provisional trace when the frame was read.
        if (http_server_index_enabled()) {
            unindex_http_server_trace_id(
                args.stream.pid_conn.pid, provisional_trace_id, info->tp.span_id);
            index_http_server_context(&args.stream, &info->tp);
        }
    } else {
        bpf_dbg_printk("rust h2 server remote parent absent stream=%u", args.stream.stream_id);
    }

    const tp_info_pid_t parent = {.tp = info->tp, .valid = 1, .req_type = info->type};
    rust_set_context(id, &parent);
    obi_ctx__set(id, &parent.tp);

    return 0;
}
