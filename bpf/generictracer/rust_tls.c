// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/algorithm.h>
#include <common/preempt_guard.h>
#include <common/rust_abi.h>
#include <common/rust_task.h>
#include <generictracer/ssl_defs.h>

// Low-address heuristic: zero-sized Rustls invalid-cipher boxes can use shared
// dangling pointers, which cannot identify a connection. The fixed 4096 cutoff
// rejects common small pointer values.
enum { k_rustls_low_address_limit = 4096 };
enum { k_rustls_max_buffer_len = 1 << 20 };

typedef struct rustls_process_args {
    u64 common;
    ssl_pid_connection_info_t connection;
} rustls_process_args_t;

typedef struct rustls_buffer {
    u64 common;
    u64 data;
    u64 len;
    u64 vectors;
} rustls_buffer_t;

typedef struct rustls_reader_args {
    u64 output;
    u64 buffer;
} rustls_reader_args_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, rustls_process_args_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rustls_process_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, rust_task_key_t);
    __type(value, ssl_pid_connection_info_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rustls_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, rustls_reader_args_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rustls_reader_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, rust_task_key_t);
    __type(value, rustls_buffer_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rustls_read_buffers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, rustls_buffer_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rustls_plain_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, rustls_buffer_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rustls_read_args SEC(".maps");

SCRATCH_MEM_TYPED(rustls_process, rustls_process_args_t)
SCRATCH_MEM_TYPED(rust_tls_flush, rust_tls_flush_t)

static __always_inline bool rustls_enabled(u64 id) {
    const rust_protocol_config_t *config = rust_protocol_config(id);
    return config && config->rustls && rust_process_instrumented(id) && valid_pid(id);
}

// Build a PID-scoped key for looking up this Rustls connection's socket binding.
// common is the user-space CommonState address. offset selects the boxed message
// encrypter's or decrypter's data pointer, using the recorded library layout.
// CommonState can move in memory, while these separately allocated objects retain
// their addresses. Callers try both pointers so replacing one cipher can leave the
// other available to recover the binding. Low-address values are rejected.
// On success, key->addr contains the selected object address, rather than CommonState.
static __always_inline bool rustls_anchor(u64 id, u64 common, u32 offset, rust_task_key_t *key) {
    *key = (rust_task_key_t){.pid = obi_pid(id)};
    if (!rust_process_instrumented(id)) {
        return false;
    }
    if (!common) {
        return false;
    }
    if (!offset) {
        return false;
    }

    const void *pointer_field = (const void *)(common + offset);
    const long read_result = bpf_probe_read_user(&key->addr, sizeof(key->addr), pointer_field);
    if (read_result != 0) {
        return false;
    }

    return key->addr > k_rustls_low_address_limit;
}

static __always_inline const ssl_pid_connection_info_t *rustls_connection(u64 id, u64 common) {
    const rust_protocol_config_t *config = rust_protocol_config(id);
    if (!config) {
        return NULL;
    }

    rust_task_key_t key = {};
    if (rustls_anchor(id, common, config->tls_encrypter, &key)) {
        const ssl_pid_connection_info_t *connection =
            bpf_map_lookup_elem(&rustls_connections, &key);

        if (connection) {
            return connection;
        }
    }

    if (rustls_anchor(id, common, config->tls_decrypter, &key)) {
        const ssl_pid_connection_info_t *connection =
            bpf_map_lookup_elem(&rustls_connections, &key);

        if (connection) {
            bpf_dbg_printk("rustls decrypt fallback common=%llx key=%llx", common, key.addr);
            return connection;
        }
    }

    bpf_dbg_printk("rustls connection missing common=%llx", common);
    return NULL;
}

static __always_inline void
rustls_bind_connection(u64 id, u64 common, const ssl_pid_connection_info_t *connection) {
    const rust_protocol_config_t *config = rust_protocol_config(id);
    if (!config) {
        return;
    }

    rust_task_key_t key = {};
    if (rustls_anchor(id, common, config->tls_encrypter, &key)) {
        const long result = bpf_map_update_elem(&rustls_connections, &key, connection, BPF_ANY);
        bpf_dbg_printk(
            "rustls encrypt bind common=%llx key=%llx err=%ld", common, key.addr, result);
        bpf_map_update_elem(&active_ssl_connections, &connection->p_conn, &key.addr, BPF_ANY);
    }

    if (rustls_anchor(id, common, config->tls_decrypter, &key)) {
        const long result = bpf_map_update_elem(&rustls_connections, &key, connection, BPF_ANY);
        bpf_dbg_printk(
            "rustls decrypt bind common=%llx key=%llx err=%ld", common, key.addr, result);
        bpf_map_update_elem(&active_ssl_connections, &connection->p_conn, &key.addr, BPF_ANY);
    }
}

static __always_inline void rustls_flush_entry(u64 id, u64 common) {
    bpf_map_delete_elem(&rust_tls_flushes, &id);
    rust_tls_flush_t *flush = rust_tls_flush_mem();

    if (flush && rustls_enabled(id)) {
        __builtin_memset(flush, 0, sizeof(*flush));
        flush->common = common;

        bpf_dbg_printk("rustls flush enter common=%llx", common);
        bpf_map_update_elem(&rust_tls_flushes, &id, flush, BPF_ANY);
    }
}

// Marks a synchronous write_tls scope so generic socket-send probes can record
// the connection used to flush this Rustls state.
SEC("uprobe/rust:rustls_flush")
int GUARDED_PROG(obi_rustls_flush, struct pt_regs *, ctx) {
    rustls_flush_entry(bpf_get_current_pid_tgid(), PT_REGS_PARM1(ctx));
    return 0;
}

// Covers inlined write_tls calls through ChunkVecBuffer::write_to. Recovers the
// CommonState from the TLS buffer before tracking socket sends.
SEC("uprobe/rust:rustls_flush_buffer")
int GUARDED_PROG(obi_rustls_flush_buffer, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_protocol_config_t *config = rust_protocol_config(id);

    if (config && config->tls_sendable) {
        rustls_flush_entry(id, PT_REGS_PARM1(ctx) - config->tls_sendable);
    }

    return 0;
}

// Shared return hook for both flush entries: binds the socket observed during the
// flush to the current cipher objects, then discards the per-thread flush scope.
SEC("uretprobe/rust:rustls_flush")
int GUARDED_PROG(obi_rustls_flush_ret, struct pt_regs *, ctx) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();
    const rust_tls_flush_t *flush = bpf_map_lookup_elem(&rust_tls_flushes, &id);

    // Only socket I/O performed inside this synchronous write_tls call can bind it.
    if (flush && rust_process_instrumented(id) && flush->connection.orig_dport) {
        bpf_dbg_printk(
            "rustls flush bind common=%llx port=%u", flush->common, flush->connection.orig_dport);
        rustls_bind_connection(id, flush->common, &flush->connection);
    } else if (flush) {
        bpf_dbg_printk("rustls flush unbound common=%llx", flush->common);
    }

    bpf_map_delete_elem(&rust_tls_flushes, &id);
    return 0;
}

static __always_inline const ssl_pid_connection_info_t *rustls_read_connection(u64 id,
                                                                               u64 deframer) {
    const rust_protocol_config_t *config = rust_protocol_config(id);
    if (!config) {
        bpf_dbg_printk("rustls deframer config missing");
        return NULL;
    }

    u64 pointer = 0;
    const long pointer_read_result = bpf_probe_read_user(
        &pointer, sizeof(pointer), (void *)(deframer + config->tls_deframer_pointer));
    if (pointer_read_result != 0) {
        bpf_dbg_printk("rustls deframer pointer unavailable addr=%llx", deframer);
        return NULL;
    }

    u64 used = 0;
    const long used_read_result =
        bpf_probe_read_user(&used, sizeof(used), (void *)(deframer + config->tls_deframer_used));
    if (used_read_result != 0) {
        bpf_dbg_printk("rustls deframer length unavailable addr=%llx", deframer);
        return NULL;
    }

    if (used == 0) {
        bpf_dbg_printk("rustls deframer empty addr=%llx", deframer);
        return NULL;
    }

    if (used > k_rustls_max_buffer_len) {
        bpf_dbg_printk("rustls deframer too large addr=%llx used=%llu", deframer, used);
        return NULL;
    }

    const u64 buffer_end = pointer + used;
    if (buffer_end < pointer) {
        bpf_dbg_printk("rustls deframer address overflow pointer=%llx used=%llu", pointer, used);
        return NULL;
    }

    const rust_task_key_t key = {.pid = obi_pid(id), .addr = buffer_end};
    bpf_dbg_printk("rustls deframer lookup end=%llx used=%llu", key.addr, used);

    return bpf_map_lookup_elem(&rust_tls_reads, &key);
}

static __always_inline void rustls_process_entry(u64 id, u64 object, u64 deframer, bool server) {
    bpf_map_delete_elem(&rustls_process_args, &id);
    const rust_protocol_config_t *config = rust_protocol_config(id);
    rustls_process_args_t *args = rustls_process_mem();
    if (!config || !args || !rustls_enabled(id)) {
        return;
    }

    args->common = object + config->tls_common;
    bpf_dbg_printk("rustls process common=%llx server=%u", args->common, server);

    if (!config->tls_external_deframer) {
        deframer = object + (server ? config->tls_server_deframer : config->tls_client_deframer);
    }

    const ssl_pid_connection_info_t *connection = rustls_read_connection(id, deframer);
    if (!connection) {
        connection = rustls_connection(id, args->common);
    }

    if (connection) {
        args->connection = *connection;
        bpf_dbg_printk(
            "rustls process matched common=%llx port=%u", args->common, connection->orig_dport);
        bpf_map_update_elem(&rustls_process_args, &id, args, BPF_ANY);
    } else {
        bpf_dbg_printk("rustls process connection missing common=%llx", args->common);
    }
}

// At client process_new_packets entry, we match the encrypted deframer bytes to a socket
// read or we reuse the existing cipher binding. Here we save that connection for the return hook.
SEC("uprobe/rust:rustls_process_client")
int GUARDED_PROG(obi_rustls_process_client, struct pt_regs *, ctx) {
    rustls_process_entry(
        bpf_get_current_pid_tgid(), rust_sret_arg1(ctx), rust_sret_arg2(ctx), false);
    return 0;
}

// Sets up the same socket association above for server process_new_packets, using the
// server deframer layout. Both ConnectionCore and older ConnectionCommon use this hook.
SEC("uprobe/rust:rustls_process_server")
int GUARDED_PROG(obi_rustls_process_server, struct pt_regs *, ctx) {
    rustls_process_entry(
        bpf_get_current_pid_tgid(), rust_sret_arg1(ctx), rust_sret_arg2(ctx), true);
    return 0;
}

// After client or server packet processing, we bind the saved socket to the cipher
// objects. Typically handshake processing and key updates can replace them.
SEC("uretprobe/rust:rustls_process")
int GUARDED_PROG(obi_rustls_process_ret, struct pt_regs *, ctx) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();
    const rustls_process_args_t *args = bpf_map_lookup_elem(&rustls_process_args, &id);

    if (args && rust_process_instrumented(id)) {
        rustls_bind_connection(id, args->common, &args->connection);
    } else if (args) {
        bpf_dbg_printk("rustls process disabled common=%llx", args->common);
    }

    bpf_map_delete_elem(&rustls_process_args, &id);
    return 0;
}

// Starts the peek/consume capture path used by tokio-rustls. We save the Reader's
// plaintext-buffer identity and hidden result pointer for the returned slice,
// and finish any delayed HTTP request before the next read.
SEC("uprobe/rust:rustls_first_chunk")
int GUARDED_PROG(obi_rustls_first_chunk, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_protocol_config_t *config = rust_protocol_config(id);

    if (!config || !rustls_enabled(id)) {
        return 0;
    }

    rustls_reader_args_t args = {.output = rust_sret(ctx)};
    if (bpf_probe_read_user(&args.buffer,
                            sizeof(args.buffer),
                            (void *)(rust_sret_arg1(ctx) + config->reader_buffer)) != 0) {
        bpf_dbg_printk("rustls reader buffer unavailable reader=%llx", rust_sret_arg1(ctx));
        return 0;
    }

    const ssl_pid_connection_info_t *connection =
        rustls_connection(id, args.buffer - config->tls_plaintext);
    if (connection) {
        finish_possible_delayed_tls_http_request((pid_connection_info_t *)&connection->p_conn);
        bpf_map_update_elem(&rustls_reader_args, &id, &args, BPF_ANY);
    }

    return 0;
}

static __always_inline void rustls_save_peeked_buffer(u64 id,
                                                      const rustls_reader_args_t *args,
                                                      const rust_protocol_config_t *config) {
    rustls_buffer_t buffer = {.common = args->buffer - config->tls_plaintext};

    const long data_read_result =
        bpf_probe_read_user(&buffer.data, sizeof(buffer.data), (void *)args->output);
    if (data_read_result != 0) {
        bpf_dbg_printk("rustls peek data unavailable output=%llx", args->output);
        return;
    }

    const long length_read_result = bpf_probe_read_user(
        &buffer.len, sizeof(buffer.len), (void *)(args->output + sizeof(buffer.data)));
    if (length_read_result != 0) {
        bpf_dbg_printk("rustls peek length unavailable output=%llx", args->output);
        return;
    }

    if (buffer.data <= k_rustls_low_address_limit) {
        bpf_dbg_printk("rustls peek invalid data=%llx", buffer.data);
        return;
    }

    if (buffer.len == 0) {
        bpf_dbg_printk("rustls peek empty common=%llx", buffer.common);
        return;
    }

    if (buffer.len > k_rustls_max_buffer_len) {
        bpf_dbg_printk("rustls peek too large len=%llu", buffer.len);
        return;
    }

    const rust_task_key_t key = {.pid = obi_pid(id), .addr = args->buffer};
    bpf_dbg_printk("rustls peek common=%llx len=%llu", buffer.common, buffer.len);
    bpf_map_update_elem(&rustls_read_buffers, &key, &buffer, BPF_ANY);
}

// Retains the slice returned by Reader::into_first_chunk. The capture waits for
// consume_first_chunk, so peeking alone does not emit plaintext multiple times.
SEC("uretprobe/rust:rustls_first_chunk")
int GUARDED_PROG(obi_rustls_first_chunk_ret, struct pt_regs *, ctx) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();
    const rustls_reader_args_t *args = bpf_map_lookup_elem(&rustls_reader_args, &id);
    const rust_protocol_config_t *config = rust_protocol_config(id);

    if (args && config && rust_process_instrumented(id)) {
        rustls_save_peeked_buffer(id, args, config);
    }

    bpf_map_delete_elem(&rustls_reader_args, &id);
    return 0;
}

// Feeds the consumed portion of the saved peeked slice to the generic TLS parser
// and advances the slice so partial consumes do not replay the same plaintext.
SEC("uprobe/rust:rustls_consume")
int GUARDED_PROG(obi_rustls_consume, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_task_key_t key = {.pid = obi_pid(id), .addr = PT_REGS_PARM1(ctx)};
    rustls_buffer_t *buffer = bpf_map_lookup_elem(&rustls_read_buffers, &key);

    if (!buffer) {
        if (rust_process_instrumented(id)) {
            bpf_dbg_printk("rustls consume buffer missing addr=%llx", key.addr);
        }
        return 0;
    }

    const ssl_pid_connection_info_t *connection = rustls_connection(id, buffer->common);
    if (!connection) {
        return 0;
    }

    const u64 data = buffer->data;
    const u32 amount = min((u64)PT_REGS_PARM2(ctx), min(buffer->len, (u64)__INT_MAX__));
    buffer->data += amount;
    buffer->len -= amount;
    bpf_dbg_printk("rustls consume common=%llx bytes=%u", buffer->common, amount);
    handle_buf_with_connection(ctx,
                               (pid_connection_info_t *)&connection->p_conn,
                               (void *)data,
                               amount,
                               WITH_SSL,
                               TCP_RECV,
                               connection->orig_dport,
                               0);
    return 0;
}

static __always_inline void rustls_read_entry(u64 id, u64 address, u64 data, u64 len) {
    const rust_protocol_config_t *config = rust_protocol_config(id);
    bpf_map_delete_elem(&rustls_read_args, &id);
    if (!config || !rustls_enabled(id)) {
        return;
    }

    const rust_task_key_t key = {.pid = obi_pid(id), .addr = address};
    bpf_map_delete_elem(&rustls_read_buffers, &key);
    const rustls_buffer_t args = {
        .common = key.addr - config->tls_plaintext, .data = data, .len = len};

    const ssl_pid_connection_info_t *connection = rustls_connection(id, args.common);
    if (connection) {
        bpf_dbg_printk("rustls read enter common=%llx len=%llu", args.common, args.len);
        finish_possible_delayed_tls_http_request((pid_connection_info_t *)&connection->p_conn);
        bpf_map_update_elem(&rustls_read_args, &id, &args, BPF_ANY);
    }
}

// Saves ChunkVecBuffer::read's destination before plaintext is copied into it.
// The return hook captures only the bytes actually read, covering the copying
// read path alongside the peek/consume path.
SEC("uprobe/rust:rustls_read")
int GUARDED_PROG(obi_rustls_read, struct pt_regs *, ctx) {
    rustls_read_entry(
        bpf_get_current_pid_tgid(), PT_REGS_PARM1(ctx), PT_REGS_PARM2(ctx), PT_REGS_PARM3(ctx));
    return 0;
}

// Covers binaries that inline ChunkVecBuffer::read through Reader::read. Resolves
// the Reader's plaintext buffer and saves its destination for the shared return hook.
SEC("uprobe/rust:rustls_reader_read")
int GUARDED_PROG(obi_rustls_reader_read, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_protocol_config_t *config = rust_protocol_config(id);
    u64 buffer = 0;
    if (config && bpf_probe_read_user(&buffer,
                                      sizeof(buffer),
                                      (void *)(PT_REGS_PARM1(ctx) + config->reader_buffer)) == 0) {
        rustls_read_entry(id, buffer, PT_REGS_PARM2(ctx), PT_REGS_PARM3(ctx));
    }
    return 0;
}

static __always_inline void
rustls_plain_entry(u64 id, u64 object, u64 data, u64 len, bool vectors) {
    const rust_protocol_config_t *config = rust_protocol_config(id);
    if (config && rustls_enabled(id)) {
        const rustls_buffer_t args = {
            .common = object + config->tls_common, .data = data, .len = len, .vectors = vectors};
        bpf_dbg_printk("rustls write enter common=%llx len=%llu vec=%u", args.common, len, vectors);
        bpf_map_update_elem(&rustls_plain_args, &id, &args, BPF_ANY);
    }
}

// Saves the scalar plaintext slice passed to PlaintextSink::write before encryption.
// The return hook limits capture to the bytes accepted by Rustls.
SEC("uprobe/rust:rustls_write")
int GUARDED_PROG(obi_rustls_write, struct pt_regs *, ctx) {
    rustls_plain_entry(bpf_get_current_pid_tgid(),
                       PT_REGS_PARM1(ctx),
                       PT_REGS_PARM2(ctx),
                       PT_REGS_PARM3(ctx),
                       false);
    return 0;
}

// Saves PlaintextSink::write_vectored's IoSlice array and count. The shared return
// hook gathers the accepted prefix using the generic tracer bounded iovec copy.
SEC("uprobe/rust:rustls_write_vectored")
int GUARDED_PROG(obi_rustls_write_vectored, struct pt_regs *, ctx) {
    rustls_plain_entry(bpf_get_current_pid_tgid(),
                       PT_REGS_PARM1(ctx),
                       PT_REGS_PARM2(ctx),
                       PT_REGS_PARM3(ctx),
                       true);
    return 0;
}

static __noinline u32 rustls_copy_vectors(u64 address, u64 count, u64 written) {
    unsigned char *data = iovec_memory();
    if (!data) {
        return 0;
    }

    iovec_iter_ctx vectors = {.iter_type = bpf_core_enum_value(enum iter_type, ITER_IOVEC),
                              .iov = (void *)address,
                              .nr_segs = count};

    return read_iovec_ctx_memory(&vectors, data, min(written, (u64)k_iovec_max_len), true);
}

static __always_inline void rustls_plain_return(void *ctx, const struct pt_regs *regs, bool read) {
    const u64 id = bpf_get_current_pid_tgid();
    void *map = read ? (void *)&rustls_read_args : (void *)&rustls_plain_args;
    const rustls_buffer_t *saved = bpf_map_lookup_elem(map, &id);
    if (!saved) {
        return;
    }

    const rustls_buffer_t args = *saved;
    bpf_map_delete_elem(map, &id);
    if (!rust_process_instrumented(id) || PT_REGS_RC(regs)) {
        bpf_dbg_printk("rustls IO skipped result=%llx", PT_REGS_RC(regs));
        return;
    }

    const ssl_pid_connection_info_t *connection = rustls_connection(id, args.common);
    if (!connection) {
        return;
    }

    u64 data = args.data;
    u32 amount = min(rust_return_word2(regs), min(args.len, (u64)__INT_MAX__));
    if (args.vectors) {
        data = (u64)iovec_memory();
        if (!data) {
            return;
        }
        amount = rustls_copy_vectors(args.data, args.len, rust_return_word2(regs));
    }

    bpf_dbg_printk("rustls plaintext common=%llx bytes=%u read=%u", args.common, amount, read);
    handle_buf_with_connection(ctx,
                               (pid_connection_info_t *)&connection->p_conn,
                               (void *)data,
                               amount,
                               WITH_SSL,
                               read ? TCP_RECV : TCP_SEND,
                               connection->orig_dport,
                               0);
}

// Shared scalar/vectored write return: submit only successfully accepted plaintext
// to the generic protocol parser as a TLS send and clear the saved call state.
SEC("uretprobe/rust:rustls_write")
int GUARDED_PROG(obi_rustls_write_ret, struct pt_regs *, ctx) {
    rustls_plain_return(ctx, ctx, false);
    return 0;
}

// Shared ChunkVecBuffer::read and Reader::read return: submit only successfully
// copied bytes as a TLS receive and clear the saved call state.
SEC("uretprobe/rust:rustls_read")
int GUARDED_PROG(obi_rustls_read_ret, struct pt_regs *, ctx) {
    rustls_plain_return(ctx, ctx, true);
    return 0;
}
