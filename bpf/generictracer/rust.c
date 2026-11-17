// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_tracing.h>

#include <common/rust_task.h>
#include <common/rust_abi.h>
#include <common/preempt_guard.h>
#include <pid/pid.h>
#include <shared/obi_ctx.h>

enum { k_rust_low_address_limit = 4096 };

static __always_inline void rust_refresh_thread_context(u64 id) {
    const tp_info_pid_t *context = rust_current_context(id);

    if (context && context->valid) {
        obi_ctx__set(id, &context->tp);
    } else {
        obi_ctx__del(id);
    }
}

// Enter a task while Tokio polls it, through either raw::poll or Harness::poll.
// The worker's task stack selects its parent context even across nested polls.
SEC("uprobe/rust:tokio_poll")
int GUARDED_PROG(obi_rust_task_poll, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    if (!rust_task_context_enabled(id) || !valid_pid(id)) {
        return 0;
    }

    rust_thread_state_t *thread = bpf_map_lookup_elem(&rust_threads, &id);
    if (!thread) {
        const rust_thread_state_t initial = {};
        bpf_map_update_elem(&rust_threads, &id, &initial, BPF_ANY);
        thread = bpf_map_lookup_elem(&rust_threads, &id);

        if (!thread) {
            bpf_dbg_printk("rust poll state unavailable");
            return 0;
        }
    }

    u32 depth = thread->depth;
    if (depth < k_rust_poll_depth) {
        bpf_clamp_umax(depth, k_rust_poll_depth - 1);
        thread->tasks[depth] = PT_REGS_PARM1(ctx);
    } else {
        bpf_dbg_printk("rust poll depth exceeded depth=%u", depth);
    }

    thread->depth++;
    bpf_dbg_printk(
        "rust poll task=%llx depth=%u ip=%llx", PT_REGS_PARM1(ctx), thread->depth, PT_REGS_IP(ctx));
    rust_refresh_thread_context(id);

    return 0;
}

// Leave the polled task and restore the enclosing task's context. At the outermost
// return, clear the worker spawn and HTTP/2 sender state before another task runs.
SEC("uretprobe/rust:tokio_poll")
int GUARDED_PROG(obi_rust_task_poll_ret, struct pt_regs *, ctx) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();
    rust_thread_state_t *thread = bpf_map_lookup_elem(&rust_threads, &id);
    if (!thread || !rust_task_context_enabled(id)) {
        return 0;
    }

    if (thread->depth) {
        thread->depth--;
        bpf_dbg_printk("rust poll return depth=%u", thread->depth);
    } else {
        bpf_dbg_printk("rust poll return without matching entry");
    }

    if (!thread->depth) {
        thread->spawn_depth = 0;
        bpf_map_delete_elem(&rust_h2_senders, &id);
    }

    rust_refresh_thread_context(id);
    return 0;
}

static __always_inline void rust_new_task(u64 id, u64 address) {
    const rust_task_key_t key = {.pid = obi_pid(id), .addr = address};
    if (!key.addr || !rust_task_context_enabled(id) || !valid_pid(id)) {
        return;
    }

    bpf_dbg_printk("rust task create task=%llx", key.addr);
    rust_copy_context(id, &rust_task_context, &key);
    bpf_map_delete_elem(&rust_io_connections, &key);
    bpf_map_delete_elem(&rust_h2_tasks, &key);
    bpf_map_delete_elem(&rust_http1_requests, &key);
}

// Snapshot the spawning task's parent when Cell::new or RawTask::new returns its
// allocation, before Tokio can publish the new task to another worker.
SEC("uretprobe/rust:tokio_new")
int GUARDED_PROG(obi_rust_task_new, struct pt_regs *, ctx) {
    rust_new_task(bpf_get_current_pid_tgid(), PT_REGS_RC(ctx));
    return 0;
}

// Copy the parent at owned-task binding or scheduler publication. These boundaries
// cover builds that inline task allocation, before the task can run elsewhere.
SEC("uprobe/rust:tokio_bind")
int GUARDED_PROG(obi_rust_task_bind, struct pt_regs *, ctx) {
    rust_new_task(bpf_get_current_pid_tgid(), PT_REGS_PARM2(ctx));
    return 0;
}

// Marks a spawn scope for the schedule fallback. Only tasks scheduled inside this
// scope inherit the caller's context, later wakes must keep their original parent.
SEC("uprobe/rust:tokio_spawn")
int GUARDED_PROG(obi_rust_task_spawn, struct pt_regs *, ctx) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();
    if (!rust_task_context_enabled(id) || !valid_pid(id)) {
        return 0;
    }

    rust_thread_state_t *thread = bpf_map_lookup_elem(&rust_threads, &id);
    if (!thread) {
        const rust_thread_state_t initial = {};
        bpf_map_update_elem(&rust_threads, &id, &initial, BPF_ANY);
        thread = bpf_map_lookup_elem(&rust_threads, &id);
    }

    if (thread) {
        thread->spawn_depth++;
        bpf_dbg_printk("rust spawn enter depth=%u", thread->spawn_depth);
    }
    return 0;
}

// Ends the spawn scope so unrelated task wakes on this worker cannot overwrite
// their saved parent with the context of the task that happens to wake them.
SEC("uretprobe/rust:tokio_spawn")
int GUARDED_PROG(obi_rust_task_spawn_ret, struct pt_regs *, ctx) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();
    rust_thread_state_t *thread = bpf_map_lookup_elem(&rust_threads, &id);

    if (thread && rust_task_context_enabled(id) && thread->spawn_depth) {
        thread->spawn_depth--;
        bpf_dbg_printk("rust spawn return depth=%u", thread->spawn_depth);
    }

    return 0;
}

// Inherits the parent at scheduling when allocation and binding were inlined.
// The spawn scope distinguishes a new task's publication from later wakes.
SEC("uprobe/rust:tokio_schedule")
int GUARDED_PROG(obi_rust_task_schedule, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_thread_state_t *thread = bpf_map_lookup_elem(&rust_threads, &id);

    // Publish the parent before scheduling when allocation/binding was inlined.
    // Wakes outside a spawn scope must preserve the task's existing parent.
    if (thread && rust_task_context_enabled(id) && thread->spawn_depth) {
        bpf_dbg_printk("rust spawn publish task=%llx", PT_REGS_PARM2(ctx));
        rust_new_task(id, PT_REGS_PARM2(ctx));
    }

    return 0;
}

// Drops task context, socket bindings, and request ownership before Tokio frees
// the task allocation, so reusing its address will not inherit stale state.
SEC("uprobe/rust:tokio_dealloc")
int GUARDED_PROG(obi_rust_task_dealloc, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_task_key_t key = {
        .pid = obi_pid(id),
        .addr = PT_REGS_PARM1(ctx),
    };

    if (rust_process_instrumented(id)) {
        bpf_dbg_printk("rust task dealloc task=%llx", key.addr);
        bpf_map_delete_elem(&rust_task_context, &key);
        bpf_map_delete_elem(&rust_io_connections, &key);
        bpf_map_delete_elem(&rust_h2_tasks, &key);
        bpf_map_delete_elem(&rust_http1_requests, &key);
    }

    return 0;
}

// Snapshots the sender's context under a queue slot before publishing its message.
// Hyper's Envelope is passed indirectly. The write closure takes its captured
// Envelope followed by the slot pointer and returns.
SEC("uprobe/rust:hyper_enqueue")
int GUARDED_PROG(obi_rust_hyper_enqueue, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_task_key_t key = {
        .pid = obi_pid(id),
        .addr = PT_REGS_PARM2(ctx),
    };

    if (!rust_process_instrumented(id) || !key.addr || !valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("rust enqueue slot=%llx", key.addr);
    rust_copy_context(id, &rust_channel_context, &key);
    return 0;
}

// Adopt and consume the slot's saved parent once Tokio has found a ready message,
// then refresh the receiving task's worker context for subsequent client I/O.
SEC("uprobe/rust:hyper_dequeue")
int GUARDED_PROG(obi_rust_hyper_dequeue, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    // The read closure runs only after the slot is ready. Its large return
    // value uses an extra first argument on amd64; arm64 uses x8 for sret.
    const rust_task_key_t key = {
        .pid = obi_pid(id),
#ifdef __TARGET_ARCH_x86
        .addr = PT_REGS_PARM2(ctx),
#else
        .addr = PT_REGS_PARM1(ctx),
#endif
    };

    if (!rust_process_instrumented(id) || !valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("rust dequeue slot=%llx", key.addr);
    rust_adopt_channel_context(id, &key);
    rust_refresh_thread_context(id);

    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, rust_task_key_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_hyper_receive_args SEC(".maps");

static __always_inline u64 rust_message_pointer(u64 address,
                                                const rust_protocol_config_t *config,
                                                bool receive) {
    const u32 tag_offset = receive ? config->message_rx_tag : config->message_tx_tag;
    const u32 some_offset = receive ? config->message_rx_some : config->message_tx_some;
    const u32 pointer_offset = receive ? config->message_rx_pointer : config->message_tx_pointer;
    if (!address) {
        bpf_dbg_printk("rust envelope address missing recv=%u", receive);
        return 0;
    }

    u64 tag = 0;
    const long tag_read_result =
        bpf_probe_read_user(&tag, sizeof(tag), (void *)(address + tag_offset));
    if (tag_read_result != 0) {
        bpf_dbg_printk("rust envelope tag unavailable value=%llx recv=%u", address, receive);
        return 0;
    }

    if (tag > 1) {
        bpf_dbg_printk("rust envelope tag invalid value=%llx tag=%llu", address, tag);
        return 0;
    }

    if (some_offset) {
        u64 some = 0;
        const long some_read_result =
            bpf_probe_read_user(&some, sizeof(some), (void *)(address + some_offset));
        if (some_read_result != 0) {
            bpf_dbg_printk("rust envelope option unavailable value=%llx", address);
            return 0;
        }

        if (some != 1) {
            bpf_dbg_printk("rust envelope option empty value=%llx tag=%llu", address, some);
            return 0;
        }
    }

    u64 pointer = 0;
    const long pointer_read_result =
        bpf_probe_read_user(&pointer, sizeof(pointer), (void *)(address + pointer_offset));
    if (pointer_read_result != 0) {
        bpf_dbg_printk("rust envelope pointer unavailable value=%llx recv=%u", address, receive);
        return 0;
    }

    return pointer;
}

// Snapshots the sender's context using the envelope's callback allocation as its
// identity. Tx::push and channel Tx::send cover inlined block write closures.
SEC("uprobe/rust:hyper_send")
int GUARDED_PROG(obi_rust_hyper_send, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_protocol_config_t *config = rust_protocol_config(id);
    if (!config || !(config->message & k_rust_message_callback) || !valid_pid(id)) {
        return 0;
    }

    const rust_task_key_t key = {.pid = obi_pid(id),
                                 .addr = rust_message_pointer(PT_REGS_PARM2(ctx), config, false)};

    if (rust_process_instrumented(id) && key.addr) {
        bpf_dbg_printk("rust send callback=%llx", key.addr);
        rust_copy_context(id, &rust_channel_context, &key);
    }

    return 0;
}

// Allocated HeaderMap entries identify a request across Hyper dispatch. Empty
// maps can have shared small dangling pointers, which cannot identify a request.
static __always_inline u64 rust_request_entries(u64 headers, const rust_protocol_config_t *config) {
    u64 entries = 0;
    const long read_result =
        bpf_probe_read_user(&entries, sizeof(entries), (void *)(headers + config->header_entries));
    if (read_result != 0) {
        bpf_dbg_printk("rust request entries unavailable headers=%llx", headers);
        return 0;
    }

    if (entries <= k_rust_low_address_limit) {
        bpf_dbg_printk("rust request entries unallocated pointer=%llx", entries);
        return 0;
    }

    return entries;
}

// Tracks Hyper dispatch by the request's HeaderMap allocation when lower queue
// hooks or callback layouts are unavailable. Its receiver uses the same identity.
SEC("uprobe/rust:hyper_request_send")
int GUARDED_PROG(obi_rust_hyper_request_send, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_protocol_config_t *config = rust_protocol_config(id);
    if (!config) {
        return 0;
    }

    if (!(config->message & k_rust_message_request)) {
        return 0;
    }

    if (!rust_process_instrumented(id) || !valid_pid(id)) {
        return 0;
    }

    const u64 request = rust_sret_arg2(ctx);
    const u64 entries = rust_request_entries(request + config->request_headers, config);
    if (!entries) {
        return 0;
    }

    bpf_dbg_printk("rust send request=%llx entries=%llx", request, entries);
    const rust_task_key_t key = {.pid = obi_pid(id), .addr = entries};
    rust_copy_context(id, &rust_channel_context, &key);

    return 0;
}

// Clears the driver's parent on an unsupported request queue. Keeping a previous
// request's context would incorrectly parent work from this untracked handoff.
SEC("uprobe/rust:hyper_clear")
int GUARDED_PROG(obi_rust_hyper_clear, struct pt_regs *, ctx) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();
    if (!rust_process_instrumented(id) || !valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("rust unsupported channel clearing task parent");
    const tp_info_pid_t empty = {};
    rust_set_context(id, &empty);
    rust_refresh_thread_context(id);

    return 0;
}

// Saves the hidden return storage for Hyper dispatch or Tokio channel receive.
// Their return hooks decode the delivered message to recover its saved parent.
SEC("uprobe/rust:hyper_receive")
int GUARDED_PROG(obi_rust_hyper_receive, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_protocol_config_t *config = rust_protocol_config(id);

    if (config && (config->message & (k_rust_message_callback | k_rust_message_request)) &&
        rust_process_instrumented(id) && valid_pid(id)) {
        const rust_task_key_t args = {.pid = obi_pid(id), .addr = rust_sret(ctx)};
        bpf_map_update_elem(&rust_hyper_receive_args, &id, &args, BPF_ANY);
    }
    return 0;
}

static __always_inline void
rust_receive_request_context(u64 id, u64 address, const rust_protocol_config_t *config) {
    u64 tag = 0;
    const long read_result =
        bpf_probe_read_user(&tag, sizeof(tag), (void *)(address + config->message_rx_tag));
    if (read_result != 0) {
        bpf_dbg_printk("rust receive request tag unavailable value=%llx", address);
        return;
    }

    if (tag > 1) {
        bpf_dbg_printk("rust receive request tag invalid value=%llx tag=%llu", address, tag);
        return;
    }

    const u64 entries = rust_request_entries(address + config->message_rx_headers, config);
    const rust_task_key_t key = {.pid = obi_pid(id), .addr = entries};
    bpf_dbg_printk("rust receive request entries=%llx", entries);
    // A missing identity must still clear the previous request's parent.
    rust_adopt_channel_context(id, &key);
    rust_refresh_thread_context(id);
}

// Restores the request's parent from the HeaderMap returned by Hyper dispatch.
// Missing ownership clears the driver's previous parent.
SEC("uretprobe/rust:hyper_request_receive")
int GUARDED_PROG(obi_rust_hyper_request_receive_ret, struct pt_regs *, ctx) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();
    const rust_protocol_config_t *config = rust_protocol_config(id);
    const rust_task_key_t *saved = bpf_map_lookup_elem(&rust_hyper_receive_args, &id);

    if (saved && config && rust_process_instrumented(id)) {
        rust_receive_request_context(id, saved->addr, config);
    }

    bpf_map_delete_elem(&rust_hyper_receive_args, &id);
    return 0;
}

// Recovers the callback identity from a completed channel receive and adopt its
// sender's context. Discards saved return storage even when no message is available.
SEC("uretprobe/rust:hyper_receive")
int GUARDED_PROG(obi_rust_hyper_receive_ret, struct pt_regs *, ctx) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();
    const rust_protocol_config_t *config = rust_protocol_config(id);
    const rust_task_key_t *args = bpf_map_lookup_elem(&rust_hyper_receive_args, &id);
    rust_task_key_t key = {.pid = obi_pid(id)};

    if (args && config && rust_process_instrumented(id)) {
        key.addr = rust_message_pointer(args->addr, config, true);
    }

    bpf_map_delete_elem(&rust_hyper_receive_args, &id);

    if (rust_process_instrumented(id) && key.addr) {
        rust_adopt_channel_context(id, &key);
        rust_refresh_thread_context(id);
    }

    return 0;
}

typedef struct rust_list_args {
    u64 receiver;
    u64 index;
} rust_list_args_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, rust_list_args_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} rust_list_args SEC(".maps");

// Remembers the reserved slot index before Tx::find_block returns its block.
// Together they identify a message when the outer Tx::push hook was inlined.
SEC("uprobe/rust:hyper_find_block")
int GUARDED_PROG(obi_rust_hyper_find_block, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();

    if (rust_process_instrumented(id) && valid_pid(id)) {
        const rust_list_args_t args = {.index = PT_REGS_PARM2(ctx)};
        bpf_map_update_elem(&rust_list_args, &id, &args, BPF_ANY);
    }

    return 0;
}

// Snapshots the sender's context under the returned block and reserved slot before
// message publication, providing the queue identity that Rx::pop later reconstructs.
SEC("uretprobe/rust:hyper_find_block")
int GUARDED_PROG(obi_rust_hyper_find_block_ret, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_list_args_t *args = bpf_map_lookup_elem(&rust_list_args, &id);
    const rust_protocol_config_t *config = rust_protocol_config(id);

    if (args && config && (config->message & k_rust_message_list) &&
        rust_process_instrumented(id) && PT_REGS_RC(ctx)) {
        // The block address and slot form an identity before publication.
        const rust_task_key_t key = {.pid = obi_pid(id),
                                     .addr = PT_REGS_RC(ctx) + (args->index & config->slot_mask)};

        bpf_dbg_printk("rust send block=%llx index=%llu", PT_REGS_RC(ctx), args->index);

        rust_copy_context(id, &rust_channel_context, &key);
    }

    bpf_map_delete_elem(&rust_list_args, &id);
    return 0;
}

// Saves the receiver and its current slot index before Rx::pop attempts a receive.
// The return hook checks that the index advanced before adopting any parent.
SEC("uprobe/rust:hyper_pop")
int GUARDED_PROG(obi_rust_hyper_pop, struct pt_regs *, ctx) {
    const u64 id = bpf_get_current_pid_tgid();
    const rust_protocol_config_t *config = rust_protocol_config(id);
    if (!config) {
        return 0;
    }

    if (!(config->message & k_rust_message_list)) {
        return 0;
    }

    if (!rust_process_instrumented(id) || !valid_pid(id)) {
        return 0;
    }

    rust_list_args_t args = {.receiver = rust_sret_arg1(ctx)};
    const long read_result = bpf_probe_read_user(
        &args.index, sizeof(args.index), (void *)(args.receiver + config->list_index));
    if (read_result != 0) {
        bpf_dbg_printk("rust pop index unavailable receiver=%llx", args.receiver);
        return 0;
    }

    bpf_map_update_elem(&rust_list_args, &id, &args, BPF_ANY);
    return 0;
}

static __always_inline void rust_receive_list_context(u64 id,
                                                      const rust_list_args_t *args,
                                                      const rust_protocol_config_t *config) {
    u64 index = 0;
    const long index_read_result =
        bpf_probe_read_user(&index, sizeof(index), (void *)(args->receiver + config->list_index));
    if (index_read_result != 0) {
        bpf_dbg_printk("rust pop return index unavailable receiver=%llx", args->receiver);
        return;
    }

    if (index != args->index + 1) {
        bpf_dbg_printk("rust pop did not consume slot before=%llu after=%llu", args->index, index);
        return;
    }

    u64 head = 0;
    const long head_read_result =
        bpf_probe_read_user(&head, sizeof(head), (void *)(args->receiver + config->list_head));
    if (head_read_result != 0) {
        bpf_dbg_printk("rust pop head unavailable receiver=%llx", args->receiver);
        return;
    }

    if (!head) {
        bpf_dbg_printk("rust pop head missing receiver=%llx", args->receiver);
        return;
    }

    const rust_task_key_t key = {.pid = obi_pid(id),
                                 .addr = head + (args->index & config->slot_mask)};
    bpf_dbg_printk("rust receive block=%llx index=%llu", head, args->index);
    rust_adopt_channel_context(id, &key);
    rust_refresh_thread_context(id);
}

// Reconstructs the consumed block/slot identity after Rx::pop and restore its
// sender's context. Empty or pending polls only discard their saved call state.
SEC("uretprobe/rust:hyper_pop")
int GUARDED_PROG(obi_rust_hyper_pop_ret, struct pt_regs *, ctx) {
    (void)ctx;
    const u64 id = bpf_get_current_pid_tgid();
    const rust_list_args_t *args = bpf_map_lookup_elem(&rust_list_args, &id);
    const rust_protocol_config_t *config = rust_protocol_config(id);

    if (args && config && rust_process_instrumented(id)) {
        rust_receive_list_context(id, args, config);
    }

    bpf_map_delete_elem(&rust_list_args, &id);
    return 0;
}
