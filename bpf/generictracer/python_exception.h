// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/exception_emit.h>
#include <common/trace_parent.h>
#include <common/tp_info.h>
#include <common/pin_internal.h>
#include <common/python_exception.h>
#include <common/python_task.h>
#include <common/scratch_mem.h>

#include <maps/python_thread_state.h>

#include <pid/maps/map_sizing.h>
#include <pid/pid_helpers.h>

enum {
    k_python_exception_pending_max = 1024,
    // Frames walked per raise, including C-stack shim frames that are skipped.
    k_python_exception_max_walk = 32,
    // Traceback entries walked; the innermost frames are kept.
    k_python_traceback_max_walk = 128,
    // Exception states searched for the exception being handled.
    k_python_exc_info_max_walk = 16,
    // Covers the frame fields read on every supported version, PyFrameObject.f_lasti on 3.9.
    k_python_frame_buf_size = 112,
    k_python_frame_owner_none = 0xff,
};

// ABI-stable object offsets on 64-bit CPython 3.9-3.14.
enum {
    k_python_object_refcnt = 0,
    k_python_object_type = 8,
    k_python_var_object_size = 16,
    k_python_exception_args = 24,
    k_python_unicode_length = 16,
    k_python_unicode_state = 32,
    k_python_traceback_next = 16,
    k_python_traceback_frame = 24,
    k_python_traceback_lasti = 32,
};

// PEP 393 str state bits.
enum {
    k_python_unicode_1byte_kind = 1,
    k_python_unicode_2byte_kind = 2,
    k_python_unicode_4byte_kind = 4,
    k_python_unicode_kind_shift = 2,
    k_python_unicode_kind_mask = 7,
    k_python_unicode_compact = 1 << 5,
    k_python_unicode_ascii = 1 << 6,
};

// CPython 3.14 tags _PyStackRef pointers in their low bit.
static const u64 k_python_stackref_tag = 1;

// Per-process CPython layout, written by user space before the probe attaches.
typedef struct python_exception_proc {
    u64 main_interp;
    u64 code_type;
    u64 unicode_type;
    u64 tuple_type;
    u64 stop_iteration;
    u64 stop_async_iteration;
    u64 generator_exit;
    python_exception_layout_t layout;
    u16 code_adaptive;
    u8 tstate_interp;
    // _PyCFrame* on 3.11 and 3.12, the current frame on 3.13+
    u8 tstate_frame;
    u8 cframe_current_frame;
    u8 frame_is_cframe;
    u8 frame_code;
    u8 frame_previous;
    u8 frame_instr;
    u8 frame_owner;
    // owner value of C-stack shim frames, k_python_frame_owner_none before 3.12
    u8 frame_owner_cstack;
    u8 tuple_items;
    u8 exception_traceback;
    // bytes of each frame to read, at most k_python_frame_buf_size
    u8 frame_read_size;
    // 3.9 and 3.10 frames are PyFrameObjects with an int f_lasti, in bytes on 3.9
    u8 frame_lasti_int;
    u8 frame_lasti_bytes;
    // PyFrameObject.f_frame on 3.11+, 0 when frame objects are the frames
    u8 frame_object_frame;
    // PyThreadState.exc_info and the _PyErr_StackItem fields it points to
    u8 tstate_exc_info;
    u8 err_item_value;
    u8 err_item_previous;
    u8 _pad[4];
} python_exception_proc_t;

typedef struct python_exception_key {
    u32 pid;
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
} python_exception_key_t;

// One raise inside a server request.
typedef struct python_exception_candidate {
    u64 capture_ns;
    // the raised instance; 0 when C code raised a str or tuple
    u64 exception;
    u8 owner;
    // seen outside the frame that raised it
    u8 propagated;
    u8 _pad[6];
    python_exception_payload_t payload;
} python_exception_candidate_t;

// The raises of one server request that a 5xx can report: the latest, and the
// newest earlier one that propagated.
typedef struct python_exception_pending {
    python_exception_candidate_t latest;
    python_exception_candidate_t kept;
} python_exception_pending_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // host PID
    __type(value, python_exception_proc_t);
    __uint(max_entries, k_max_concurrent_pids);
    __uint(pinning, OBI_PIN_INTERNAL);
} python_exception_procs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, python_exception_key_t);
    __type(value, python_exception_pending_t);
    __uint(max_entries, k_python_exception_pending_max);
    __uint(pinning, OBI_PIN_INTERNAL);
} python_exception_pending SEC(".maps");

SCRATCH_MEM(python_exception_pending_t)
SCRATCH_MEM_SIZED(python_frame_buf, k_python_frame_buf_size)
SCRATCH_MEM_SIZED(python_traceback_ring,
                  sizeof(python_exception_frame_t) * k_python_exception_max_frames)

static __always_inline u64 python_read_ptr(const u64 address) {
    u64 value = 0;
    bpf_probe_read_user(&value, sizeof(value), (const void *)address);
    return value;
}

static __always_inline u64 python_object_type(const u64 object) {
    return object ? python_read_ptr(object + k_python_object_type) : 0;
}

// The request served by this thread while its response is pending.
static __always_inline enum exception_owner python_exception_thread_owner(const u32 host_pid,
                                                                          tp_info_t *tp) {
    trace_key_t key = {};
    trace_key_from_pid_tid(&key);
    const tp_info_pid_t *server = bpf_map_lookup_elem(&server_traces, &key);
    if (!server || !server->valid || server->response_sent || server->pid != host_pid) {
        return k_exception_owner_none;
    }
    *tp = server->tp;
    return k_exception_owner_thread;
}

// The asyncio task running on this thread owns the raise, through the request
// it serves; a stale task owns nothing. A thread with no task, or whose context
// no task owns, falls back to the request it is serving.
static __always_inline enum exception_owner python_exception_owner(const u64 id, tp_info_t *tp) {
    const python_thread_state_t *thread = bpf_map_lookup_elem(&python_thread_state, &id);

    python_task_ref_t task = {};
    python_task_resolution_t resolution = PYTHON_TASK_NOT_FOUND;
    if (thread && thread->current_task) {
        if (!resolve_python_task_ref(id, thread->current_task, &task)) {
            return k_exception_owner_none;
        }
        resolution = PYTHON_TASK_RESOLVED;
    } else if (thread && thread->current_context) {
        resolution = resolve_python_task_from_context(id, thread->current_context, &task);
    }

    if (resolution != PYTHON_TASK_RESOLVED) {
        return python_exception_thread_owner(pid_from_pid_tgid(id), tp);
    }

    const tp_info_pid_t *server = find_python_owning_server_trace(id, task, NULL);
    if (!server || !server->valid) {
        return k_exception_owner_none;
    }

    *tp = server->tp;
    return k_exception_owner_ongoing;
}

static __always_inline bool python_exception_control_flow(const python_exception_proc_t *proc,
                                                          const u64 type) {
    return type == proc->stop_iteration || type == proc->stop_async_iteration ||
           type == proc->generator_exit;
}

static __always_inline bool python_exception_instance(const python_exception_proc_t *proc,
                                                      const u64 value_type) {
    return value_type && value_type != proc->unicode_type && value_type != proc->tuple_type;
}

// `raise err` of an instance that already propagated keeps the first capture.
// A traceback tells the re-raise from a new instance at a recycled address.
static __always_inline bool python_exception_reraised(const python_exception_proc_t *proc,
                                                      const python_exception_candidate_t *latest,
                                                      const u64 value,
                                                      const u64 value_type) {
    if (!python_exception_instance(proc, value_type) || latest->exception != value) {
        return false;
    }

    return python_read_ptr(value + proc->exception_traceback) != 0;
}

// Whether a live exception left the frame that raised it: its traceback gains
// an entry for each frame it passes through. A freed or reused object fails.
static __always_inline bool
python_exception_propagated(const python_exception_proc_t *proc, const u64 value, const u64 type) {
    if ((s64)python_read_ptr(value + k_python_object_refcnt) <= 0 ||
        python_object_type(value) != type) {
        return false;
    }

    const u64 traceback = python_read_ptr(value + proc->exception_traceback);
    return traceback && python_read_ptr(traceback + k_python_traceback_next);
}

// Checks whether a propagated candidate is being handled on this thread.
static __always_inline bool python_exception_handled(const python_exception_proc_t *proc,
                                                     const u64 tstate,
                                                     const python_exception_candidate_t *candidate,
                                                     const u64 kept) {
    u64 item = python_read_ptr(tstate + proc->tstate_exc_info);
    for (u32 i = 0; i < k_python_exc_info_max_walk && item; i++) {
        const u64 handled = python_read_ptr(item + proc->err_item_value);
        item = python_read_ptr(item + proc->err_item_previous);
        if (!handled) {
            continue;
        }

        // Candidates captured as a str or tuple match by type, excluding the saved exception.
        const bool same = candidate->exception ? handled == candidate->exception
                                               : handled != kept && python_object_type(handled) ==
                                                                        candidate->payload.type;
        if (same) {
            return python_exception_propagated(proc, handled, candidate->payload.type);
        }
    }

    return false;
}

static __always_inline void python_exception_copy(python_exception_candidate_t *dst,
                                                  const python_exception_candidate_t *src) {
    bpf_probe_read_kernel(dst, sizeof(*dst), src);
}

// Before a new raise replaces the latest candidate, keeps it if it propagated.
static __always_inline void python_exception_keep(const python_exception_proc_t *proc,
                                                  const u64 tstate,
                                                  python_exception_pending_t *pending) {
    python_exception_candidate_t *latest = &pending->latest;
    if (!latest->capture_ns) {
        return;
    }

    if (!latest->propagated) {
        latest->propagated =
            python_exception_handled(proc, tstate, latest, pending->kept.exception) ||
            (latest->exception &&
             python_exception_propagated(proc, latest->exception, latest->payload.type));
    }

    if (latest->propagated) {
        python_exception_copy(&pending->kept, latest);
    }
}

// The message is `value` when a str was raised, else the instance's args[0] if it is a str.
static __always_inline u64 python_exception_text(const python_exception_proc_t *proc,
                                                 const u64 value,
                                                 const u64 value_type) {
    if (!value_type) {
        return 0;
    }
    if (value_type == proc->unicode_type) {
        return value;
    }

    u64 args = value;
    if (value_type != proc->tuple_type) {
        args = python_read_ptr(value + k_python_exception_args);
        if (python_object_type(args) != proc->tuple_type) {
            return 0;
        }
    }

    if ((s64)python_read_ptr(args + k_python_var_object_size) < 1) {
        return 0;
    }

    const u64 first = python_read_ptr(args + proc->tuple_items);
    return python_object_type(first) == proc->unicode_type ? first : 0;
}

static __always_inline void python_exception_message(const python_exception_proc_t *proc,
                                                     const u64 value,
                                                     const u64 value_type,
                                                     python_exception_payload_t *payload) {
    payload->message_len = 0;
    payload->message_kind = 0;
    __builtin_memset(payload->message, 0, sizeof(payload->message));

    const u64 text = python_exception_text(proc, value, value_type);
    if (!text) {
        return;
    }

    u32 state = 0;
    bpf_probe_read_user(&state, sizeof(state), (const void *)(text + k_python_unicode_state));
    const u8 kind = (state >> k_python_unicode_kind_shift) & k_python_unicode_kind_mask;
    // Non-compact strings keep their data out of line; exception messages are compact.
    if (!(state & k_python_unicode_compact) ||
        (kind != k_python_unicode_1byte_kind && kind != k_python_unicode_2byte_kind &&
         kind != k_python_unicode_4byte_kind)) {
        return;
    }

    const u64 length = python_read_ptr(text + k_python_unicode_length);
    u64 size = length * kind;
    if (size > sizeof(payload->message)) {
        size = sizeof(payload->message) / kind * kind;
        payload->flags |= k_python_exception_message_truncated;
    }
    bpf_clamp_umax(size, sizeof(payload->message));

    const u8 data_offset = (state & k_python_unicode_ascii) ? proc->layout.unicode_ascii_data
                                                            : proc->layout.unicode_compact_data;
    if (size && bpf_probe_read_user(payload->message, size, (const void *)(text + data_offset))) {
        return;
    }

    payload->message_len = size;
    payload->message_kind = kind;
}

static __always_inline u64 python_exception_first_frame(const python_exception_proc_t *proc,
                                                        const u64 tstate) {
    const u64 frame = python_read_ptr(tstate + proc->tstate_frame);
    if (!proc->frame_is_cframe || !frame) {
        return frame;
    }

    return python_read_ptr(frame + proc->cframe_current_frame);
}

static __always_inline u64 python_frame_field(const unsigned char *buf, u32 offset) {
    bpf_clamp_umax(offset, k_python_frame_buf_size - sizeof(u64));
    return *(const u64 *)(buf + offset);
}

// The executing instruction as code units into the bytecode.
static __always_inline u32 python_frame_instr(const python_exception_proc_t *proc,
                                              const unsigned char *buf,
                                              const u64 code) {
    if (proc->frame_lasti_int) {
        const s32 lasti = (s32)python_frame_field(buf, proc->frame_instr);
        if (lasti <= 0) {
            return 0;
        }
        return proc->frame_lasti_bytes ? (u32)lasti >> 1 : (u32)lasti;
    }

    const s64 units =
        ((s64)python_frame_field(buf, proc->frame_instr) - (s64)(code + proc->code_adaptive)) >> 1;
    return units > 0 ? (u32)units : 0;
}

static __always_inline bool python_is_code(const python_exception_proc_t *proc, const u64 code) {
    return python_object_type(code) == proc->code_type;
}

// Walks active Python frames, skipping C-stack shims and non-code objects.
static __always_inline void python_exception_walk(const python_exception_proc_t *proc,
                                                  const u64 tstate,
                                                  python_exception_payload_t *payload) {
    unsigned char *buf = python_frame_buf_mem();
    if (!buf) {
        return;
    }

    u32 read_size = proc->frame_read_size;
    bpf_clamp_umax(read_size, k_python_frame_buf_size);
    u32 owner_offset = proc->frame_owner;
    bpf_clamp_umax(owner_offset, k_python_frame_buf_size - 1);

    u64 frame = python_exception_first_frame(proc, tstate);
    for (u32 i = 0; i < k_python_exception_max_walk && frame; i++) {
        if (bpf_probe_read_user(buf, read_size, (const void *)frame)) {
            return;
        }

        const u64 code = python_frame_field(buf, proc->frame_code) & ~k_python_stackref_tag;
        const bool shim = proc->frame_owner_cstack != k_python_frame_owner_none &&
                          buf[owner_offset] == proc->frame_owner_cstack;
        const u32 instr = python_frame_instr(proc, buf, code);
        frame = python_frame_field(buf, proc->frame_previous);

        if (shim || !python_is_code(proc, code)) {
            continue;
        }

        const u8 n = payload->frame_count;
        if (n >= k_python_exception_max_frames) {
            payload->flags |= k_python_exception_truncated;
            return;
        }

        payload->frames[n].code = code;
        payload->frames[n].instr = instr;
        payload->frames[n]._pad = 0;
        payload->frame_count = n + 1;
    }

    if (frame) {
        payload->flags |= k_python_exception_truncated;
    }
}

// The code object a PyFrameObject runs, through its interpreter frame on 3.11+.
static __always_inline u64 python_frame_object_code(const python_exception_proc_t *proc,
                                                    const u64 frame_object) {
    u64 frame = frame_object;
    if (proc->frame_object_frame) {
        frame = python_read_ptr(frame_object + proc->frame_object_frame);
    }

    return python_read_ptr(frame + proc->frame_code) & ~k_python_stackref_tag;
}

// Walks a traceback, outermost entry first, keeping its last
// k_python_exception_max_frames entries in a ring, and writes them to an empty
// payload innermost first.
static __always_inline void python_traceback_walk(const python_exception_proc_t *proc,
                                                  u64 traceback,
                                                  python_exception_payload_t *payload) {
    python_exception_frame_t *ring = python_traceback_ring_mem();
    if (!ring) {
        return;
    }

    // The entry count lives in the payload rather than a register, so paths
    // that skip an entry do not multiply the verifier's states.
    payload->frame_count = 0;
    for (u32 i = 0; i < k_python_traceback_max_walk && traceback; i++) {
        const u64 code =
            python_frame_object_code(proc, python_read_ptr(traceback + k_python_traceback_frame));
        s32 lasti = 0;
        bpf_probe_read_user(
            &lasti, sizeof(lasti), (const void *)(traceback + k_python_traceback_lasti));
        traceback = python_read_ptr(traceback + k_python_traceback_next);

        if (!python_is_code(proc, code)) {
            continue;
        }

        const u8 seen = payload->frame_count;
        u32 slot = seen % k_python_exception_max_frames;
        bpf_clamp_umax(slot, k_python_exception_max_frames - 1);
        // tb_lasti counts bytes on every version
        ring[slot].code = code;
        ring[slot].instr = lasti > 0 ? (u32)lasti >> 1 : 0;
        ring[slot]._pad = 0;
        payload->frame_count = seen + 1;
    }

    const u32 total = payload->frame_count;
    if (traceback || total > k_python_exception_max_frames) {
        payload->flags |= k_python_exception_truncated;
    }

    const u32 count = total < k_python_exception_max_frames ? total : k_python_exception_max_frames;
    payload->frame_count = 0;
    for (u32 n = 0; n < count && n < k_python_exception_max_frames; n++) {
        u32 slot = (total - 1 - n) % k_python_exception_max_frames;
        bpf_clamp_umax(slot, k_python_exception_max_frames - 1);
        payload->frames[n] = ring[slot];
        payload->frame_count = n + 1;
    }
}

// Records a raise. An instance raised again after propagating, as when a
// thread's exception is re-raised on the event loop, takes its frames from its
// traceback: the live stack is the re-raising thread's.
static __always_inline void python_exception_capture(const python_exception_proc_t *proc,
                                                     const u64 tstate,
                                                     const u64 type,
                                                     const u64 value,
                                                     const u64 value_type,
                                                     python_exception_candidate_t *candidate) {
    const bool instance = python_exception_instance(proc, value_type);
    candidate->capture_ns = bpf_ktime_get_ns();
    candidate->exception = instance ? value : 0;
    candidate->propagated = 0;

    python_exception_payload_t *payload = &candidate->payload;
    payload->type = type;
    payload->flags = 0;
    __builtin_memset(payload->_pad, 0, sizeof(payload->_pad));
    payload->layout = proc->layout;
    python_exception_message(proc, value, value_type, payload);
    payload->frame_count = 0;

    const u64 traceback = instance ? python_read_ptr(value + proc->exception_traceback) : 0;
    if (traceback) {
        python_traceback_walk(proc, traceback, payload);
    } else {
        python_exception_walk(proc, tstate, payload);
    }
}

// The request's candidates, updated in place; a request's first raise creates
// them empty.
static __always_inline python_exception_pending_t *
python_exception_pending_slot(const python_exception_key_t *key) {
    python_exception_pending_t *pending = bpf_map_lookup_elem(&python_exception_pending, key);
    if (pending) {
        return pending;
    }

    python_exception_pending_t *empty = python_exception_pending_t_mem();
    if (!empty) {
        return NULL;
    }
    empty->latest.capture_ns = 0;
    empty->latest.exception = 0;
    empty->kept.capture_ns = 0;
    empty->kept.exception = 0;
    bpf_map_update_elem(&python_exception_pending, key, empty, BPF_NOEXIST);
    return bpf_map_lookup_elem(&python_exception_pending, key);
}

static __always_inline u32 python_exception_payload_len(const python_exception_payload_t *payload) {
    u8 frames = payload->frame_count;
    bpf_clamp_umax(frames, k_python_exception_max_frames);
    return offsetof(python_exception_payload_t, frames) + frames * sizeof(python_exception_frame_t);
}

// Selects the latest propagated exception, falling back to the saved candidate.
static __always_inline const python_exception_candidate_t *
python_exception_choose(const python_exception_proc_t *proc,
                        const python_exception_pending_t *pending) {
    const python_exception_candidate_t *latest = &pending->latest;
    const python_exception_candidate_t *kept = &pending->kept;
    if (latest->exception &&
        (latest->propagated ||
         python_exception_propagated(proc, latest->exception, latest->payload.type))) {
        return latest;
    }
    return kept->capture_ns ? kept : NULL;
}

// Sends the exception of the server request that owns `tp`, if it was raised
// after the request started.
static __always_inline void
python_exception_emit(const u32 host_pid, const tp_info_t *tp, const u64 request_start_ns) {
    python_exception_key_t key = {.pid = host_pid};
    __builtin_memcpy(key.span_id, tp->span_id, sizeof(key.span_id));

    const python_exception_pending_t *pending =
        bpf_map_lookup_elem(&python_exception_pending, &key);
    if (!pending) {
        return;
    }

    const python_exception_proc_t *proc = bpf_map_lookup_elem(&python_exception_procs, &host_pid);
    const python_exception_candidate_t *candidate =
        proc ? python_exception_choose(proc, pending) : NULL;
    if (!candidate || candidate->capture_ns < request_start_ns) {
        bpf_map_delete_elem(&python_exception_pending, &key);
        return;
    }

    exception_record_t *record = exception_record_start();
    if (!record) {
        bpf_map_delete_elem(&python_exception_pending, &key);
        return;
    }

    record->hdr.capture_ns = candidate->capture_ns;
    record->hdr.tp = *tp;
    task_pid(&record->hdr.pid);
    record->hdr.runtime = k_exception_runtime_python;
    record->hdr.owner = candidate->owner;
    record->hdr.payload_len = python_exception_payload_len(&candidate->payload);
    __builtin_memcpy(record->payload, &candidate->payload, sizeof(candidate->payload));

    exception_record_submit(record);
    bpf_map_delete_elem(&python_exception_pending, &key);
}
