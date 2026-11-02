// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/common.h>
#include <common/exception_emit.h>
#include <common/preempt_guard.h>

#include <gotracer/go_common.h>

#include <gotracer/maps/errors.h>
#include <gotracer/maps/nethttp.h>

#include <gotracer/types/errors.h>
#include <gotracer/types/nethttp.h>

#include <pid/pid_helpers.h>

// Returns the capture flags of the current process, or 0 when it does not
// capture exceptions.
static __always_inline u8 go_exception_pid_flags(void) {
    if (!g_exceptions_enabled) {
        return 0;
    }

    const u32 host_pid = bpf_get_current_pid_tgid() >> 32;
    const u8 *flags = bpf_map_lookup_elem(&go_exception_pids, &host_pid);
    if (!flags || !(*flags & k_go_exception_pid_enabled)) {
        return 0;
    }
    return *flags;
}

// The request that this goroutine is serving. Spawn ancestry is not ownership:
// a long-lived child goroutine can do work for other requests.
static __always_inline server_http_func_invocation_t *
find_active_http_server_request(const go_addr_key_t *g_key) {
    server_http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_server_requests, g_key);
    if (!invocation || !invocation->start_monotime_ns) {
        return NULL;
    }
    return invocation;
}

static __always_inline enum exception_owner
go_http_exception_owner(const go_addr_key_t *g_key, const u8 kind, tp_info_t *tp) {
    server_http_func_invocation_t *invocation = find_active_http_server_request(g_key);
    if (!invocation) {
        return k_exception_owner_none;
    }

    if (kind == k_go_exception_panic) {
        invocation->panicked = true;
    }
    tp_clone(tp, &invocation->tp);
    return k_exception_owner_ongoing;
}

static __always_inline void go_exception_read_message(go_exception_payload_t *payload,
                                                      const go_string_t *message) {
    if (!message->str || message->len <= 0) {
        return;
    }

    u64 len = (u64)message->len;
    bpf_clamp_umax(len, sizeof(payload->message));
    if (bpf_probe_read_user(payload->message, len, message->str) == 0) {
        payload->message_len = len;
        payload->message_truncated = (u64)message->len > sizeof(payload->message);
    }
}

// The probes run before the callee sets up its frame, or after it tears it
// down, so the frame pointer walk misses the immediate caller: its return
// address is at the stack top (x86) or in the link register (arm64).
static __always_inline void go_exception_read_stack(struct pt_regs *ctx,
                                                    go_exception_payload_t *payload) {
    const long bytes = bpf_get_stack(ctx, payload->pcs, sizeof(payload->pcs), BPF_F_USER_STACK);
    u16 frames = bytes > 0 ? bytes / sizeof(payload->pcs[0]) : 0;

    u64 caller_pc = 0;
#ifdef __TARGET_ARCH_x86
    bpf_probe_read_user(&caller_pc, sizeof(caller_pc), (const void *)PT_REGS_SP(ctx));
#elif defined(__TARGET_ARCH_arm64)
    caller_pc = PT_REGS_RET(ctx);
#endif
    if (caller_pc) {
        // Recover the caller missed by the frame walk, even if it returned no frames.
        payload->pcs[0] = caller_pc;
        if (!frames) {
            frames = 1;
        }
    }
    payload->frames = frames;
}

static __always_inline int
go_exception_emit(struct pt_regs *ctx, const u8 kind, const go_string_t *message) {
    const u64 capture_ns = bpf_ktime_get_ns();

    exception_record_t *record = exception_record_start();
    if (!record) {
        return 0;
    }

    go_exception_payload_t *payload = (go_exception_payload_t *)record->payload;
    __builtin_memset(payload, 0, sizeof(*payload));
    payload->kind = kind;
    go_exception_read_message(payload, message);
    go_exception_read_stack(ctx, payload);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, GOROUTINE_PTR(ctx));

    exception_event_header_t *hdr = &record->hdr;
    hdr->capture_ns = capture_ns;
    task_pid(&hdr->pid);
    hdr->runtime = k_exception_runtime_go;
    hdr->owner = go_http_exception_owner(&g_key, kind, &hdr->tp);
    hdr->payload_len = sizeof(*payload);

    exception_record_submit(record);
    return 0;
}

// func fmt.errorf(format string, a ...any) error (Go 1.26+), or
// func fmt.Errorf(format string, a ...any) error before it
SEC("uprobe/fmt_errorf_ret")
int GUARDED_PROG(obi_uprobe_fmt_errorf_ret, struct pt_regs *, ctx) {
    // fmt.errorf returns nil when no formatting is needed
    const void *itab = GO_PARAM1(ctx);
    const void *data = GO_PARAM2(ctx);
    if (!itab || !data) {
        return 0;
    }

    const u8 flags = go_exception_pid_flags();
    if (!(flags & k_go_exception_pid_formatted_errors)) {
        return 0;
    }

    // every error type fmt returns starts with its message string
    go_string_t message = {};
    if (bpf_probe_read_user(&message, sizeof(message), data)) {
        return 0;
    }
    return go_exception_emit(ctx, k_go_exception_formatted_error, &message);
}

// Leading fields of the 64-bit internal/abi.Type
typedef struct go_abi_type {
    u64 size;
    u64 ptr_bytes;
    u32 hash;
    u8 tflag;
    u8 align;
    u8 field_align;
    u8 kind;
    u64 equal;
    u64 gc_data;
    s32 str;
    s32 ptr_to_this;
} go_abi_type_t;

enum {
    k_go_tflag_uncommon = 1,
    k_go_kind_string = 24,
    k_go_kind_mask = 31,
    // abi.UncommonType.Mcount follows its PkgPath name offset
    k_go_uncommon_mcount_off = sizeof(go_abi_type_t) + sizeof(u32),
};

// A panic value is read as the message only when it is a string without
// methods: other values need their String or Error method to be rendered.
static __always_inline void
go_panic_message(const void *type_addr, const void *value_addr, go_string_t *message) {
    // Read Go's type metadata to verify value_addr holds a string descriptor.
    go_abi_type_t type = {};
    if (!type_addr || !value_addr || bpf_probe_read_user(&type, sizeof(type), type_addr) ||
        (type.kind & k_go_kind_mask) != k_go_kind_string || type.size != sizeof(go_string_t)) {
        return;
    }

    if (type.tflag & k_go_tflag_uncommon) {
        u16 methods = 0;
        if (bpf_probe_read_user(&methods,
                                sizeof(methods),
                                (const unsigned char *)type_addr + k_go_uncommon_mcount_off) ||
            methods) {
            return;
        }
    }

    bpf_probe_read_user(message, sizeof(*message), value_addr);
}

// func runtime.gopanic(e any)
SEC("uprobe/runtime_gopanic")
int GUARDED_PROG(obi_uprobe_runtime_gopanic, struct pt_regs *, ctx) {
    const u8 flags = go_exception_pid_flags();
    if (!(flags & k_go_exception_pid_panics)) {
        return 0;
    }

    go_string_t message = {};
    go_panic_message(GO_PARAM1(ctx), GO_PARAM2(ctx), &message);
    return go_exception_emit(ctx, k_go_exception_panic, &message);
}
