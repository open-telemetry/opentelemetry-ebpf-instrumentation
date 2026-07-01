// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/utils.h>

#include <generictracer/custom_span.h>
#include <common/event_defs.h>
#include <common/ringbuf.h>
#include <common/usdt.h>
#include <logger/bpf_dbg.h>
#include <pid/pid.h>
#include <shared/obi_ctx.h>

struct custom_span_event _custom_span_event = {};

// has_attach_cookie is patched to 1 by userspace at load time when the
// running kernel exports bpf_get_attach_cookie (≥5.15). On older kernels it
// stays 0, and the verifier dead-code-eliminates the helper call below so
// the program loads even where the helper id is unknown.
volatile const u32 has_attach_cookie = 0;

static __always_inline void custom_span_fill_pid(u64 pid_tgid, struct custom_span_event *e) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int ns_pid = 0;
    int ns_ppid = 0;
    u32 pid_ns_id = 0;
    ns_pid_ppid(task, &ns_pid, &ns_ppid, &pid_ns_id);

    e->global_pid = pid_from_pid_tgid(pid_tgid);
    e->global_tid = tid_from_pid_tgid(pid_tgid);
    e->ns_pid = (u32)ns_pid;
    e->ns_tid = get_task_tid();
    e->pid_ns_id = pid_ns_id;
}

static __always_inline void custom_span_attach_trace_ctx(u64 pid_tgid,
                                                         struct custom_span_event *e) {
    obi_ctx_info_t *ctx = obi_ctx__get(pid_tgid);
    if (!ctx) {
        bpf_memset(&e->trace_ctx, 0, sizeof(e->trace_ctx));
        e->has_trace_ctx = 0;
        return;
    }
    bpf_memcpy(&e->trace_ctx, ctx, sizeof(*ctx));
    e->has_trace_ctx = 1;
}

// custom_span_int_from_spec extracts an integer arg directly from the
// passed-in spec, bypassing the IP-map re-lookup that obi_usdt_arg performs.
// This is required because custom_span resolves specs via attach cookie
// (which disambiguates probes that share an IP, e.g. an inline USDT inside
// a function being probed in function-mode).
static __always_inline int
custom_span_int_from_spec(struct pt_regs *ctx, struct obi_usdt_arg_spec *arg, long *res) {
    *res = 0;
    if (!obi_usdt_arg_bitshift_ok(arg->arg_bitshift)) {
        return k_obi_usdt_arg_err_bad_size;
    }
    unsigned long val = 0;
    int err = 0;
    switch (arg->arg_type) {
    case k_obi_usdt_arg_const:
        val = arg->val_off;
        break;
    case k_obi_usdt_arg_reg:
        if (!obi_usdt_reg_off_ok(arg->reg_off)) {
            return k_obi_usdt_arg_err_bad_reg;
        }
        err = bpf_probe_read_kernel(&val, sizeof(val), (unsigned char *)ctx + arg->reg_off);
        if (err) {
            return err;
        }
        break;
    case k_obi_usdt_arg_reg_deref:
        if (!obi_usdt_reg_off_ok(arg->reg_off)) {
            return k_obi_usdt_arg_err_bad_reg;
        }
        err = bpf_probe_read_kernel(&val, sizeof(val), (unsigned char *)ctx + arg->reg_off);
        if (err) {
            return err;
        }
        err = obi_usdt_read_user_value(val + arg->val_off, arg->arg_bitshift, &val);
        if (err) {
            return err;
        }
        break;
    default:
        return k_obi_usdt_arg_err_bad_type;
    }
    val <<= arg->arg_bitshift;
    if (arg->arg_signed) {
        val = ((long)val) >> arg->arg_bitshift;
    } else {
        val >>= arg->arg_bitshift;
    }
    *res = (long)val;
    return 0;
}

static __always_inline int custom_span_str_from_spec(
    struct pt_regs *ctx, struct obi_usdt_arg_spec *arg, void *dst, u32 dst_max, u32 *out_len) {
    *out_len = 0;
    if (!obi_usdt_reg_off_ok(arg->reg_off)) {
        return k_obi_usdt_arg_err_bad_reg;
    }
    unsigned long ptr = 0;
    int err = bpf_probe_read_kernel(&ptr, sizeof(ptr), (unsigned char *)ctx + arg->reg_off);
    if (err) {
        return err;
    }
    if (!ptr) {
        return 0;
    }
    if (arg->arg_type == k_obi_usdt_arg_go_string) {
        // Go string {ptr, len}. ptr is at reg_off; len is at val_off
        // (a second pt_regs offset). Go regabi on amd64 spreads scalars
        // across non-consecutive registers (AX, BX, CX, DI, SI, R8, ...),
        // so a {ptr, len} pair does NOT live at reg_off and reg_off+8 —
        // userspace encodes the second register's offset explicitly.
        s16 len_reg_off = (s16)(arg->val_off & 0xFFFF);
        if (!obi_usdt_reg_off_ok(len_reg_off)) {
            return k_obi_usdt_arg_err_bad_reg;
        }
        unsigned long slen = 0;
        if ((err =
                 bpf_probe_read_kernel(&slen, sizeof(slen), (unsigned char *)ctx + len_reg_off))) {
            return err;
        }
        u32 n = (u32)slen;
        if (n >= dst_max) {
            n = dst_max - 1;
        }
        if (n == 0) {
            return 0;
        }
        if ((err = bpf_probe_read_user(dst, n, (const void *)ptr))) {
            return err;
        }
        ((u8 *)dst)[n] = 0;
        *out_len = n + 1;
        return 0;
    }
    if (arg->arg_type == k_obi_usdt_arg_ptr_field_go_string) {
        // reg = *struct; string header at {struct+val_off, +8}
        unsigned long sdata = 0;
        unsigned long slen = 0;
        if ((err =
                 bpf_probe_read_user(&sdata, sizeof(sdata), (const void *)(ptr + arg->val_off)))) {
            return err;
        }
        if ((err = bpf_probe_read_user(
                 &slen, sizeof(slen), (const void *)(ptr + arg->val_off + 8)))) {
            return err;
        }
        if (!sdata || slen == 0) {
            return 0;
        }
        u32 n = (u32)slen;
        if (n >= dst_max) {
            n = dst_max - 1;
        }
        if ((err = bpf_probe_read_user(dst, n, (const void *)sdata))) {
            return err;
        }
        ((u8 *)dst)[n] = 0;
        *out_len = n + 1;
        return 0;
    }
    if (arg->arg_type != k_obi_usdt_arg_reg_deref_str) {
        return k_obi_usdt_arg_err_bad_type;
    }
    long n = bpf_probe_read_user_str(dst, dst_max, (const void *)ptr);
    if (n < 0) {
        return (int)n;
    }
    *out_len = (u32)n;
    return 0;
}

static __always_inline void custom_span_fill_args(struct pt_regs *ctx,
                                                  struct obi_usdt_spec *spec,
                                                  struct custom_span_event *e) {
    u32 cnt = spec->arg_cnt;
    if (cnt > k_custom_span_max_args) {
        cnt = k_custom_span_max_args;
    }
    e->arg_cnt = (u8)cnt;

#pragma unroll
    for (u32 i = 0; i < k_custom_span_max_args; i++) {
        e->arg_int[i] = 0;
        e->arg_str_len[i] = 0;
        bpf_memset(e->arg_str[i], 0, k_custom_span_str_len);

        if (i >= cnt) {
            e->arg_kind[i] = k_custom_span_arg_none;
            continue;
        }

        u8 t = spec->args[i].arg_type;
        if (t == k_obi_usdt_arg_reg_deref_str || t == k_obi_usdt_arg_go_string ||
            t == k_obi_usdt_arg_ptr_field_go_string) {
            u32 out_len = 0;
            int err = custom_span_str_from_spec(
                ctx, &spec->args[i], e->arg_str[i], k_custom_span_str_len, &out_len);
            if (err != 0) {
                bpf_dbg_printk("custom_span: str arg %u err=%d", i, err);
                e->arg_kind[i] = k_custom_span_arg_none;
                continue;
            }
            if (out_len == 0) {
                e->arg_kind[i] = k_custom_span_arg_none;
                continue;
            }
            e->arg_str_len[i] = (u16)out_len;
            e->arg_kind[i] = k_custom_span_arg_str;
        } else {
            long val = 0;
            int err = custom_span_int_from_spec(ctx, &spec->args[i], &val);
            if (err != 0) {
                bpf_dbg_printk("custom_span: int arg %u err=%d", i, err);
                e->arg_kind[i] = k_custom_span_arg_none;
                continue;
            }
            e->arg_int[i] = (u64)val;
            e->arg_kind[i] = k_custom_span_arg_int;
        }
    }
}

// match_name_ok returns 1 if spec has no match filter or arg_str[match_arg_idx]
// equals spec->match_name (NUL-terminated, max k_obi_usdt_match_name_len).
static __always_inline int custom_span_match_name_ok(struct obi_usdt_spec *spec,
                                                     struct custom_span_event *e) {
    if (!spec->match_enabled) {
        return 1;
    }
    u32 idx = spec->match_arg_idx;
    if (idx >= k_custom_span_max_args) {
        return 0;
    }
    if (e->arg_kind[idx] != k_custom_span_arg_str) {
        return 0;
    }
#pragma unroll
    for (u32 i = 0; i < k_obi_usdt_match_name_len; i++) {
        u8 a = e->arg_str[idx][i];
        u8 b = spec->match_name[i];
        if (a != b) {
            return 0;
        }
        if (a == 0) {
            return 1;
        }
    }
    return 1;
}

static __always_inline struct obi_usdt_spec *custom_span_spec_lookup(struct pt_regs *ctx) {
    // Cookie path is gated on has_attach_cookie (patched to 1 on kernel
    // ≥5.15). When the constant is 0 the verifier eliminates the helper
    // call entirely so the program loads on older kernels — those still
    // resolve specs through obi_usdt_spec_for_ctx (the IP map).
    if (has_attach_cookie) {
        u64 cookie = bpf_get_attach_cookie(ctx);
        if (cookie != 0) {
            u32 spec_id = (u32)cookie;
            return bpf_map_lookup_elem(&obi_usdt_specs, &spec_id);
        }
    }
    return obi_usdt_spec_for_ctx(ctx);
}

static __always_inline int custom_span_emit(struct pt_regs *ctx, u8 kind) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const u32 pid = valid_pid(pid_tgid);
    if (!pid) {
        return 0;
    }

    struct obi_usdt_spec *spec = custom_span_spec_lookup(ctx);
    if (!spec) {
        return 0;
    }

    struct custom_span_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->type = EVENT_CUSTOM_SPAN;
    e->kind = kind;
    e->arg_cnt = 0;
    e->has_trace_ctx = 0;
    e->pair_kind = spec->pair_kind;
    e->cookie = spec->cookie;
    e->timestamp = bpf_ktime_get_ns();
    // Goroutine pointer: stable across goroutine scheduling onto different
    // OS threads. Used as pair key for Go function_span; harmless otherwise.
    e->g_ptr = (u64)GOROUTINE_PTR(ctx);
    custom_span_fill_pid(pid_tgid, e);
    custom_span_attach_trace_ctx(pid_tgid, e);
    custom_span_fill_args(ctx, spec, e);

    // Apply the match-name filter only on start / single events. Paired
    // usdt_span end probes share the spec with their start side but may
    // pass a different arg at match_arg_idx (e.g. start carries a customer
    // name, end carries a status code). Filtering only on start is enough:
    // unmatched start events never enter the pairer, so the corresponding
    // end event simply finds no pending state in userspace and drops.
    if (kind != k_custom_span_kind_end && !custom_span_match_name_ok(spec, e)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, get_flags());
    return 0;
}

SEC("uprobe/obi_custom_span_start")
int obi_custom_span_start(struct pt_regs *ctx) {
    return custom_span_emit(ctx, k_custom_span_kind_start);
}

SEC("uprobe/obi_custom_span_end")
int obi_custom_span_end(struct pt_regs *ctx) {
    return custom_span_emit(ctx, k_custom_span_kind_end);
}

SEC("uprobe/obi_custom_span_event")
int obi_custom_span_event(struct pt_regs *ctx) {
    return custom_span_emit(ctx, k_custom_span_kind_single);
}

SEC("uretprobe/obi_custom_span_func_ret")
int obi_custom_span_func_ret(struct pt_regs *ctx) {
    return custom_span_emit(ctx, k_custom_span_kind_end);
}
