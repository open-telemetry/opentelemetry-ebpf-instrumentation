// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <common/pin_internal.h>
#include <common/usdt_types.h>
#include <pid/pid.h>

#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var))
#endif

#include <common/maps/obi_usdt_ip_to_spec_id.h>
#include <common/maps/obi_usdt_specs.h>

_Static_assert(sizeof(struct pt_regs) >= sizeof(unsigned long),
               "pt_regs must hold register-sized values");

static __always_inline u8 obi_usdt_arg_bitshift_ok(u8 arg_bitshift) {
    switch (arg_bitshift) {
    case 0:
    case 32:
    case 48:
    case 56:
        return 1;
    default:
        return 0;
    }
}

static __always_inline u8 obi_usdt_reg_off_ok(s16 reg_off) {
    if (reg_off < 0) {
        return 0;
    }

    return (size_t)reg_off <= sizeof(struct pt_regs) - sizeof(unsigned long);
}

static __always_inline struct obi_usdt_spec *obi_usdt_spec_for_ctx(struct pt_regs *ctx) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const u32 pid = valid_pid(pid_tgid);
    if (!pid) {
        return NULL;
    }

    const struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int ns_pid = 0;
    int ns_ppid = 0;
    u32 pid_ns_id = 0;
    ns_pid_ppid(task, &ns_pid, &ns_ppid, &pid_ns_id);

    struct obi_usdt_ip_key key = {
        .pid = pid,
        .ns = pid_ns_id,
        .ip = PT_REGS_IP(ctx),
    };

    u32 *spec_id = bpf_map_lookup_elem(&obi_usdt_ip_to_spec_id, &key);
    if (!spec_id) {
        return NULL;
    }

    return bpf_map_lookup_elem(&obi_usdt_specs, spec_id);
}

static __always_inline int obi_usdt_read_user_value(u64 addr, u8 arg_bitshift, unsigned long *val) {
    *val = 0;

    switch (arg_bitshift) {
    case 56: {
        u8 tmp = 0;
        int err = bpf_probe_read_user(&tmp, sizeof(tmp), (void *)addr);
        *val = tmp;
        return err;
    }
    case 48: {
        u16 tmp = 0;
        int err = bpf_probe_read_user(&tmp, sizeof(tmp), (void *)addr);
        *val = tmp;
        return err;
    }
    case 32: {
        u32 tmp = 0;
        int err = bpf_probe_read_user(&tmp, sizeof(tmp), (void *)addr);
        *val = tmp;
        return err;
    }
    case 0:
        return bpf_probe_read_user(val, sizeof(*val), (void *)addr);
    default:
        return k_obi_usdt_arg_err_bad_size;
    }
}

static __always_inline int obi_usdt_arg(struct pt_regs *ctx, u64 arg_num, long *res) {
    *res = 0;

    struct obi_usdt_spec *spec = obi_usdt_spec_for_ctx(ctx);
    if (!spec) {
        return k_obi_usdt_arg_err_no_spec;
    }

    if (arg_num >= k_obi_usdt_max_args) {
        return k_obi_usdt_arg_err_out_of_range;
    }
    barrier_var(arg_num);
    if (arg_num >= spec->arg_cnt) {
        return k_obi_usdt_arg_err_out_of_range;
    }

    struct obi_usdt_arg_spec *arg = &spec->args[arg_num];
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
