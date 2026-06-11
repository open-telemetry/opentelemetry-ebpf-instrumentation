// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <common/pin_internal.h>

#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var))
#endif

enum { k_obi_usdt_max_args = 12, k_obi_usdt_max_spec_cnt = 256, k_obi_usdt_max_ip_cnt = 1024 };

enum obi_usdt_arg_type {
    k_obi_usdt_arg_const = 0,
    k_obi_usdt_arg_reg = 1,
    k_obi_usdt_arg_reg_deref = 2,
    k_obi_usdt_arg_sib = 3,
};

struct obi_usdt_arg_spec {
    u64 val_off;
    s16 reg_off;
    s16 idx_reg_off;
    u8 arg_type;
    u8 scale_bitshift;
    u8 arg_signed;
    u8 arg_bitshift;
};

struct obi_usdt_spec {
    struct obi_usdt_arg_spec args[k_obi_usdt_max_args];
    u64 cookie;
    u16 arg_cnt;
    u8 _pad[6];
};

struct obi_usdt_ip_key {
    u32 pid;
    u32 _pad;
    u64 ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, k_obi_usdt_max_spec_cnt);
    __type(key, u32);
    __type(value, struct obi_usdt_spec);
    __uint(pinning, OBI_PIN_INTERNAL);
} obi_usdt_specs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, k_obi_usdt_max_ip_cnt);
    __type(key, struct obi_usdt_ip_key);
    __type(value, u32);
    __uint(pinning, OBI_PIN_INTERNAL);
} obi_usdt_ip_to_spec_id SEC(".maps");

static __always_inline struct obi_usdt_spec *obi_usdt_spec_for_ctx(struct pt_regs *ctx) {
    struct obi_usdt_ip_key key = {
        .pid = (u32)(bpf_get_current_pid_tgid() >> 32),
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

    switch ((64 - arg_bitshift) / 8) {
    case 1: {
        u8 tmp = 0;
        int err = bpf_probe_read_user(&tmp, sizeof(tmp), (void *)addr);
        *val = tmp;
        return err;
    }
    case 2: {
        u16 tmp = 0;
        int err = bpf_probe_read_user(&tmp, sizeof(tmp), (void *)addr);
        *val = tmp;
        return err;
    }
    case 4: {
        u32 tmp = 0;
        int err = bpf_probe_read_user(&tmp, sizeof(tmp), (void *)addr);
        *val = tmp;
        return err;
    }
    case 8:
        return bpf_probe_read_user(val, sizeof(*val), (void *)addr);
    default:
        return -1;
    }
}

static __always_inline int obi_usdt_arg(struct pt_regs *ctx, u64 arg_num, long *res) {
    *res = 0;

    struct obi_usdt_spec *spec = obi_usdt_spec_for_ctx(ctx);
    if (!spec) {
        return -1;
    }

    if (arg_num >= k_obi_usdt_max_args) {
        return -1;
    }
    barrier_var(arg_num);
    if (arg_num >= spec->arg_cnt) {
        return -1;
    }

    struct obi_usdt_arg_spec *arg = &spec->args[arg_num];
    unsigned long val = 0;
    unsigned long idx = 0;
    int err = 0;

    switch (arg->arg_type) {
    case k_obi_usdt_arg_const:
        val = arg->val_off;
        break;
    case k_obi_usdt_arg_reg:
        err = bpf_probe_read_kernel(&val, sizeof(val), (unsigned char *)ctx + arg->reg_off);
        if (err) {
            return err;
        }
        break;
    case k_obi_usdt_arg_reg_deref:
        err = bpf_probe_read_kernel(&val, sizeof(val), (unsigned char *)ctx + arg->reg_off);
        if (err) {
            return err;
        }
        err = obi_usdt_read_user_value(val + arg->val_off, arg->arg_bitshift, &val);
        if (err) {
            return err;
        }
        break;
    case k_obi_usdt_arg_sib:
        err = bpf_probe_read_kernel(&val, sizeof(val), (unsigned char *)ctx + arg->reg_off);
        if (err) {
            return err;
        }
        err = bpf_probe_read_kernel(&idx, sizeof(idx), (unsigned char *)ctx + arg->idx_reg_off);
        if (err) {
            return err;
        }
        err = obi_usdt_read_user_value(
            val + (idx << arg->scale_bitshift) + arg->val_off, arg->arg_bitshift, &val);
        if (err) {
            return err;
        }
        break;
    default:
        return -1;
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
