// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

enum { k_obi_usdt_max_args = 12, k_obi_usdt_max_spec_cnt = 256, k_obi_usdt_max_ip_cnt = 1024 };

enum obi_usdt_arg_type {
    k_obi_usdt_arg_const = 0,
    k_obi_usdt_arg_reg = 1,
    k_obi_usdt_arg_reg_deref = 2,
};

enum obi_usdt_arg_error {
    k_obi_usdt_arg_err_no_spec = -2,
    k_obi_usdt_arg_err_out_of_range = -3,
    k_obi_usdt_arg_err_bad_type = -4,
    k_obi_usdt_arg_err_bad_size = -5,
    k_obi_usdt_arg_err_bad_reg = -6,
};

struct obi_usdt_arg_spec {
    u64 val_off;
    s16 reg_off;
    u8 arg_type;
    u8 arg_signed;
    u8 arg_bitshift;
    u8 _pad[3];
};

struct obi_usdt_spec {
    struct obi_usdt_arg_spec args[k_obi_usdt_max_args];
    u64 cookie;
    u16 arg_cnt;
    u8 _pad[6];
};

struct obi_usdt_ip_key {
    u32 pid;
    u32 ns;
    u64 ip;
};
