// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

enum {
    k_obi_usdt_max_args = 12,
    k_obi_usdt_max_spec_cnt = 256,
    k_obi_usdt_max_ip_cnt = 1024,
    k_obi_usdt_match_name_len = 64,
};

enum obi_usdt_pair_kind {
    k_obi_usdt_pair_arg0 = 0, // legacy: pair on arg_int[0] value
    k_obi_usdt_pair_tid = 1,  // function-pair: pair on pid_tgid
    k_obi_usdt_pair_g = 2,    // Go function-pair: pair on goroutine pointer (r14/x28)
};

enum obi_usdt_arg_type {
    k_obi_usdt_arg_const = 0,
    k_obi_usdt_arg_reg = 1,
    k_obi_usdt_arg_reg_deref = 2,
    // reg = user ptr; read NUL-terminated string
    k_obi_usdt_arg_reg_deref_str = 3,
    // Go string {ptr in reg_off, len in val_off (2nd reg's pt_regs offset)}
    k_obi_usdt_arg_go_string = 4,
    // Go string field: reg = *struct, val_off = field offset
    k_obi_usdt_arg_ptr_field_go_string = 5,
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
    u8 pair_kind;     // see enum obi_usdt_pair_kind
    u8 match_arg_idx; // index into e->arg_str compared against match_name
    u8 match_enabled; // 1 when match filter active; distinguishes "" from "no filter"
    u8 _pad[3];
    u8 match_name[k_obi_usdt_match_name_len];
};

struct obi_usdt_ip_key {
    u32 pid;
    u32 ns;
    u64 ip;
};
