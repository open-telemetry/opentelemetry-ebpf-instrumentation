// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>

#include <common/tp_info.h>

enum {
    // include/linux/tty_driver.h
    k_tty_driver_type_pty = 0x0004,
    k_tty_driver_subtype_pty_master = 0x0001,

    // include/uapi/asm-generic/termbits.h
    k_echo = 0x00008,

    // log handling
    k_log_event_max_size = 1 << 14,                       // 16K
    k_log_event_max_size_mask = k_log_event_max_size - 1, // 16K - 1
    k_log_event_max_log_mask = (1 << 13) - 1,             // 8K - 1

    // terminal file
    k_pts_file_path_len_max = 64,
    k_pts_file_path_len_max_mask = k_pts_file_path_len_max - 1,
};

typedef struct log_event {
    tp_info_pid_t pid_tp;
    u32 tgid;
    u32 len;
    u32 fd;
    u32 _pad;
    u8 file_path[k_pts_file_path_len_max];
    u8 log[];
} log_event_t;

const log_event_t *log_event__unused __attribute__((unused));

enum tty_driver_type___new {
    TTY_DRIVER_TYPE_SYSTEM,
    TTY_DRIVER_TYPE_CONSOLE,
    TTY_DRIVER_TYPE_SERIAL,
    TTY_DRIVER_TYPE_PTY,
    TTY_DRIVER_TYPE_SCC,
    TTY_DRIVER_TYPE_SYSCONS,
};

enum tty_driver_subtype___new {
    SYSTEM_TYPE_TTY = 1,
    SYSTEM_TYPE_CONSOLE,
    SYSTEM_TYPE_SYSCONS,
    SYSTEM_TYPE_SYSPTMX,

    PTY_TYPE_MASTER = 1,
    PTY_TYPE_SLAVE,

    SERIAL_TYPE_NORMAL = 1,
};

struct tty_termios {
    u32 c_lflag;
    // ...unused fields
};

struct tty_dev {
    u16 minor;
    u16 major;
    struct tty_termios termios;
};

static __always_inline void tty_dev_fill(struct tty_dev *dev, struct tty_struct *tty) {
    BPF_CORE_READ_INTO(&dev->major, tty, driver, major);
    BPF_CORE_READ_INTO(&dev->minor, tty, driver, minor_start);
    dev->minor += BPF_CORE_READ(tty, index);
    dev->termios.c_lflag = BPF_CORE_READ(tty, termios.c_lflag);
}

static __always_inline bool tty_driver_is_pty(struct tty_struct *tty) {
    if (bpf_core_enum_value_exists(enum tty_driver_type___new, TTY_DRIVER_TYPE_PTY)) {
        int typ = bpf_core_enum_value(enum tty_driver_type___new, TTY_DRIVER_TYPE_PTY);
        return BPF_CORE_READ(tty, driver, type) == typ;
    }
    return BPF_CORE_READ(tty, driver, type) == k_tty_driver_type_pty;
}

static __always_inline bool tty_driver_is_master(struct tty_struct *tty) {
    if (bpf_core_enum_value_exists(enum tty_driver_subtype___new, PTY_TYPE_MASTER)) {
        int typ = bpf_core_enum_value(enum tty_driver_subtype___new, PTY_TYPE_MASTER);
        return BPF_CORE_READ(tty, driver, subtype) == typ;
    }
    return BPF_CORE_READ(tty, driver, subtype) == k_tty_driver_subtype_pty_master;
}
