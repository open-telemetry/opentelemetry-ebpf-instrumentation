// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>

#include <shared/obi_ctx.h>

enum {
    // include/linux/tty_driver.h
    k_tty_driver_type_pty = 0x0004,
    k_tty_driver_subtype_pty_master = 0x0001,

    // include/linux/kdev_t.h
    k_minor_bits = 20,

    // log handling
    k_log_event_max_size = 1 << 15,    // 32K
    k_log_event_max_log_len = 1 << 13, // 8K

    // iovec
    k_iov_max_segs = 8,
    k_iov_seg_max_len = 1 << 13, // 8K
};

enum log_dest_kind {
    k_log_dest_pipe,
    k_log_dest_tty,
};

static const char k_newline = '\n';

typedef struct log_event {
    u64 ino;
    u32 tgid;
    u32 len;
    u32 fd;
    u32 dev; // kernel dev_t of the destination's superblock, disambiguates ino across filesystems
    obi_ctx_info_t ctx;
    u8 dest_kind; // enum log_dest_kind
    u8 _pad[7];
    u8 log[];
} log_event_t;

const log_event_t *log_event__unused __attribute__((unused));

// bare inode numbers collide across filesystems (pipefs vs on-disk FIFOs,
// and get_next_ino() wraps at 32 bits), so pipes are keyed by (ino, dev).
// dev holds a 32-bit kernel dev_t; u64 keeps the key free of implicit padding
typedef struct log_pipe_key {
    u64 ino;
    u64 dev;
} log_pipe_key_t;

const log_pipe_key_t *log_pipe_key__unused __attribute__((unused));

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

static __always_inline bool tty_driver_is_pty(struct tty_struct *tty) {
    int typ;
    if (bpf_core_enum_value_exists(enum tty_driver_type___new, TTY_DRIVER_TYPE_PTY)) {
        typ = bpf_core_enum_value(enum tty_driver_type___new, TTY_DRIVER_TYPE_PTY);
    } else {
        typ = k_tty_driver_type_pty;
    }

    if (bpf_core_field_exists(((struct tty_driver *)0)->type)) {
        return BPF_CORE_READ(tty, driver, type) == typ;
    }

    return false;
}

static __always_inline bool tty_driver_is_master(struct tty_struct *tty) {
    int typ;
    if (bpf_core_enum_value_exists(enum tty_driver_subtype___new, PTY_TYPE_MASTER)) {
        typ = bpf_core_enum_value(enum tty_driver_subtype___new, PTY_TYPE_MASTER);
    } else {
        typ = k_tty_driver_subtype_pty_master;
    }

    if (bpf_core_field_exists(((struct tty_driver *)0)->subtype)) {
        return BPF_CORE_READ(tty, driver, subtype) == typ;
    }

    return false;
}

// same as tty_devnum() in drivers/tty/tty_io.c
static __always_inline u32 tty_devnum(struct tty_struct *tty) {
    const u32 major = BPF_CORE_READ(tty, driver, major);
    const u32 minor_start = BPF_CORE_READ(tty, driver, minor_start);
    const u32 index = BPF_CORE_READ(tty, index);

    return ((major << k_minor_bits) | minor_start) + index;
}
