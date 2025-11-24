// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>

#include <common/pin_internal.h>

#ifdef BPF_DEBUG

enum { k_bpf_debug = 1 };

typedef struct log_info {
    u64 pid;
    unsigned char log[80];
    unsigned char comm[20];
    u8 _pad[4];
} log_info_t;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 15);
    __uint(pinning, OBI_PIN_INTERNAL);
} debug_events SEC(".maps");

enum bpf_func_id___x {
    BPF_FUNC_snprintf___x = 42, /* avoid zero */
};

#define bpf_dbg_helper(fmt, args...)                                                               \
    {                                                                                              \
        log_info_t *__trace__ = bpf_ringbuf_reserve(&debug_events, sizeof(log_info_t), 0);         \
        if (__trace__) {                                                                           \
            if (bpf_core_enum_value_exists(enum bpf_func_id___x, BPF_FUNC_snprintf___x)) {         \
                BPF_SNPRINTF((char *)__trace__->log, sizeof(__trace__->log), fmt, ##args);         \
            } else {                                                                               \
                __builtin_memcpy(__trace__->log, fmt, sizeof(__trace__->log));                     \
            }                                                                                      \
            struct task_struct *task = (struct task_struct *)bpf_get_current_task();               \
            __trace__->pid = (u32)BPF_CORE_READ(task, pid);                                        \
            BPF_CORE_READ_STR_INTO(&__trace__->comm, task, comm);                                  \
            bpf_ringbuf_submit(__trace__, 0);                                                      \
        }                                                                                          \
    }
#define bpf_dbg_printk(fmt, args...)                                                               \
    {                                                                                              \
        bpf_printk(fmt, ##args);                                                                   \
        bpf_dbg_helper(fmt, ##args);                                                               \
    }
#define bpf_d_printk(fmt, args...)                                                                 \
    {                                                                                              \
        bpf_printk(fmt, ##args);                                                                   \
    }
#else

enum { k_bpf_debug = 0 };

#define bpf_dbg_printk(fmt, args...)
#define bpf_d_printk(fmt, args...)
#endif
