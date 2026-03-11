// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#undef __always_inline
#define __always_inline inline __attribute__((always_inline))
#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif
#ifndef __weak
#define __weak __attribute__((weak))
#endif
#ifndef NULL
#define NULL ((void *)0)
#endif

#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

#define SEC(name) __attribute__((section(name), used))

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_PERCPU_ARRAY 10
#define BPF_MAP_TYPE_LRU_PERCPU_HASH 13
#define BPF_MAP_TYPE_RINGBUF 27

static inline void *bpf_map_lookup_elem(void *map, const void *key) {
    return NULL;
}
static inline long
bpf_map_update_elem(void *map, const void *key, const void *val, unsigned long long flags) {
    return 0;
}
static inline long bpf_map_delete_elem(void *map, const void *key) {
    return 0;
}
static inline long bpf_probe_read(void *dst, unsigned int size, const void *src) {
    return 0;
}
static inline long bpf_probe_read_kernel(void *dst, unsigned int size, const void *src) {
    return 0;
}
static long (*bpf_ringbuf_output_hook)(void *rb,
                                       void *data,
                                       unsigned long long sz,
                                       unsigned long long flags);
static inline long
bpf_ringbuf_output(void *rb, void *data, unsigned long long sz, unsigned long long flags) {
    return bpf_ringbuf_output_hook ? bpf_ringbuf_output_hook(rb, data, sz, flags) : 0;
}
static inline void *bpf_ringbuf_reserve(void *rb, unsigned long long sz, unsigned long long flags) {
    return NULL;
}
static inline void bpf_ringbuf_submit(void *data, unsigned long long flags) {
}
static inline unsigned long long bpf_ringbuf_query(void *rb, int flags) {
    return 0;
}

#define BPF_RB_NO_WAKEUP 1
#define BPF_RB_FORCE_WAKEUP 2
#define BPF_RB_AVAIL_DATA 0
static inline void *bpf_get_current_task(void) {
    return NULL;
}
static inline unsigned long long bpf_get_current_pid_tgid(void) {
    return 0;
}
static inline long bpf_get_current_comm(void *buf, unsigned int sz) {
    return 0;
}
static inline int bpf_printk(const char *fmt, ...) {
    return 0;
}
