// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t __s8;
typedef int16_t __s16;
typedef int32_t __s32;
typedef int64_t __s64;

struct upid {
    int nr;
};

struct pid {
    struct upid numbers[8];
};

struct ns_common {
    unsigned int inum;
};

struct net {
    struct ns_common ns;
};

struct pid_namespace {
    unsigned int level;
    struct ns_common ns;
};

typedef struct {
    struct net *net;
} possible_net_t;

struct nsproxy {
    struct pid_namespace *pid_ns_for_children;
    struct net *net_ns;
};

struct task_struct {
    int pid;
    int tgid;
    struct task_struct *group_leader;
    struct task_struct *real_parent;
    struct nsproxy *nsproxy;
    struct pid *thread_pid;
};

struct sock_common {
    u16 skc_num;
    possible_net_t skc_net;
};
struct sock {
    struct sock_common __sk_common;
};
struct iov_iter {};
struct iovec {
    void *iov_base;
    size_t iov_len;
};
struct msghdr {
    struct iov_iter msg_iter;
};
