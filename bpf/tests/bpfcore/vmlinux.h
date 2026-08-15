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

enum {
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT = 2,
    TCP_SYN_RECV = 3,
    TCP_FIN_WAIT1 = 4,
    TCP_FIN_WAIT2 = 5,
    TCP_TIME_WAIT = 6,
    TCP_CLOSE = 7,
    TCP_CLOSE_WAIT = 8,
    TCP_LAST_ACK = 9,
    TCP_LISTEN = 10,
    TCP_CLOSING = 11,
};

struct in6_addr {
    union {
        u8 u6_addr8[16];
    } in6_u;
};

struct sockaddr {
    u16 sa_family;
};

struct sockaddr_in {
    u16 sin_family;
    u16 sin_port;
    u32 sin_addr;
};

struct sockaddr_in6 {
    u16 sin6_family;
    u16 sin6_port;
    struct in6_addr sin6_addr;
};

struct sock_common {
    u32 skc_daddr;
    u32 skc_rcv_saddr;
    u16 skc_num;
    u16 skc_dport;
    u16 skc_family;
    u8 skc_state;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
    possible_net_t skc_net;
};
struct sock {
    struct sock_common __sk_common;
};

// Only the fields the failed-connect classification reads, in the order the
// kernel declares them.
struct tcp_sock {
    u64 bytes_received;
    u64 bytes_sent;
    u64 bytes_acked;
};
struct socket {
    struct sock *sk;
};

struct iov_iter {};
struct iovec {
    void *iov_base;
    size_t iov_len;
};
struct msghdr {
    struct iov_iter msg_iter;
};
