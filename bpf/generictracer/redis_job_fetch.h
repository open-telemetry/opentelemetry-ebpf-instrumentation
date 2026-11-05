// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

// Redis commands that take work off a queue, by the shape of their reply
enum redis_job_fetch : u8 {
    k_redis_job_fetch_none = 0,
    // list and sorted set pops, stream reads and claims: nil or empty when nothing was taken
    k_redis_job_fetch_take = 1,
    // XAUTOCLAIM replies [cursor, claimed entries, deleted ids]
    k_redis_job_fetch_autoclaim = 2,
};

enum {
    // *<argc>\r\n$<name length>\r\n<name>: up to 3 argc digits, 2 length digits, 10 name bytes
    k_redis_job_fetch_head_len = 21,
    k_redis_job_fetch_name_min_len = 4,
    k_redis_job_fetch_name_max_len = 10,
    // *3\r\n$<cursor length>\r\n
    k_redis_autoclaim_min_len = 9,
    // after a cursor of at most 99 bytes
    k_redis_autoclaim_claimed_at_max = k_redis_autoclaim_min_len + 99 + 2,
};

static __always_inline bool resp_crlf_at(const unsigned char *buf, const u32 at) {
    return buf[at] == '\r' && buf[at + 1] == '\n';
}

static __always_inline bool resp_digit(const unsigned char c) {
    return c >= '0' && c <= '9';
}

// Where the bulk string whose $ is at `at` starts, and its length of at most 2 digits;
// 0 when malformed
static __always_inline u32 resp_bulk_at(const unsigned char *buf, const u32 at, u32 *len) {
    if (buf[at] != '$' || !resp_digit(buf[at + 1])) {
        return 0;
    }

    if (resp_crlf_at(buf, at + 2)) {
        *len = buf[at + 1] - '0';
        return at + 4;
    }

    if (resp_digit(buf[at + 2]) && resp_crlf_at(buf, at + 3)) {
        *len = (buf[at + 1] - '0') * 10 + (buf[at + 2] - '0');
        return at + 5;
    }

    return 0;
}

static __always_inline enum redis_job_fetch redis_job_fetch_by_name(const char *name,
                                                                    const u32 len) {
    switch (len) {
    case 4:
        if (!bpf_memcmp(name, "lpop", 4) || !bpf_memcmp(name, "rpop", 4)) {
            return k_redis_job_fetch_take;
        }
        break;
    case 5:
        if (!bpf_memcmp(name, "blpop", 5) || !bpf_memcmp(name, "brpop", 5) ||
            !bpf_memcmp(name, "lmove", 5) || !bpf_memcmp(name, "lmpop", 5) ||
            !bpf_memcmp(name, "zmpop", 5) || !bpf_memcmp(name, "xread", 5)) {
            return k_redis_job_fetch_take;
        }
        break;
    case 6:
        if (!bpf_memcmp(name, "blmove", 6) || !bpf_memcmp(name, "blmpop", 6) ||
            !bpf_memcmp(name, "bzmpop", 6) || !bpf_memcmp(name, "xclaim", 6)) {
            return k_redis_job_fetch_take;
        }
        break;
    case 7:
        if (!bpf_memcmp(name, "zpopmin", 7) || !bpf_memcmp(name, "zpopmax", 7)) {
            return k_redis_job_fetch_take;
        }
        break;
    case 8:
        if (!bpf_memcmp(name, "bzpopmin", 8) || !bpf_memcmp(name, "bzpopmax", 8)) {
            return k_redis_job_fetch_take;
        }
        break;
    case 9:
        if (!bpf_memcmp(name, "rpoplpush", 9)) {
            return k_redis_job_fetch_take;
        }
        break;
    case 10:
        if (!bpf_memcmp(name, "brpoplpush", 10) || !bpf_memcmp(name, "xreadgroup", 10)) {
            return k_redis_job_fetch_take;
        }
        if (!bpf_memcmp(name, "xautoclaim", 10)) {
            return k_redis_job_fetch_autoclaim;
        }
        break;
    }

    return k_redis_job_fetch_none;
}

// The job fetch a client request starts, from the RESP array that names the command
static __always_inline enum redis_job_fetch redis_job_fetch_request(const unsigned char *buf,
                                                                    const u32 len) {
    if (len < k_redis_job_fetch_head_len || buf[0] != '*') {
        return k_redis_job_fetch_none;
    }

    u32 bulk_at = 0;
    if (resp_crlf_at(buf, 2)) {
        bulk_at = 4;
    } else if (resp_crlf_at(buf, 3)) {
        bulk_at = 5;
    } else if (resp_crlf_at(buf, 4)) {
        bulk_at = 6;
    } else {
        return k_redis_job_fetch_none;
    }

    u32 name_len = 0;
    const u32 name_at = resp_bulk_at(buf, bulk_at, &name_len);
    if (!name_at || name_len < k_redis_job_fetch_name_min_len ||
        name_len > k_redis_job_fetch_name_max_len) {
        return k_redis_job_fetch_none;
    }

    // clients send command names in either case
    char name[k_redis_job_fetch_name_max_len] = {};
    for (u32 i = 0; i < k_redis_job_fetch_name_max_len; i++) {
        name[i] = buf[name_at + i] | 0x20;
    }

    return redis_job_fetch_by_name(name, name_len);
}

// nil, an empty aggregate or an error: nothing was taken
static __always_inline bool resp_reply_is_empty(const unsigned char *buf) {
    switch (buf[0]) {
    case '-':
    case '!':
    case '_':
        return true;
    case '$':
        return buf[1] == '-';
    case '*':
    case '%':
    case '~':
        return buf[1] == '-' || (buf[1] == '0' && buf[2] == '\r');
    }

    return false;
}

// Whether the reply to a job fetch carries a job; len is how much of it was captured
static __always_inline bool redis_job_fetch_reply_has_job(const enum redis_job_fetch fetch,
                                                          const unsigned char *buf,
                                                          const u32 len) {
    if (len < 4 || resp_reply_is_empty(buf)) {
        return false;
    }

    if (fetch != k_redis_job_fetch_autoclaim) {
        return true;
    }

    if (len < k_redis_autoclaim_min_len || buf[0] != '*' || !resp_crlf_at(buf, 2)) {
        return false;
    }

    u32 cursor_len = 0;
    const u32 cursor_at = resp_bulk_at(buf, 4, &cursor_len);
    if (!cursor_at) {
        return false;
    }

    // a cursor too long for the captured reply leaves the claimed entries unseen
    u32 claimed_at = cursor_at + cursor_len + 2;
    if (claimed_at + 3 > len) {
        return true;
    }

    // the verifier doesn't carry the digit checks into the cursor length
    bpf_clamp_umax(claimed_at, k_redis_autoclaim_claimed_at_max);

    return !resp_reply_is_empty(buf + claimed_at);
}
