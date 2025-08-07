// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

enum { MAX_INLINE_LEN = 0x3ff, MAX_NEEDLE_LEN = 16 };

const char TP[] = "Traceparent: 00-00000000000000000000000000000000-0000000000000000-01\r\n";
const u32 EXTEND_SIZE = sizeof(TP) - 1;
const char TP_PREFIX[] = "Traceparent: ";
const u32 TP_PREFIX_SIZE = sizeof(TP_PREFIX) - 1;
const u32 INVALID_POS = 0xffffffff;

static __always_inline unsigned char *
memchar(unsigned char *haystack, char needle, const unsigned char *end, u32 size) {
    for (u32 i = 0; i < size; ++i) {
        if (&haystack[i] >= end) {
            break;
        }

        if (haystack[i] == needle) {
            return &haystack[i];
        }
    }

    return 0;
}

static __always_inline unsigned char *
find_first_of(unsigned char *begin, unsigned char *end, char ch) {
    return memchar(begin, ch, end, MAX_INLINE_LEN);
}

static __always_inline u32 memchar_pos(unsigned char *haystack,
                                       char needle,
                                       const unsigned char *end,
                                       u32 size) {
    for (u32 i = 0; i < size; ++i) {
        unsigned char *ptr = haystack + i;

        if (ptr + 1 >= end) {
            break;
        } else if (ptr && *ptr == needle) {
            return i;
        }
    }

    return INVALID_POS;
}

static __always_inline u32 find_first_pos_of(unsigned char *begin, unsigned char *end, char ch) {
    return memchar_pos(begin, ch, end, MAX_INLINE_LEN);
}

static __always_inline void *ctx_data(struct __sk_buff *ctx) {
    void *data;

    asm("%[res] = *(u32 *)(%[base] + %[offset])"
        : [res] "=r"(data)
        : [base] "r"(ctx), [offset] "i"(offsetof(struct __sk_buff, data)), "m"(*ctx));

    return data;
}

static __always_inline void *ctx_data_end(struct __sk_buff *ctx) {
    void *data_end;

    asm("%[res] = *(u32 *)(%[base] + %[offset])"
        : [res] "=r"(data_end)
        : [base] "r"(ctx), [offset] "i"(offsetof(struct __sk_buff, data_end)), "m"(*ctx));

    return data_end;
}

static __always_inline void *ctx_msg_data(struct sk_msg_md *ctx) {
    void *data;

    asm("%[res] = *(u64 *)(%[base] + %[offset])"
        : [res] "=r"(data)
        : [base] "r"(ctx), [offset] "i"(offsetof(struct sk_msg_md, data)), "m"(*ctx));

    return data;
}

static __always_inline void *ctx_msg_data_end(struct sk_msg_md *ctx) {
    void *data_end;

    asm("%[res] = *(u64 *)(%[base] + %[offset])"
        : [res] "=r"(data_end)
        : [base] "r"(ctx), [offset] "i"(offsetof(struct sk_msg_md, data_end)), "m"(*ctx));

    return data_end;
}

static __always_inline void
sk_msg_read_remote_ip6(struct sk_msg_md *ctx, u32 *res) { //NOLINT(readability-non-const-parameter)
    asm("%[res0] = *(u32 *)(%[base] + %[offset] + 0)\n"
        "%[res1] = *(u32 *)(%[base] + %[offset] + 4)\n"
        "%[res2] = *(u32 *)(%[base] + %[offset] + 8)\n"
        "%[res3] = *(u32 *)(%[base] + %[offset] + 12)\n"
        : [res0] "=r"(res[0]), [res1] "=r"(res[1]), [res2] "=r"(res[2]), [res3] "=r"(res[3])
        : [base] "r"(ctx), [offset] "i"(offsetof(struct sk_msg_md, remote_ip6)), "m"(*ctx));
}

static __always_inline void
sk_msg_read_local_ip6(struct sk_msg_md *ctx, u32 *res) { //NOLINT(readability-non-const-parameter)
    asm("%[res0] = *(u32 *)(%[base] + %[offset] + 0)\n"
        "%[res1] = *(u32 *)(%[base] + %[offset] + 4)\n"
        "%[res2] = *(u32 *)(%[base] + %[offset] + 8)\n"
        "%[res3] = *(u32 *)(%[base] + %[offset] + 12)\n"
        : [res0] "=r"(res[0]), [res1] "=r"(res[1]), [res2] "=r"(res[2]), [res3] "=r"(res[3])
        : [base] "r"(ctx), [offset] "i"(offsetof(struct sk_msg_md, local_ip6)), "m"(*ctx));
}

static __always_inline u32 sk_msg_remote_port(struct sk_msg_md *ctx) {
    u32 data;

    asm("%[res] = *(u32 *)(%[base] + %[offset])"
        : [res] "=r"(data)
        : [base] "r"(ctx), [offset] "i"(offsetof(struct sk_msg_md, remote_port)), "m"(*ctx));

    return data;
}

static __always_inline u32 sk_msg_local_port(struct sk_msg_md *ctx) {
    u32 data;

    asm("%[res] = *(u32 *)(%[base] + %[offset])"
        : [res] "=r"(data)
        : [base] "r"(ctx), [offset] "i"(offsetof(struct sk_msg_md, local_port)), "m"(*ctx));

    return data;
}

// find the needle in the haystack, return the position of the first occurrence, return -1 if not found
static __always_inline u32 bpf_memstr(const unsigned char *haystack,
                                      u32 haystack_len,
                                      const unsigned char *needle,
                                      u32 needle_len) {
    if (needle_len == 0 || haystack_len < needle_len) {
        return INVALID_POS;
    }
    for (u32 i = 0; i <= haystack_len - needle_len; i++) {
        if (i + needle_len > haystack_len) {
            return INVALID_POS;
        }
        u8 found = 1;
#pragma unroll
        // max needle length
        for (u8 j = 0; j < MAX_NEEDLE_LEN; j++) {
            if (j >= needle_len) {
                break;
            }
            if (i + j >= haystack_len) {
                found = 0;
                break;
            }
            if (haystack[i + j] != needle[j]) {
                found = 0;
                break;
            }
        }
        if (found) {
            return i;
        }
    }
    return INVALID_POS;
}