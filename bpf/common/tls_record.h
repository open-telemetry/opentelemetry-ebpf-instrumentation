// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

// TLS record layer framing, RFC 8446 section 5.1 (and RFC 5246 section 6.2.1,
// which uses the same header):
//
//   byte 0     ContentType
//   bytes 1-2  legacy_record_version, whose major byte is always 0x03
//   bytes 3-4  length of the fragment that follows, big endian
//
// Every record OpenSSL hands to a BIO begins with this header, which is what
// lets the same bytes be recognised again once they reach the socket.
enum {
    k_tls_hdr_len = 5,
    k_tls_ct_change_cipher_spec = 0x14,
    k_tls_ct_alert = 0x15,
    k_tls_ct_handshake = 0x16,
    k_tls_ct_app_data = 0x17,
    k_tls_version_major = 0x03,
};

// Width of the ciphertext correlation key.
//
// The clamp to the record boundary below is what makes both observation points
// derive the same bytes, so this width is only a cost choice. 32 bytes overlaps
// the ClientHello's client_random and an application record's AEAD tag.
enum { k_tls_prefix_max = 32 };

typedef struct tls_prefix_key {
    unsigned char bytes[k_tls_prefix_max];
    u8 len;
    // Hash map keys are compared by value, so every byte must be initialised.
    u8 _pad[7];
} tls_prefix_key_t;

// Correlation data model. Kept away from the map definitions so the host
// compiled unit tests share the exact types the BPF maps are declared with.

// A userspace pointer scoped to the process it belongs to.
//
// The correlation maps are pinned and shared node-wide, and entries outlive the
// process that made them, so the pid keeps each process's pointers distinct.
typedef struct pid_ptr_key {
    u64 ptr;
    u32 pid;
    u32 _pad;
} pid_ptr_key_t;

static __always_inline pid_ptr_key_t pid_ptr_key(u32 pid, const void *ptr) {
    pid_ptr_key_t key = {.ptr = (u64)ptr, .pid = pid, ._pad = 0};

    return key;
}

typedef struct bio_ssl_info {
    u64 ssl;
    u8 is_wbio; // 1 for the write BIO (egress), 0 for the read BIO (ingress)
    u8 _pad[7];
} bio_ssl_info_t;

typedef struct ssl_bios {
    u64 rbio;
    u64 wbio;
} ssl_bios_t;

typedef struct tls_prefix_val {
    u64 ssl;
    u64 ts_ns;
    u32 pid;
    u32 _pad;
} tls_prefix_val_t;

typedef struct tls_prefix_scratch {
    tls_prefix_key_t key;
    unsigned char record[k_tls_prefix_max];
} tls_prefix_scratch_t;

// Two byte test for the start of a TLS record, cheap enough for every plaintext
// socket write. The version byte also screens out kTLS, where the kernel
// encrypts below us and the socket carries plaintext.
static __always_inline u8 tls_record_plausible_start(const unsigned char *hdr, u32 avail) {
    if (avail < k_tls_hdr_len) {
        return 0;
    }

    const unsigned char content_type = hdr[0];

    if (content_type != k_tls_ct_change_cipher_spec && content_type != k_tls_ct_alert &&
        content_type != k_tls_ct_handshake && content_type != k_tls_ct_app_data) {
        return 0;
    }

    return hdr[1] == k_tls_version_major;
}

// Returns how many leading bytes of a buffer form a stable correlation key, or
// 0 if the buffer does not begin with a plausible TLS record.
//
// Clamping to the record length is what makes both sides derive identical
// bytes: OpenSSL writes one record to the BIO, while the socket may carry that
// record plus whatever was coalesced behind it. `avail` is how many bytes the
// caller knows the transfer holds, which may exceed what it copied out.
static __always_inline u32 tls_record_key_len(const unsigned char *hdr, u32 avail) {
    if (!tls_record_plausible_start(hdr, avail)) {
        return 0;
    }

    const u32 fragment_len = ((u32)hdr[3] << 8) | (u32)hdr[4];

    if (fragment_len == 0) {
        return 0;
    }

    const u32 record_len = k_tls_hdr_len + fragment_len;
    u32 key_len = record_len < avail ? record_len : avail;

    if (key_len > k_tls_prefix_max) {
        key_len = k_tls_prefix_max;
    }

    return key_len;
}

// Builds a correlation key from a buffer that is already readable by the
// caller. `copied` is how many bytes `src` actually holds; `avail` is the size
// of the whole transfer the buffer was taken from. Returns 0 if no key could be
// derived.
static __always_inline u32 tls_prefix_key_from_buf(tls_prefix_key_t *key,
                                                   const unsigned char *src,
                                                   u32 copied,
                                                   u32 avail) {
    __builtin_memset(key, 0, sizeof(*key));

    if (copied < k_tls_hdr_len) {
        return 0;
    }

    const u32 key_len = tls_record_key_len(src, avail);

    if (key_len == 0 || key_len > copied) {
        return 0;
    }

    // Constant trip count with a per-byte predicate, so the verifier sees a
    // fully unrolled copy. The loads may be emitted unconditionally, so the
    // index is clamped to keep every one inside the copied bytes.
#pragma unroll
    for (u32 i = 0; i < k_tls_prefix_max; i++) {
        const u32 idx = i < key_len ? i : key_len - 1;
        key->bytes[i] = i < key_len ? src[idx] : 0;
    }

    key->len = (u8)key_len;

    return key_len;
}
