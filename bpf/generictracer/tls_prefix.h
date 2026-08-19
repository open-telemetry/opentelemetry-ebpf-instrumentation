// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_builtins.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/connection_info.h>
#include <common/ssl_helpers.h>
#include <common/tls_record.h>

#include <logger/bpf_dbg.h>

#include <generictracer/maps/tls_prefix_mem.h>

#include <maps/bio_to_ssl.h>
#include <maps/ssl_to_bios.h>
#include <maps/tls_prefix_to_ssl.h>

// Correlating a memory BIO TLS connection to its socket.
//
// CPython's ssl.MemoryBIO and Node's TLSWrap encrypt into a buffer that the
// event loop writes later, so the socket write lands outside any
// SSL_read/SSL_write uprobe window.
//
// Correlate on the ciphertext instead: record the leading bytes of each record
// written to the write BIO, and bind the SSL when the socket carries the same
// bytes. The ClientHello is record aligned and unique through client_random, so
// the binding is usually in place before the first application record.

enum {
    // An entry only spans the gap between the BIO write and the socket send -
    // same thread, microseconds. LRU evicts by pressure, so bound the age too.
    k_tls_prefix_max_age_ns = 1000000000ULL,
};

// Drops the BIO associations an SSL owns, if any.
static __always_inline void ssl_bios_forget(u32 pid, void *ssl) {
    const pid_ptr_key_t ssl_key = pid_ptr_key(pid, ssl);
    ssl_bios_t *bios = bpf_map_lookup_elem(&ssl_to_bios, &ssl_key);

    if (!bios) {
        return;
    }

    if (bios->rbio) {
        const pid_ptr_key_t rbio_key = pid_ptr_key(pid, (void *)bios->rbio);
        bpf_map_delete_elem(&bio_to_ssl, &rbio_key);
    }

    if (bios->wbio) {
        const pid_ptr_key_t wbio_key = pid_ptr_key(pid, (void *)bios->wbio);
        bpf_map_delete_elem(&bio_to_ssl, &wbio_key);
    }

    bpf_map_delete_elem(&ssl_to_bios, &ssl_key);
}

// Records which BIOs belong to an SSL, dropping any it owned before.
static __always_inline void ssl_bios_track(u32 pid, void *ssl, void *rbio, void *wbio) {
    // Drop the previous pair first. SSL_set_bio can be called more than once,
    // so only the current BIOs should point at this SSL.
    ssl_bios_forget(pid, ssl);

    ssl_bios_t bios = {.rbio = (u64)rbio, .wbio = (u64)wbio};

    if (bios.rbio) {
        const pid_ptr_key_t rbio_key = pid_ptr_key(pid, rbio);
        bio_ssl_info_t info = {.ssl = (u64)ssl, .is_wbio = 0};
        bpf_map_update_elem(&bio_to_ssl, &rbio_key, &info, BPF_ANY);
    }

    if (bios.wbio) {
        const pid_ptr_key_t wbio_key = pid_ptr_key(pid, wbio);
        bio_ssl_info_t info = {.ssl = (u64)ssl, .is_wbio = 1};
        bpf_map_update_elem(&bio_to_ssl, &wbio_key, &info, BPF_ANY);
    }

    const pid_ptr_key_t ssl_key = pid_ptr_key(pid, ssl);
    bpf_map_update_elem(&ssl_to_bios, &ssl_key, &bios, BPF_ANY);
}

// True while the SSL named by a bio_to_ssl entry still claims that BIO.
//
// bio_to_ssl and ssl_to_bios are independent LRUs, so the reverse entry can be
// evicted on its own. ssl_bios_forget then has nothing to follow and leaves the
// forward entries behind, and the next connection to be handed that BIO address
// would inherit the dead SSL. Eviction gives no callback to keep the pair
// together, so the forward entry is validated against the reverse instead.
static __always_inline u8 bio_owner_is_current(u32 pid,
                                               const void *bio,
                                               const bio_ssl_info_t *info) {
    const pid_ptr_key_t ssl_key = pid_ptr_key(pid, (void *)info->ssl);
    const ssl_bios_t *bios = bpf_map_lookup_elem(&ssl_to_bios, &ssl_key);

    if (!bios) {
        return 0;
    }

    return info->is_wbio ? bios->wbio == (u64)bio : bios->rbio == (u64)bio;
}

// True when this SSL has no known peer yet, so correlating is worth the work.
// A connection awaiting a peer is recorded with a zeroed destination port.
static __always_inline u8 tls_prefix_needs_binding(u64 ssl_ptr) {
    void *ssl = (void *)ssl_ptr;
    ssl_pid_connection_info_t *conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);

    return !conn || conn->orig_dport == 0;
}

// Called where OpenSSL hands one record to the connection's write BIO. `buf` is
// a user space pointer.
static __always_inline void tls_prefix_register_egress(void *bio, const void *buf, int len) {
    if (len < k_tls_hdr_len) {
        return;
    }

    const u32 pid = pid_from_pid_tgid(bpf_get_current_pid_tgid());
    const pid_ptr_key_t bio_key = pid_ptr_key(pid, bio);
    bio_ssl_info_t *info = bpf_map_lookup_elem(&bio_to_ssl, &bio_key);

    // Only a BIO named by SSL_set_bio is an endpoint of a connection; OpenSSL
    // stages the same record through internal BIOs too.
    if (!info) {
        return;
    }

    // Ownership the SSL no longer confirms cannot be trusted, and the entry
    // would outlive every connection that could correct it.
    if (!bio_owner_is_current(pid, bio, info)) {
        bpf_map_delete_elem(&bio_to_ssl, &bio_key);
        return;
    }

    // The write BIO carries what this connection sends; the read BIO carries
    // received data being pushed in.
    if (!info->is_wbio) {
        return;
    }

    if (!tls_prefix_needs_binding(info->ssl)) {
        return;
    }

    unsigned char hdr[k_tls_hdr_len];

    if (bpf_probe_read_user(hdr, sizeof(hdr), buf) != 0) {
        return;
    }

    u32 key_len = tls_record_key_len(hdr, (u32)len);

    if (key_len == 0) {
        return;
    }

    // tls_record_key_len already caps this; the clamp is here so the verifier
    // can see the bound on the read size below.
    bpf_clamp_umax(key_len, k_tls_prefix_max);

    tls_prefix_scratch_t *scratch = tls_prefix_mem();

    if (!scratch) {
        return;
    }

    bpf_memset(scratch->record, 0, sizeof(scratch->record));

    if (bpf_probe_read_user(scratch->record, key_len, buf) != 0) {
        return;
    }

    if (tls_prefix_key_from_buf(&scratch->key, scratch->record, key_len, (u32)len) == 0) {
        return;
    }

    tls_prefix_val_t val = {
        .ssl = info->ssl,
        .ts_ns = bpf_ktime_get_ns(),
        .pid = pid,
    };

    bpf_dbg_printk("tls prefix: registered %d bytes for ssl=%llx", scratch->key.len, info->ssl);

    bpf_map_update_elem(&tls_prefix_to_ssl, &scratch->key, &val, BPF_ANY);
}

// Called from the socket send path with bytes already copied out of the
// transfer, whichever buffer source produced them. `copied` is how much of the
// record `buf` holds, `avail` the size of the whole send. Returns 1 when an SSL
// was bound to this connection.
static __always_inline u8 tls_prefix_try_bind(u64 id,
                                              const unsigned char *buf,
                                              u32 copied,
                                              u32 avail,
                                              pid_connection_info_t *p_conn,
                                              u16 orig_dport) {
    // Screened before the scratch lookup: most sends are plaintext.
    if (!tls_record_plausible_start(buf, copied)) {
        return 0;
    }

    tls_prefix_scratch_t *scratch = tls_prefix_mem();

    if (!scratch) {
        return 0;
    }

    if (tls_prefix_key_from_buf(&scratch->key, buf, copied, avail) == 0) {
        return 0;
    }

    tls_prefix_val_t *val = bpf_map_lookup_elem(&tls_prefix_to_ssl, &scratch->key);

    if (!val) {
        return 0;
    }

    // The key space is global, so require the match to come from this process.
    if (val->pid != pid_from_pid_tgid(id)) {
        return 0;
    }

    if (bpf_ktime_get_ns() - val->ts_ns > k_tls_prefix_max_age_ns) {
        bpf_map_delete_elem(&tls_prefix_to_ssl, &scratch->key);
        return 0;
    }

    ssl_pid_connection_info_t ssl_conn = {0};
    ssl_conn.p_conn = *p_conn;
    ssl_conn.orig_dport = orig_dport;

    bpf_dbg_printk("tls prefix: bound ssl=%llx to connection", val->ssl);

    set_active_ssl_connection(&ssl_conn, (void *)val->ssl);
    bpf_map_delete_elem(&tls_prefix_to_ssl, &scratch->key);

    return 1;
}
