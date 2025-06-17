#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>

#include <logger/bpf_dbg.h>

#include <maps/nodejs_fd_map.h>

enum { k_ebpf_ipc_magic = 0xbe14be14 };

typedef enum ev_type : u8 {
    IPC_EV_NODEJS,
} ev_type;

struct ipc_header_t {
    u32 marker;
    ev_type type;
    u8 size;
    u8 _pad[2];
};

struct nodejs_ev_t {
    struct ipc_header_t hdr;
    u32 serverFD;
    u32 clientFD;
    u8 _pad[3];
    u8 crc;
};

static __always_inline uint8_t crc8(const unsigned char *data, u8 size) {
    const u8 polynomial = 0x07;

    u8 crc = 0x0;

#pragma clang loop unroll(full)
    for (u8 i = 0; i < size; ++i) {
        crc ^= data[i];

        for (u8 bit = 0; bit < 8; ++bit) {
            if (crc & 0x80) {
                crc = (crc << 1) ^ polynomial;
            } else {
                crc <<= 1;
            }
        }
    }

    return crc;
}

static __always_inline int handle_ev_nodejs(const struct ipc_header_t *hdr, size_t buf_size) {
    const size_t ev_size = sizeof(struct nodejs_ev_t);

    bpf_dbg_printk("checking for node ipc event size=%u, buf_size=%u", hdr->size, buf_size);

    if (hdr->size != ev_size || buf_size < ev_size) {
        return 0;
    }

    const struct nodejs_ev_t *ev = (const struct nodejs_ev_t *)hdr;

    const u8 crc = crc8((const unsigned char *)ev, sizeof(*ev));

    bpf_dbg_printk("calculated CRC = %u", crc);

    if (crc != 0) {
        return 0;
    }

    const s32 serverFD = bpf_ntohl(ev->serverFD);
    const s32 clientFD = bpf_ntohl(ev->clientFD);
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const u64 key = (pid_tgid << 32) | clientFD;

    bpf_map_update_elem(&nodejs_fd_map, &key, &serverFD, BPF_ANY);

    bpf_dbg_printk(
        "[ebpf_ipc_node] pid=%u, serverFD=%d, clientFD=%d", pid_tgid, serverFD, clientFD);

    return 1;
}

// at the moment, this is only used by the nodejs agent (fdextractor) to
// communicate the file descriptors of the incoming and outgoing calls - this
// could be extended in the future (and potentially become a tail call target)
static __always_inline int handle_ebpf_ipc(const void *buf, size_t buf_size) {
    if (buf_size < sizeof(struct ipc_header_t)) {
        return 0;
    }

    const struct ipc_header_t *hdr = (const struct ipc_header_t *)buf;
    const u32 marker = bpf_ntohl(hdr->marker);

    if (marker != k_ebpf_ipc_magic) {
        return 0;
    }

    switch (hdr->type) {
    case IPC_EV_NODEJS:
        return handle_ev_nodejs(hdr, buf_size);
    }

    return 0;
}
