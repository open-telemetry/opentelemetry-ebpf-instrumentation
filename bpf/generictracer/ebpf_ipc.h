#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/utils.h>

#include <common/scratch_mem.h>

#include <logger/bpf_dbg.h>

#include <maps/nodejs_fd_map.h>

enum { k_ebpf_ipc_magic = 0xbe14be14 };

typedef enum ev_type : u8 {
    IPC_EV_NODEJS,
} ev_type;

typedef struct ipc_header_t {
    u32 marker;
    ev_type type;
    u8 size;
    u8 _pad[2];
} ipc_header;

typedef struct nodejs_ev_t {
    ipc_header hdr;
    u32 serverFD;
    u32 clientFD;
    u8 _pad[3];
    u8 crc;
} nodejs_ev;

typedef union ipc_buffer_t {
    ipc_header hdr;
    nodejs_ev njs;
} ipc_buffer;

SCRATCH_MEM(ipc_buffer)

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

static __always_inline int handle_ev_nodejs(const ipc_buffer *ev) {
    const size_t ev_size = sizeof(nodejs_ev);

    bpf_dbg_printk("checking for node ipc event size=%u, expected = %llu", ev->hdr.size, ev_size);

    if (ev->hdr.size != ev_size) {
        return 0;
    }

    const u8 crc = crc8((const unsigned char *)ev, ev_size);

    bpf_dbg_printk("calculated CRC = %u", crc);

    if (crc != 0) {
        return 0;
    }

    const s32 serverFD = bpf_ntohl(ev->njs.serverFD);
    const s32 clientFD = bpf_ntohl(ev->njs.clientFD);
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
    // events don't usually share buffers with other traffic, so the following
    // sanity check ensures we bail early if the buffer is unlikely to contain
    // an event
    if (buf_size < sizeof(ipc_header) || buf_size > sizeof(ipc_buffer)) {
        return 0;
    }

    ipc_buffer *ev = ipc_buffer_mem();

    if (!ev) {
        return 0;
    }

    bpf_clamp_umax(buf_size, sizeof(ipc_buffer));

    if (bpf_probe_read(ev, buf_size, buf) != 0) {
        return 0;
    }

    const u32 marker = bpf_ntohl(ev->hdr.marker);

    if (marker != k_ebpf_ipc_magic) {
        return 0;
    }

    switch (ev->hdr.type) {
    case IPC_EV_NODEJS:
        return handle_ev_nodejs(ev);
    }

    return 0;
}
