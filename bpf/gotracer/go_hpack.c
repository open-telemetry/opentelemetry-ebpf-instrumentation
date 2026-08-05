// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/globals.h>

#include <gotracer/go_common.h>
#include <gotracer/go_hpack.h>
#include <gotracer/maps/hpack.h>

#include <logger/bpf_dbg.h>

SEC("uprobe/hpackEncoderWriteField")
int obi_uprobe_hpackEncoderWriteField(struct pt_regs *ctx) {
    if (!g_bpf_header_propagation) {
        return 0;
    }

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    go_addr_key_t key = {};
    go_addr_key_from_id(&key, goroutine_addr);

    const unsigned char *name_ptr = (const unsigned char *)GO_PARAM2(ctx);
    const u64 name_len = (u64)GO_PARAM3(ctx);

    go_hpack_block_t block = {};
    read_go_hpack_traceparent(&key, &block);

    unsigned char first = 0;
    if (name_len && (!name_ptr || bpf_probe_read_user(&first, sizeof(first), name_ptr))) {
        clear_go_hpack_traceparent(&key);
        return 0;
    }
    if (name_ptr && name_len && go_hpack_starts_header_block(&first, 1)) {
        unsigned char pseudo_name[k_go_hpack_authority_name_len] = {};
        if (name_len == k_go_hpack_method_name_len) {
            if (bpf_probe_read_user(pseudo_name, k_go_hpack_method_name_len, name_ptr)) {
                clear_go_hpack_traceparent(&key);
                return 0;
            }
        } else if (name_len == k_go_hpack_authority_name_len) {
            if (bpf_probe_read_user(pseudo_name, k_go_hpack_authority_name_len, name_ptr)) {
                clear_go_hpack_traceparent(&key);
                return 0;
            }
        } else {
            return 0;
        }

        const u8 transition = go_hpack_observe_pseudo_header(&block, pseudo_name, name_len);
        if (transition == k_go_hpack_block_store) {
            replace_go_hpack_traceparent(&key, &block);
        } else if (transition == k_go_hpack_block_clear) {
            clear_go_hpack_traceparent(&key);
        }
        return 0;
    }

    if (name_len != k_go_hpack_traceparent_name_len || !name_ptr) {
        return 0;
    }

    unsigned char name[k_go_hpack_traceparent_name_len];
    if (bpf_probe_read_user(name, sizeof(name), name_ptr)) {
        clear_go_hpack_traceparent(&key);
        return 0;
    }
    if (!go_hpack_is_traceparent_name(name, sizeof(name))) {
        return 0;
    }

    const u64 value_len = (u64)GO_PARAM5(ctx);
    const unsigned char *value_ptr = (const unsigned char *)GO_PARAM4(ctx);
    if (value_len < k_go_hpack_traceparent_value_len || !value_ptr) {
        const u8 classification =
            go_hpack_capture_traceparent(&block, name, name_len, NULL, value_len);
        if (classification != k_go_hpack_traceparent_unknown) {
            replace_go_hpack_traceparent(&key, &block);
        }
        if (block.state != k_go_hpack_block_request) {
            clear_go_hpack_traceparent(&key);
        }
        return 0;
    }

    unsigned char value[k_go_hpack_traceparent_value_len + 1] = {};
    if (bpf_probe_read_user(value, k_go_hpack_traceparent_value_len, value_ptr)) {
        go_hpack_capture_traceparent(&block, name, name_len, NULL, value_len);
        replace_go_hpack_traceparent(&key, &block);
        return 0;
    }
    if (value_len > k_go_hpack_traceparent_value_len &&
        bpf_probe_read_user(value + k_go_hpack_traceparent_value_len,
                            1,
                            value_ptr + k_go_hpack_traceparent_value_len)) {
        go_hpack_capture_traceparent(&block, name, name_len, NULL, value_len);
        replace_go_hpack_traceparent(&key, &block);
        return 0;
    }

    const u8 classification =
        go_hpack_capture_traceparent(&block, name, name_len, value, value_len);
    if (classification == k_go_hpack_traceparent_unknown) {
        if (block.state != k_go_hpack_block_request) {
            clear_go_hpack_traceparent(&key);
        }
        return 0;
    }

    replace_go_hpack_traceparent(&key, &block);
    return 0;
}
