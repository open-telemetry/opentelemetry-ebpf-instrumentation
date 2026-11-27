// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

// Check just the length and the numeric MTI prefix on the unknown-TCP hot path.
// Go validates the exchange after the other protocol detectors have seen it.
static __always_inline bool iso8583_numeric_mti(const unsigned char *mti) {
    enum { k_version_2003 = 2, k_max_digit = 9 };
    if (mti[0] >= '0') {
        const bool valid_version = mti[0] <= '0' + k_version_2003;
        const bool numeric_class = mti[1] >= '0' && mti[1] <= '9';
        const bool numeric_function = mti[2] >= '0' && mti[2] <= '9';
        const bool numeric_origin = mti[3] >= '0' && mti[3] <= '9';
        return valid_version && numeric_class && numeric_function && numeric_origin;
    }

    const u8 version = mti[0] >> 4;
    const u8 message_class = mti[0] & 0xf;
    const u8 function = mti[1] >> 4;
    const u8 origin = mti[1] & 0xf;
    const bool valid_version = version <= k_version_2003;
    const bool numeric_class = message_class <= k_max_digit;
    const bool numeric_function = function <= k_max_digit;
    const bool numeric_origin = origin <= k_max_digit;

    return valid_version && numeric_class && numeric_function && numeric_origin;
}

static __always_inline bool iso8583_framed_write(const unsigned char *data, int len) {
    enum { k_min_body = 2 + 8 }; // packed MTI and primary bitmap
    if (len < 2 + k_min_body) {
        return false;
    }
    const u32 size = ((u32)data[0] << 8) | data[1];
    const u32 binary_body_len = (u32)len - 2;
    const bool valid_binary_length = size >= k_min_body && size <= binary_body_len;

    if (valid_binary_length) {
        const bool numeric_mti = iso8583_numeric_mti(data + 2);
        if (numeric_mti) {
            return true;
        }
    }
    u32 ascii_size = 0;
    for (u8 i = 0; i < 4; ++i) {
        const bool numeric = data[i] >= '0' && data[i] <= '9';
        if (!numeric) {
            return false;
        }
        ascii_size = ascii_size * 10 + data[i] - '0';
    }

    const u32 ascii_body_len = (u32)len - 4;
    const bool valid_ascii_length = ascii_size >= k_min_body && ascii_size <= ascii_body_len;
    if (!valid_ascii_length) {
        return false;
    }

    return iso8583_numeric_mti(data + 4);
}
