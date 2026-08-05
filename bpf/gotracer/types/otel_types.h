// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// This implementation copied from https://github.com/open-telemetry/opentelemetry-go-instrumentation/blob/main/internal/include/otel_types.h
// and has been adapted to OBI.

#ifndef _OTEL_TYPES_H
#define _OTEL_TYPES_H

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/common.h>

volatile const u64 attr_type_invalid;

volatile const u64 attr_type_bool;
volatile const u64 attr_type_int64;
volatile const u64 attr_type_float64;
volatile const u64 attr_type_string;

volatile const u64 attr_type_boolslice;
volatile const u64 attr_type_int64slice;
volatile const u64 attr_type_float64slice;
volatile const u64 attr_type_stringslice;

static const unsigned char k_http_route_key[] = "http.route";
static const unsigned char k_service_peer_name_key[] = "service.peer.name";
static const unsigned char k_network_peer_address_key[] = "network.peer.address";
static const unsigned char k_server_address_key[] = "server.address";
static const unsigned char k_client_address_key[] = "client.address";
static const otel_attribute_t k_empty_otel_attribute = {};
static const unsigned char k_empty_otel_route[OTEL_ATTRIBUTE_VALUE_MAX_LEN] = {};

enum go_otel_special_attr : u8 {
    k_go_otel_special_attr_none = 0,
    k_go_otel_special_attr_route = 1 << 0,
    k_go_otel_special_attr_service_peer_name = 1 << 1,
    k_go_otel_special_attr_network_peer_address = 1 << 2,
    k_go_otel_special_attr_remote_address = 1 << 3,
};

enum go_otel_special_attr_state : u8 {
    k_go_otel_special_attr_unset = 0,
    k_go_otel_special_attr_invalid = 1,
    k_go_otel_special_attr_valid = 2,
};

static __always_inline u8 go_otel_special_attr_from_key(const unsigned char *key,
                                                        u64 key_len,
                                                        u8 span_kind) {
    if (key_len == sizeof(k_http_route_key) - 1 &&
        __builtin_memcmp(key, k_http_route_key, sizeof(k_http_route_key) - 1) == 0) {
        return k_go_otel_special_attr_route;
    }
    if (span_kind == k_otel_span_kind_internal) {
        return k_go_otel_special_attr_none;
    }
    if (key_len == sizeof(k_service_peer_name_key) - 1 &&
        __builtin_memcmp(key, k_service_peer_name_key, sizeof(k_service_peer_name_key) - 1) == 0) {
        return k_go_otel_special_attr_service_peer_name;
    }
    if (key_len == sizeof(k_network_peer_address_key) - 1 &&
        __builtin_memcmp(key, k_network_peer_address_key, sizeof(k_network_peer_address_key) - 1) ==
            0) {
        return k_go_otel_special_attr_network_peer_address;
    }
    if ((span_kind == k_otel_span_kind_client || span_kind == k_otel_span_kind_producer) &&
        key_len == sizeof(k_server_address_key) - 1 &&
        __builtin_memcmp(key, k_server_address_key, sizeof(k_server_address_key) - 1) == 0) {
        return k_go_otel_special_attr_remote_address;
    }
    if ((span_kind == k_otel_span_kind_server || span_kind == k_otel_span_kind_consumer) &&
        key_len == sizeof(k_client_address_key) - 1 &&
        __builtin_memcmp(key, k_client_address_key, sizeof(k_client_address_key) - 1) == 0) {
        return k_go_otel_special_attr_remote_address;
    }
    return k_go_otel_special_attr_none;
}

static __always_inline u8 required_go_otel_special_attrs(u8 span_kind) {
    if (span_kind == k_otel_span_kind_internal) {
        return k_go_otel_special_attr_route;
    }
    return k_go_otel_special_attr_route | k_go_otel_special_attr_service_peer_name |
           k_go_otel_special_attr_network_peer_address | k_go_otel_special_attr_remote_address;
}

static __noinline u8 capture_go_otel_special_attr(go_otel_key_value_t *go_attr,
                                                  otel_span_t *span,
                                                  u8 found) {
    if (!go_attr || !span) {
        return k_go_otel_special_attr_none;
    }

    struct go_string go_key = {};
    if (bpf_probe_read_user(&go_key, sizeof(go_key), &go_attr->key) != 0 ||
        go_key.len > sizeof(k_network_peer_address_key) - 1) {
        return k_go_otel_special_attr_none;
    }

    unsigned char key[OTEL_ATTRIBUTE_KEY_MAX_LEN] = {};
    if (bpf_probe_read_user(key, go_key.len & (OTEL_ATTRIBUTE_KEY_MAX_LEN - 1), go_key.str) != 0) {
        return k_go_otel_special_attr_none;
    }

    const u8 special_attr = go_otel_special_attr_from_key(key, go_key.len, span->span_kind);
    if (special_attr == k_go_otel_special_attr_none || (found & special_attr)) {
        return k_go_otel_special_attr_none;
    }

    unsigned char *value;
    u8 *state;
    switch (special_attr) {
    case k_go_otel_special_attr_route:
        value = span->route;
        state = &span->route_state;
        break;
    case k_go_otel_special_attr_service_peer_name:
        value = span->service_peer_name;
        state = &span->service_peer_name_state;
        break;
    case k_go_otel_special_attr_network_peer_address:
        value = span->network_peer_address;
        state = &span->network_peer_address_state;
        break;
    case k_go_otel_special_attr_remote_address:
        value = span->remote_address;
        state = &span->remote_address_state;
        break;
    default:
        return k_go_otel_special_attr_none;
    }

    bpf_probe_read_kernel(value, OTEL_ATTRIBUTE_VALUE_MAX_LEN, &k_empty_otel_route);
    *state = k_go_otel_special_attr_invalid;

    go_otel_attr_value_t go_value = {};
    if (bpf_probe_read_user(&go_value, sizeof(go_value), &go_attr->value) == 0 &&
        go_value.vtype == attr_type_string && go_value.string.len < OTEL_ATTRIBUTE_VALUE_MAX_LEN) {
        const u64 value_len = go_value.string.len & (OTEL_ATTRIBUTE_VALUE_MAX_LEN - 1);
        if (!value_len || bpf_probe_read_user(value, value_len, go_value.string.str) == 0) {
            *state = k_go_otel_special_attr_valid;
        }
    }
    return special_attr;
}

static __always_inline bool set_attr_value(otel_attribute_t *attr,
                                           go_otel_attr_value_t *go_attr_value) {
    const u64 vtype = go_attr_value->vtype;

    // Constant size values
    if (vtype == attr_type_bool || vtype == attr_type_int64 || vtype == attr_type_float64) {
        bpf_probe_read(attr->value, sizeof(s64), &go_attr_value->numeric);
        return true;
    }

    // String values
    if (vtype == attr_type_string) {
        if (go_attr_value->string.len >= OTEL_ATTRIBUTE_VALUE_MAX_LEN) {
            return false;
        }
        const long res =
            bpf_probe_read_user(attr->value,
                                go_attr_value->string.len & (OTEL_ATTRIBUTE_VALUE_MAX_LEN - 1),
                                go_attr_value->string.str);
        return res == 0;
    }

    // TODO (#525): handle slices
    return false;
}

enum { k_go_otel_max_attribute_scan = 128 };

static __always_inline void
convert_go_otel_attributes(void *attrs_buf, u64 slice_len, otel_attributes_t *enc_attrs) {
    if (attrs_buf == NULL || slice_len < 1) {
        return;
    }

    go_otel_key_value_t *go_attr = (go_otel_key_value_t *)attrs_buf;
    u8 valid_attrs = enc_attrs->valid_attrs;

    for (u8 go_attr_index = 0; go_attr_index < OTEL_ATTRIBUTE_MAX_COUNT; go_attr_index++) {
        if (go_attr_index >= slice_len) {
            break;
        }
        if (valid_attrs >= OTEL_ATTRIBUTE_MAX_COUNT) {
            break;
        }

        go_otel_attr_value_t go_attr_value = {};
        if (bpf_probe_read_user(
                &go_attr_value, sizeof(go_otel_attr_value_t), &go_attr[go_attr_index].value) != 0 ||
            go_attr_value.vtype == attr_type_invalid) {
            continue;
        }

        struct go_string go_str = {};
        if (bpf_probe_read_user(&go_str, sizeof(struct go_string), &go_attr[go_attr_index].key) !=
                0 ||
            go_str.len >= OTEL_ATTRIBUTE_KEY_MAX_LEN) {
            continue;
        }

        u8 attr_index = valid_attrs;
        bpf_clamp_umax(attr_index, OTEL_ATTRIBUTE_MAX_COUNT - 1);
        if (bpf_probe_read_kernel(&enc_attrs->attrs[attr_index],
                                  sizeof(enc_attrs->attrs[attr_index]),
                                  &k_empty_otel_attribute) != 0) {
            continue;
        }
        bpf_probe_read_user(enc_attrs->attrs[attr_index].key,
                            go_str.len & (OTEL_ATTRIBUTE_KEY_MAX_LEN - 1),
                            go_str.str);

        if (!set_attr_value(&enc_attrs->attrs[attr_index], &go_attr_value)) {
            continue;
        }

        enc_attrs->attrs[attr_index].vtype = go_attr_value.vtype;
        valid_attrs++;
    }

    enc_attrs->valid_attrs = valid_attrs;
}

#endif
