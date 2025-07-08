#pragma once

#include <logger/bpf_dbg.h>
#include <common/tc_common.h>
#include <common/common.h>
#include <common/strings.h>
#include <gotracer/go_common.h>

static const char k_jsonrpc_key[] = "\"jsonrpc\"";
static const u32 k_jsonrpc_key_len = sizeof(k_jsonrpc_key) - 1;
static const char k_jsonrpc_val[] = "\"2.0\"";
static const u32 k_jsonrpc_val_len = sizeof(k_jsonrpc_val) - 1;
static const char k_application_json[] = "application/json";
static const u32 k_application_json_len = sizeof(k_application_json) - 1;
static const char k_method_key[] = "\"method\"";
static const u32 k_method_key_len = sizeof(k_method_key) - 1;

enum { JSON_MAX_STRING_LEN = 16, JSONRPC_METHOD_BUF_SIZE = 16 };

// should match application/json, application/json-rpc, application/jsonrequest
// listed in https://www.jsonrpc.org/historical/json-rpc-over-http.html
static __always_inline u8 is_json_content_type(const char *c, u32 len) {
    if (len < k_application_json_len) {
        return 0;
    }
    // Check for "application/json" at the start
    if (c[0] == 'a' && c[1] == 'p' && c[2] == 'p' && c[3] == 'l' && c[4] == 'i' && c[5] == 'c' &&
        c[6] == 'a' && c[7] == 't' && c[8] == 'i' && c[9] == 'o' && c[10] == 'n' && c[11] == '/' &&
        c[12] == 'j' && c[13] == 's' && c[14] == 'o' && c[15] == 'n') {
        return 1;
    }
    return 0;
}

// ref: https://en.cppreference.com/w/c/string/byte/isspace
static __always_inline u8 bpf_isspace(char c) {
    return (c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v');
}

// Returns the offset of the next JSON value after skipping whitespace and colon.
// If not found, returns body_len.
static __always_inline u32 json_value_offset(const unsigned char *body,
                                             u32 body_len,
                                             u32 start_pos) {
    u32 pos = start_pos;
    while (pos < body_len && (bpf_isspace(body[pos]) || body[pos] == ':')) {
        pos++;
    }
    return pos;
}

// Returns the position of the first occurrence of a string in a JSON body.
// If not found, returns INVALID_POS.
static __always_inline u32 json_str_value(const unsigned char *body,
                                          u32 body_len,
                                          const unsigned char *str,
                                          u32 str_len) {
    return bpf_memstr(body, body_len, str, str_len);
}

// Compares a JSON value at start with a given value.
static __always_inline bool json_value_eq(const char *start, const char *val, u32 val_len) {

    return stricmp(start, val, val_len);
}

// Extracts a JSON string value starting at a given position.
// Copies up to buf_len-1 bytes into buf, null-terminated.
// Returns the number of bytes copied (not including null terminator), or 0 on error.
static __always_inline u32 extract_json_string(
    const unsigned char *body, u32 body_len, u32 value_start, unsigned char *buf, u32 buf_len) {
    if (value_start >= body_len || buf_len == 0) {
        return 0;
    }

    if (body[value_start] != '"') {
        return 0;
    }

    const u32 str_start = value_start + 1;
    u32 value_end = str_start;
    while (value_end < body_len && body[value_end] != '"') {
        value_end++;
    }
    const u32 value_len = value_end - str_start;
    if (value_len == 0) {
        return 0;
    }

    const u32 copy_len = value_len < (buf_len - 1) ? value_len : (buf_len - 1);

    for (u32 i = 0; i < buf_len; i++) {
        if (i >= copy_len) {
            break;
        }
        buf[i] = body[str_start + i];
    }
    buf[copy_len] = '\0';
    return copy_len;
}

// Looks for '"jsonrpc":"2.0"'
static __always_inline u32 is_jsonrpc2_body(const unsigned char *body, u32 body_len) {
    u32 key_pos =
        json_str_value(body, body_len, (const unsigned char *)k_jsonrpc_key, k_jsonrpc_key_len);
    if (key_pos == INVALID_POS) {
        return 0;
    }

    bpf_dbg_printk("Found JSON-RPC 2.0 key");

    u32 val_search_start = key_pos + k_jsonrpc_key_len;
    if (val_search_start >= body_len) {
        return 0;
    }

    val_search_start = json_value_offset(body, body_len, val_search_start);
    if (val_search_start >= body_len) {
        return 0;
    }

    if (val_search_start + k_jsonrpc_val_len >= body_len) {
        return 0;
    }

    if (!json_value_eq((const char *)(body + val_search_start),
                       (const char *)k_jsonrpc_val,
                       k_jsonrpc_val_len)) {
        return 0;
    }

    bpf_dbg_printk("Found JSON-RPC 2.0 value");

    return 1; // JSON-RPC 2.0 detected
}

// Extracts the value of the "method" key from a JSON-RPC 2.0 body.
// Returns the length of the method value, or 0 if not found or error.
// method_buf must be at least method_buf_len bytes.
static __always_inline u32 extract_jsonrpc2_method(const unsigned char *body,
                                                   u32 body_len,
                                                   unsigned char *method_buf,
                                                   u32 method_buf_len) {
    u32 key_pos =
        json_str_value(body, body_len, (const unsigned char *)k_method_key, k_method_key_len);
    if (key_pos == INVALID_POS) {
        return 0;
    }

    bpf_dbg_printk("Found JSON-RPC method key");

    u32 val_search_start = key_pos + k_method_key_len;
    if (val_search_start >= body_len) {
        return 0;
    }

    val_search_start = json_value_offset(body, body_len, val_search_start);
    if (val_search_start >= body_len) {
        return 0;
    }
    return extract_json_string(body, body_len, val_search_start, method_buf, method_buf_len);
}