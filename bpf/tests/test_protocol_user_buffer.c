// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <assert.h>
#include <stdio.h>

#include <common/http_types.h>

int main(void) {
    const unsigned char request[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const u32 len = sizeof(request) - 1;
    call_protocol_args_t args = {.bytes_len = len};

    set_protocol_user_buffer(&args, request, len);
    assert(args.user_buf == 0 && "complete captures must scan their copy, not user memory");
    assert(args.user_len == 0);
    assert(args.source_buf == (u64)request && args.source_len == len);

    args.bytes_len = len - 1;
    set_protocol_user_buffer(&args, request, len);
    assert(args.user_buf == (u64)request && args.user_len == len);
    assert(args.source_buf == (u64)request && args.source_len == len);

    args.bytes_len = len;
    set_protocol_user_buffer(&args, request, len);
    assert(args.user_buf == 0 && args.user_len == 0);
    assert(args.source_buf == (u64)request && args.source_len == len);

    set_protocol_user_buffer(&args, NULL, len);
    assert(args.user_buf == 0 && args.user_len == 0);
    assert(args.source_buf == 0 && args.source_len == 0);

    puts("Protocol capture separates truncation from original user-buffer metadata");
    return 0;
}
