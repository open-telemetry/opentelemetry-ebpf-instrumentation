// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

// Role values stored in openai_go_req_t.input_message_role.
enum openai_role : u8 {
    k_openai_role_user = 0,
    k_openai_role_system = 1,
    k_openai_role_assistant = 2,
    k_openai_role_developer = 3,
    k_openai_role_tool = 4,
    k_openai_role_function = 5,
    k_openai_role_unknown = 0xFF,
};
