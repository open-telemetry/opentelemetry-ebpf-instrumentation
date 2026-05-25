// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build obi_bpf_ignore

#include <bpfcore/utils.h>

#include <common/common.h>
#include <common/ringbuf.h>
#include <common/scratch_mem.h>

#include <gotracer/go_common.h>
#include <gotracer/go_str.h>

#include <gotracer/maps/ongoing_openai_requests.h>

#include <logger/bpf_dbg.h>

#include <shared/obi_ctx.h>

SCRATCH_MEM_TYPED(openai_scratch, openai_go_req_t);

enum : u32 {
    k_openai_body_sp_offset = 8,
};

enum : u32 {
    k_openai_msg_union_size = 64,
    k_openai_msg_union_ptr_count = 6,
    k_openai_max_messages = 4096,
};

// Index of each OfXxx pointer inside ChatCompletionMessageParamUnion.
enum : u32 {
    k_openai_msg_idx_of_developer = 0,
    k_openai_msg_idx_of_system = 1,
    k_openai_msg_idx_of_user = 2,
    k_openai_msg_idx_of_assistant = 3,
    k_openai_msg_idx_of_tool = 4,
    k_openai_msg_idx_of_function = 5,
};

// Reads the Content string of the last ChatCompletionMessageParamUnion in the
// Messages slice and stores it (with its role) into req.
static __always_inline void
read_last_input_message(off_table_t *ot, const void *body_ptr, openai_go_req_t *req) {
    const u64 messages_off = go_offset_of(ot, (go_offset){.v = _openai_chat_params_messages_pos});

    void *msgs_arr = NULL;
    if (bpf_probe_read_user(&msgs_arr, sizeof(msgs_arr), (void *)body_ptr + messages_off) != 0) {
        bpf_dbg_printk("can't read openai messages array");
        return;
    }

    u64 msgs_len = 0;
    if (bpf_probe_read_user(&msgs_len,
                            sizeof(msgs_len),
                            (void *)body_ptr + messages_off + k_go_slice_len_offset) != 0) {
        bpf_dbg_printk("can't read openai messages len");
        return;
    }

    if (!msgs_arr || msgs_len == 0) {
        return;
    }

    u64 last_idx = msgs_len - 1;
    bpf_clamp_umax(last_idx, k_openai_max_messages);

    void *last_msg_addr = (unsigned char *)msgs_arr + last_idx * k_openai_msg_union_size;

    void *of_ptrs[k_openai_msg_union_ptr_count] = {};
    if (bpf_probe_read_user(of_ptrs, sizeof(of_ptrs), last_msg_addr) != 0) {
        bpf_dbg_printk("can't read openai message union pointers");
        return;
    }

    void *msg_ptr = NULL;
    u8 role = k_openai_role_unknown;

    if (of_ptrs[k_openai_msg_idx_of_user]) {
        msg_ptr = of_ptrs[k_openai_msg_idx_of_user];
        role = k_openai_role_user;
    } else if (of_ptrs[k_openai_msg_idx_of_system]) {
        msg_ptr = of_ptrs[k_openai_msg_idx_of_system];
        role = k_openai_role_system;
    } else if (of_ptrs[k_openai_msg_idx_of_assistant]) {
        msg_ptr = of_ptrs[k_openai_msg_idx_of_assistant];
        role = k_openai_role_assistant;
    } else if (of_ptrs[k_openai_msg_idx_of_developer]) {
        msg_ptr = of_ptrs[k_openai_msg_idx_of_developer];
        role = k_openai_role_developer;
    } else if (of_ptrs[k_openai_msg_idx_of_tool]) {
        msg_ptr = of_ptrs[k_openai_msg_idx_of_tool];
        role = k_openai_role_tool;
    } else if (of_ptrs[k_openai_msg_idx_of_function]) {
        msg_ptr = of_ptrs[k_openai_msg_idx_of_function];
        role = k_openai_role_function;
    }

    if (!msg_ptr) {
        return;
    }

    req->input_message_role = role;

    read_go_str("openai request message content",
                msg_ptr,
                0,
                req->input_message_content,
                sizeof(req->input_message_content));

    bpf_dbg_printk("openai request message role=%d content=[%s]",
                   req->input_message_role,
                   req->input_message_content);
}

// Reads the response Choices[0].Message.Content into req->output_message_content.
static __always_inline void
read_first_output_choice(off_table_t *ot, void *resp_ptr, openai_go_req_t *req) {
    const u64 choices_off = go_offset_of(ot, (go_offset){.v = _openai_chat_completion_choices_pos});
    const u64 choice_message_off =
        go_offset_of(ot, (go_offset){.v = _openai_chat_completion_choice_message_pos});
    const u64 message_content_off =
        go_offset_of(ot, (go_offset){.v = _openai_chat_completion_message_content_pos});

    void *choices_arr = NULL;
    if (bpf_probe_read_user(&choices_arr, sizeof(choices_arr), resp_ptr + choices_off) != 0) {
        bpf_dbg_printk("can't read openai choices array");
        return;
    }

    u64 choices_len = 0;
    if (bpf_probe_read_user(&choices_len,
                            sizeof(choices_len),
                            resp_ptr + choices_off + k_go_slice_len_offset) != 0) {
        bpf_dbg_printk("can't read openai choices len");
        return;
    }

    if (!choices_arr || choices_len == 0) {
        return;
    }

    unsigned char *content_hdr =
        (unsigned char *)choices_arr + choice_message_off + message_content_off;
    read_go_str("openai response message content",
                content_hdr,
                0,
                req->output_message_content,
                sizeof(req->output_message_content));

    bpf_dbg_printk("openai response message content=[%s]", req->output_message_content);
}

// github.com/openai/openai-go/v3.(*ChatCompletionService).New
SEC("uprobe/openai_chat_new")
int obi_uprobe_openai_chat_new(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/openai_chat_new goroutine_addr=%lx ===", goroutine_addr);

    openai_go_req_t *req = openai_scratch_mem();
    if (!req) {
        return 0;
    }
    __builtin_memset(req, 0, sizeof(openai_go_req_t));

    off_table_t *ot = get_offsets_table();

    const void *body_ptr = (const void *)PT_REGS_SP(ctx) + k_openai_body_sp_offset;

    req->type = EVENT_GO_OPENAI;
    req->start_monotime_ns = bpf_ktime_get_ns();
    req->input_message_role = k_openai_role_unknown;

    client_trace_parent(goroutine_addr, &req->tp);

    const u64 model_off = go_offset_of(ot, (go_offset){.v = _openai_chat_params_model_pos});

    read_go_str("openai request model",
                (void *)body_ptr,
                model_off,
                req->request_model,
                sizeof(req->request_model));

    bpf_dbg_printk("openai request model=[%s]", req->request_model);

    read_last_input_message(ot, body_ptr, req);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);
    bpf_map_update_elem(&ongoing_openai_requests, &g_key, req, BPF_ANY);

    obi_ctx__set(bpf_get_current_pid_tgid(), &req->tp);

    return 0;
}

// Return probe for github.com/openai/openai-go/v3.(*ChatCompletionService).New
SEC("uprobe/openai_chat_new_ret")
int obi_uprobe_openai_chat_new_ret(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/openai_chat_new_ret goroutine_addr=%lx ===", goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    openai_go_req_t *req = bpf_map_lookup_elem(&ongoing_openai_requests, &g_key);
    if (!req) {
        return 0;
    }

    void *resp_ptr = GO_PARAM1(ctx);
    bpf_dbg_printk("openai resp_ptr=%llx", resp_ptr);

    if (resp_ptr) {
        off_table_t *ot = get_offsets_table();

        const u64 id_off = go_offset_of(ot, (go_offset){.v = _openai_chat_completion_id_pos});
        const u64 model_off = go_offset_of(ot, (go_offset){.v = _openai_chat_completion_model_pos});
        const u64 usage_off = go_offset_of(ot, (go_offset){.v = _openai_chat_completion_usage_pos});
        const u64 comp_tokens_off =
            go_offset_of(ot, (go_offset){.v = _openai_completion_usage_completion_tokens_pos});
        const u64 prompt_tokens_off =
            go_offset_of(ot, (go_offset){.v = _openai_completion_usage_prompt_tokens_pos});

        read_go_str(
            "openai response id", resp_ptr, id_off, req->response_id, sizeof(req->response_id));

        read_go_str("openai response model",
                    resp_ptr,
                    model_off,
                    req->response_model,
                    sizeof(req->response_model));

        const void *usage_ptr = resp_ptr + usage_off;

        if (bpf_probe_read_user(&req->completion_tokens,
                                sizeof(req->completion_tokens),
                                usage_ptr + comp_tokens_off) != 0) {
            bpf_dbg_printk("can't read openai completion_tokens");
        }
        if (bpf_probe_read_user(&req->prompt_tokens,
                                sizeof(req->prompt_tokens),
                                usage_ptr + prompt_tokens_off) != 0) {
            bpf_dbg_printk("can't read openai prompt_tokens");
        }

        bpf_dbg_printk("openai response_id=[%s] model=[%s]", req->response_id, req->response_model);
        bpf_dbg_printk("openai prompt_tokens=%lld completion_tokens=%lld",
                       req->prompt_tokens,
                       req->completion_tokens);

        read_first_output_choice(ot, resp_ptr, req);
    }

    req->end_monotime_ns = bpf_ktime_get_ns();
    task_pid(&req->pid);
    bpf_ringbuf_output(&events, req, sizeof(openai_go_req_t), get_flags());

    bpf_map_delete_elem(&ongoing_openai_requests, &g_key);
    obi_ctx__del(bpf_get_current_pid_tgid());

    return 0;
}
