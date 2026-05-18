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

#include <gotracer/go_common.h>

#include <gotracer/maps/openai.h>

#include <logger/bpf_dbg.h>

#include <shared/obi_ctx.h>

// Stack offset for the body parameter in the Go register ABI calling convention.
enum : u32 {
    k_openai_body_sp_offset = 8, // body is the first stack-spilled argument (after return addr)
};

// github.com/openai/openai-go/v3.(*ChatCompletionService).New
// func (r *ChatCompletionService) New(ctx context.Context, body ChatCompletionNewParams,
//                                     opts ...option.RequestOption) (*ChatCompletion, error)
//
// Go 1.17+ register ABI (AMD64):
//   r   *ChatCompletionService -> AX  (GO_PARAM1)
//   ctx context.Context        -> BX  (GO_PARAM2) type, CX (GO_PARAM3) data
//   body ChatCompletionNewParams -> stack at SP+8 (too large for remaining registers)
//   opts ...option.RequestOption -> stack (variadic slice)
SEC("uprobe/openai_chat_new")
int obi_uprobe_openai_chat_new(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/openai_chat_new goroutine_addr=%lx ===", goroutine_addr);

    off_table_t *ot = get_offsets_table();

    const void *body_ptr = (const void *)PT_REGS_SP(ctx) + k_openai_body_sp_offset;

    openai_go_req_t req = {};
    req.type = EVENT_GO_OPENAI;
    req.start_monotime_ns = bpf_ktime_get_ns();

    client_trace_parent(goroutine_addr, &req.tp);

    const u64 model_off = go_offset_of(ot, (go_offset){.v = _openai_chat_params_model_pos});

    void *model_ptr = 0;
    u64 model_len = 0;

    if (bpf_probe_read_user(&model_ptr, sizeof(model_ptr),
                            body_ptr + model_off) == 0 &&
        bpf_probe_read_user(&model_len, sizeof(model_len),
                            body_ptr + model_off + k_go_string_len_offset) == 0 &&
        model_ptr && model_len > 0) {
        bpf_clamp_umax(model_len, k_openai_model_max_len - 1);
        bpf_probe_read_user(req.request_model, model_len, model_ptr);
    }

    bpf_dbg_printk("openai request model=[%s]", req.request_model);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);
    bpf_map_update_elem(&ongoing_openai_requests, &g_key, &req, BPF_ANY);

    obi_ctx__set(bpf_get_current_pid_tgid(), &req.tp);

    return 0;
}

// Return probe for github.com/openai/openai-go/v3.(*ChatCompletionService).New
//
// Return registers (AMD64):
//   res *ChatCompletion -> AX (GO_PARAM1)
//   err error           -> BX (GO_PARAM2) type, CX (GO_PARAM3) data
SEC("uprobe/openai_chat_new")
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

        void *id_ptr = 0;
        u64 id_len = 0;

        if (bpf_probe_read_user(&id_ptr, sizeof(id_ptr),
                                resp_ptr + id_off) == 0 &&
            bpf_probe_read_user(&id_len, sizeof(id_len),
                                resp_ptr + id_off + k_go_string_len_offset) == 0 &&
            id_ptr && id_len > 0) {
            bpf_clamp_umax(id_len, k_openai_response_id_max_len - 1);
            bpf_probe_read_user(req->response_id, id_len, id_ptr);
        }

        void *resp_model_ptr = 0;
        u64 resp_model_len = 0;

        if (bpf_probe_read_user(&resp_model_ptr, sizeof(resp_model_ptr),
                                resp_ptr + model_off) == 0 &&
            bpf_probe_read_user(&resp_model_len, sizeof(resp_model_len),
                                resp_ptr + model_off + k_go_string_len_offset) == 0 &&
            resp_model_ptr && resp_model_len > 0) {
            bpf_clamp_umax(resp_model_len, k_openai_model_max_len - 1);
            bpf_probe_read_user(req->response_model, resp_model_len, resp_model_ptr);
        }

        const void *usage_ptr = resp_ptr + usage_off;

        bpf_probe_read_user(&req->completion_tokens, sizeof(req->completion_tokens),
                            usage_ptr + comp_tokens_off);
        bpf_probe_read_user(&req->prompt_tokens, sizeof(req->prompt_tokens),
                            usage_ptr + prompt_tokens_off);

        bpf_dbg_printk("openai response_id=[%s] model=[%s]",
                       req->response_id,
                       req->response_model);
        bpf_dbg_printk("openai prompt_tokens=%lld completion_tokens=%lld",
                       req->prompt_tokens, req->completion_tokens);
    }

    openai_go_req_t *trace = bpf_ringbuf_reserve(&events, sizeof(openai_go_req_t), 0);
    if (trace) {
        __builtin_memcpy(trace, req, sizeof(openai_go_req_t));
        trace->end_monotime_ns = bpf_ktime_get_ns();
        task_pid(&trace->pid);
        bpf_ringbuf_submit(trace, get_flags());
    }

    bpf_map_delete_elem(&ongoing_openai_requests, &g_key);
    obi_ctx__del(bpf_get_current_pid_tgid());

    return 0;
}
