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

#include <common/ringbuf.h>

#include <gotracer/go_common.h>

#include <logger/bpf_dbg.h>

SEC("uprobe/op_coll_op")
int obi_uprobe_mongo_coll_op(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/mongo op_execute === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *coll_ptr = (void *)GO_PARAM1(ctx);
    off_table_t *ot = get_offsets_table();

    mongo_go_client_req_t req = {
        .type = EVENT_GO_MONGO,
        .start_monotime_ns = bpf_ktime_get_ns(),
    };

    if (!read_go_str("name",
                     coll_ptr,
                     go_offset_of(ot, (go_offset){.v = _mongo_conn_name_pos}),
                     &req.coll,
                     sizeof(req.coll))) {
        bpf_dbg_printk("can't read mongodb Collection.name");
        goto done;
    }

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    client_trace_parent(goroutine_addr, &req.tp);

    bpf_map_update_elem(&ongoing_mongo_requests, &g_key, &req, BPF_ANY);

done:
    return 0;
}

// go.mongodb.org/mongo-driver/x/mongo/driver.Operation.Execute
// func (op Operation) Execute(ctx context.Context) error
SEC("uprobe/op_execute")
int obi_uprobe_mongo_op_execute(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/mongo op_execute === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *op_ptr = (void *)PT_REGS_SP(ctx) + 8;
    off_table_t *ot = get_offsets_table();

    mongo_go_client_req_t fresh_req = {
        .type = EVENT_GO_MONGO,
        .start_monotime_ns = bpf_ktime_get_ns(),
    };

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    mongo_go_client_req_t *req = bpf_map_lookup_elem(&ongoing_mongo_requests, &g_key);

    if (!req) {
        client_trace_parent(goroutine_addr, &fresh_req.tp);
        req = &fresh_req;
    }

    if (!req) {
        goto done;
    }

    bpf_dbg_printk("op_ptr %llx", op_ptr);

    if (!read_go_str("name",
                     op_ptr,
                     go_offset_of(ot, (go_offset){.v = _mongo_op_name_pos}),
                     &req->op,
                     sizeof(req->op))) {
        bpf_dbg_printk("can't read mongodb Operation.Name");
        goto done;
    }

    if (!read_go_str("database",
                     op_ptr,
                     go_offset_of(ot, (go_offset){.v = _mongo_db_name_pos}),
                     &req->db,
                     sizeof(req->db))) {
        bpf_dbg_printk("can't read mongodb Operation.Database");
        goto done;
    }

    bpf_map_update_elem(&ongoing_mongo_requests, &g_key, req, BPF_ANY);

done:
    return 0;
}

SEC("uprobe/op_execute")
int obi_uprobe_mongo_op_execute_ret(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/mongo op_execute return === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *err_ptr = (void *)GO_PARAM1(ctx);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    mongo_go_client_req_t *req = bpf_map_lookup_elem(&ongoing_mongo_requests, &g_key);
    if (req) {
        if (err_ptr) {
            req->err = 1;
        } else {
            req->err = 0;
        }

        mongo_go_client_req_t *trace =
            bpf_ringbuf_reserve(&events, sizeof(mongo_go_client_req_t), 0);
        if (trace) {
            bpf_dbg_printk("Sending mongo Go client go trace");
            __builtin_memcpy(trace, req, sizeof(mongo_go_client_req_t));
            trace->end_monotime_ns = bpf_ktime_get_ns();
            task_pid(&trace->pid);
            bpf_ringbuf_submit(trace, get_flags());
        }
    }

    bpf_map_delete_elem(&ongoing_mongo_requests, &g_key);

    return 0;
}
