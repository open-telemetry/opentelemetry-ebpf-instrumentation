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
#include <gotracer/go_str.h>

#include <logger/bpf_dbg.h>

#define MONGO_OP_DEF(name, str)                                                                    \
    static const char name[] = str;                                                                \
    static const u32 name##_size = sizeof(name) - 1;

MONGO_OP_DEF(insert, "insert")
MONGO_OP_DEF(delete, "delete")
MONGO_OP_DEF(find, "find")
MONGO_OP_DEF(drop, "drop")
MONGO_OP_DEF(findAndModify, "findAndModify")
MONGO_OP_DEF(updateOrReplace, "updateOrReplace")
MONGO_OP_DEF(aggregate, "aggregate")
MONGO_OP_DEF(countDocuments, "countDocuments")
MONGO_OP_DEF(estimatedDocumentCount, "estimatedDocumentCount")
MONGO_OP_DEF(distinct, "distinct")

static __always_inline int
obi_uprobe_mongo_coll_op(struct pt_regs *ctx, const char *op, const u32 op_len) {
    bpf_dbg_printk("=== uprobe/mongo op_execute === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *coll_ptr = (void *)GO_PARAM1(ctx);
    off_table_t *ot = get_offsets_table();

    mongo_go_client_req_t req = {0};
    req.type = EVENT_GO_MONGO;
    req.start_monotime_ns = bpf_ktime_get_ns();

    if (!read_go_str("name",
                     coll_ptr,
                     go_offset_of(ot, (go_offset){.v = _mongo_conn_name_pos}),
                     &req.coll,
                     sizeof(req.coll))) {
        bpf_dbg_printk("can't read mongodb Collection.name");
        return 0;
    }

    __builtin_memcpy(req.op, op, op_len);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    client_trace_parent(goroutine_addr, &req.tp);

    bpf_d_printk("op %s", req.op);

    bpf_map_update_elem(&ongoing_mongo_requests, &g_key, &req, BPF_ANY);

    return 0;
}

SEC("uprobe/op_coll_insert")
int obi_uprobe_mongo_op_insert(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, insert, insert_size);
}

SEC("uprobe/op_coll_delete")
int obi_uprobe_mongo_op_delete(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, delete, delete_size);
}

SEC("uprobe/op_coll_find")
int obi_uprobe_mongo_op_find(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, find, find_size);
}

SEC("uprobe/op_coll_drop")
int obi_uprobe_mongo_op_drop(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, drop, drop_size);
}

SEC("uprobe/op_coll_findAndModify")
int obi_uprobe_mongo_op_findAndModify(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, findAndModify, findAndModify_size);
}

SEC("uprobe/op_coll_updateOrReplace")
int obi_uprobe_mongo_op_updateOrReplace(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, updateOrReplace, updateOrReplace_size);
}

SEC("uprobe/op_coll_aggregate")
int obi_uprobe_mongo_op_aggregate(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, aggregate, aggregate_size);
}

SEC("uprobe/op_coll_countDocuments")
int obi_uprobe_mongo_op_countDocuments(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, countDocuments, countDocuments_size);
}

SEC("uprobe/op_coll_estimatedDocumentCount")
int obi_uprobe_mongo_op_estimatedDocumentCount(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, estimatedDocumentCount, estimatedDocumentCount_size);
}

SEC("uprobe/op_coll_distinct")
int obi_uprobe_mongo_op_distinct(struct pt_regs *ctx) {
    return obi_uprobe_mongo_coll_op(ctx, distinct, distinct_size);
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

    mongo_go_client_req_t fresh_req = {0};
    fresh_req.type = EVENT_GO_MONGO;
    fresh_req.start_monotime_ns = bpf_ktime_get_ns();

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    mongo_go_client_req_t *req = bpf_map_lookup_elem(&ongoing_mongo_requests, &g_key);

    if (!req) {
        client_trace_parent(goroutine_addr, &fresh_req.tp);
        req = &fresh_req;
    }

    if (!req) {
        return 0;
    }

    bpf_dbg_printk("op_ptr %llx", op_ptr);

    u64 new_mongo_version = go_offset_of(ot, (go_offset){.v = _mongo_op_name_new});

    // If we see driver > 1.13.1 we read the operation name
    if (new_mongo_version) {
        if (!read_go_str("name",
                         op_ptr,
                         go_offset_of(ot, (go_offset){.v = _mongo_op_name_pos}),
                         &req->op,
                         sizeof(req->op))) {
            bpf_dbg_printk("can't read mongodb Operation.Name");
            return 0;
        }
    }

    if (!read_go_str("database",
                     op_ptr,
                     go_offset_of(ot, (go_offset){.v = _mongo_db_name_pos}),
                     &req->db,
                     sizeof(req->db))) {
        bpf_dbg_printk("can't read mongodb Operation.Database");
        return 0;
    }

    bpf_map_update_elem(&ongoing_mongo_requests, &g_key, req, BPF_ANY);

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
