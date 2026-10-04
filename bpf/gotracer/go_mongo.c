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
#include <common/preempt_guard.h>
#include <common/ringbuf.h>
#include <common/scratch_mem.h>

#include <gotracer/go_common.h>
#include <gotracer/go_str.h>

#include <gotracer/maps/mongo.h>

#include <logger/bpf_dbg.h>

#include <gotracer/go_obi_ctx.h>

SCRATCH_MEM_TYPED(mongo_req, mongo_go_client_req_t);

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
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

    void *coll_ptr = (void *)GO_PARAM1(ctx);
    off_table_t *ot = get_offsets_table();

    mongo_go_client_req_t *req = mongo_req_mem();
    if (!req) {
        return 0;
    }

    bpf_memset(req, 0, sizeof(*req));
    req->type = k_event_type_go_mongo;
    req->start_monotime_ns = bpf_ktime_get_ns();

    if (!read_go_str("name",
                     coll_ptr,
                     go_offset_of(ot, (go_offset){.v = _mongo_conn_name_pos}),
                     &req->coll,
                     sizeof(req->coll))) {
        bpf_dbg_printk("can't read mongodb Collection.name");
        return 0;
    }

    __builtin_memcpy(req->op, op, op_len);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    client_trace_parent(goroutine_addr, &req->tp);

    bpf_d_printk("op=%s, [%s]", req->op, __FUNCTION__);

    bpf_map_update_elem(&ongoing_mongo_requests, &g_key, req, BPF_ANY);

    go_obi_ctx__begin(&g_key, k_obi_ctx_mongo, &req->tp, go_obi_ctx__stack_off(ctx));

    return 0;
}

static __always_inline bool mongo_connection_type_matches(const void *itab, u64 expected_itab) {
    if (!itab || !expected_itab) {
        return false;
    }

    void *actual_type = 0;
    void *expected_type = 0;
    if (bpf_probe_read_user(
            &actual_type, sizeof(actual_type), (const void *)((u64)itab + sizeof(void *))) != 0 ||
        bpf_probe_read_user(&expected_type,
                            sizeof(expected_type),
                            (const void *)(expected_itab + sizeof(void *))) != 0) {
        return false;
    }

    return actual_type && actual_type == expected_type;
}

static __always_inline bool
read_mongo_hostname_from_connection(void *conn_ptr, char *hostname, u64 max_len) {
    if (!conn_ptr) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();

    if (!read_go_str("mongo hostname",
                     conn_ptr,
                     go_offset_of(ot, (go_offset){.v = _mongo_connection_addr_pos}),
                     hostname,
                     max_len)) {
        bpf_dbg_printk("can't read mongo topology.connection.addr");
        return 0;
    }

    return 1;
}

static __always_inline bool
read_mongo_hostname_from_topology_connection(void *topology_conn_ptr, char *hostname, u64 max_len) {
    if (!topology_conn_ptr) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();

    void *conn_ptr = 0;
    int res = bpf_probe_read_user(
        &conn_ptr,
        sizeof(conn_ptr),
        (void *)((u64)topology_conn_ptr +
                 go_offset_of(ot, (go_offset){.v = _mongo_topology_connection_pos})));

    if (res != 0 || !conn_ptr) {
        bpf_dbg_printk("can't read mongo topology.Connection.connection");
        return 0;
    }

    return read_mongo_hostname_from_connection(conn_ptr, hostname, max_len);
}

static __always_inline void *read_mongo_topology_connection_from_mnet(void *mnet_ptr) {
    if (!mnet_ptr) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();

    unsigned char *iface =
        (unsigned char *)mnet_ptr + go_offset_of(ot, (go_offset){.v = _mongo_mnet_describer_pos});

    void *itab = 0;
    int res = bpf_probe_read_user(&itab, sizeof(itab), iface);

    if (res != 0 || !itab) {
        bpf_dbg_printk("can't read mongo mnet.Connection.Describer itab");
        return 0;
    }

    const u64 expected_itab =
        go_offset_of(ot, (go_offset){.v = _mongo_v2_topology_connection_type_addr});

    if (!mongo_connection_type_matches(itab, expected_itab)) {
        bpf_dbg_printk("mongo Describer is not topology.Connection");
        return 0;
    }

    void *topology_conn_ptr = 0;
    res = bpf_probe_read_user(
        &topology_conn_ptr, sizeof(topology_conn_ptr), iface + k_go_iface_data_offset);

    if (res != 0 || !topology_conn_ptr) {
        bpf_dbg_printk("can't read mongo Describer data");
        return 0;
    }

    return topology_conn_ptr;
}

static __always_inline bool
read_mongo_hostname_from_mnet(void *mnet_ptr, char *hostname, u64 max_len) {
    void *topology_conn_ptr = read_mongo_topology_connection_from_mnet(mnet_ptr);

    if (!topology_conn_ptr) {
        return 0;
    }

    return read_mongo_hostname_from_topology_connection(topology_conn_ptr, hostname, max_len);
}

SEC("uprobe/op_coll_insert")
int GUARDED_PROG(obi_uprobe_mongo_op_insert, struct pt_regs *, ctx) {
    return obi_uprobe_mongo_coll_op(ctx, insert, insert_size);
}

SEC("uprobe/op_coll_delete")
int GUARDED_PROG(obi_uprobe_mongo_op_delete, struct pt_regs *, ctx) {
    return obi_uprobe_mongo_coll_op(ctx, delete, delete_size);
}

SEC("uprobe/op_coll_find")
int GUARDED_PROG(obi_uprobe_mongo_op_find, struct pt_regs *, ctx) {
    return obi_uprobe_mongo_coll_op(ctx, find, find_size);
}

SEC("uprobe/op_coll_drop")
int GUARDED_PROG(obi_uprobe_mongo_op_drop, struct pt_regs *, ctx) {
    return obi_uprobe_mongo_coll_op(ctx, drop, drop_size);
}

SEC("uprobe/op_coll_findAndModify")
int GUARDED_PROG(obi_uprobe_mongo_op_findAndModify, struct pt_regs *, ctx) {
    return obi_uprobe_mongo_coll_op(ctx, findAndModify, findAndModify_size);
}

SEC("uprobe/op_coll_updateOrReplace")
int GUARDED_PROG(obi_uprobe_mongo_op_updateOrReplace, struct pt_regs *, ctx) {
    return obi_uprobe_mongo_coll_op(ctx, updateOrReplace, updateOrReplace_size);
}

SEC("uprobe/op_coll_aggregate")
int GUARDED_PROG(obi_uprobe_mongo_op_aggregate, struct pt_regs *, ctx) {
    return obi_uprobe_mongo_coll_op(ctx, aggregate, aggregate_size);
}

SEC("uprobe/op_coll_countDocuments")
int GUARDED_PROG(obi_uprobe_mongo_op_countDocuments, struct pt_regs *, ctx) {
    return obi_uprobe_mongo_coll_op(ctx, countDocuments, countDocuments_size);
}

SEC("uprobe/op_coll_estimatedDocumentCount")
int GUARDED_PROG(obi_uprobe_mongo_op_estimatedDocumentCount, struct pt_regs *, ctx) {
    return obi_uprobe_mongo_coll_op(ctx, estimatedDocumentCount, estimatedDocumentCount_size);
}

SEC("uprobe/op_coll_distinct")
int GUARDED_PROG(obi_uprobe_mongo_op_distinct, struct pt_regs *, ctx) {
    return obi_uprobe_mongo_coll_op(ctx, distinct, distinct_size);
}

// go.mongodb.org/mongo-driver/x/mongo/driver.Operation.Execute
// func (op Operation) Execute(ctx context.Context) error
SEC("uprobe/op_execute")
int GUARDED_PROG(obi_uprobe_mongo_op_execute, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/op_execute ===");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

    void *op_ptr = (void *)PT_REGS_SP(ctx) + 8;
    off_table_t *ot = get_offsets_table();

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    mongo_go_client_req_t *req = bpf_map_lookup_elem(&ongoing_mongo_requests, &g_key);
    // the collection op already began this span
    const u8 begun = req != NULL;

    if (!req) {
        req = mongo_req_mem();
        if (!req) {
            return 0;
        }

        bpf_memset(req, 0, sizeof(*req));
        req->type = k_event_type_go_mongo;
        req->start_monotime_ns = bpf_ktime_get_ns();
        client_trace_parent(goroutine_addr, &req->tp);
    }

    bpf_dbg_printk("op_ptr=%llx", op_ptr);

    const u64 new_mongo_version = go_offset_of(ot, (go_offset){.v = _mongo_op_name_new});

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

    if (!begun) {
        go_obi_ctx__begin(&g_key, k_obi_ctx_mongo, &req->tp, go_obi_ctx__stack_off(ctx));
    }

    return 0;
}

SEC("uprobe/op_execute")
int GUARDED_PROG(obi_uprobe_mongo_op_execute_ret, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/op_execute ===");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

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

    go_obi_ctx__end(&g_key, k_obi_ctx_mongo, req ? &req->tp : NULL);
    bpf_map_delete_elem(&ongoing_mongo_requests, &g_key);

    return 0;
}

SEC("uprobe/mongo_v1_get_server_and_connection_ret")
int GUARDED_PROG(obi_uretprobe_mongo_v1_get_server_and_connection, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/op_execute ===");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    mongo_go_client_req_t *req = bpf_map_lookup_elem(&ongoing_mongo_requests, &g_key);

    if (!req) {
        return 0;
    }

    void *conn_type = (void *)GO_PARAM3(ctx);
    void *topology_conn_ptr = (void *)GO_PARAM4(ctx);

    if (!conn_type || !topology_conn_ptr) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();

    const u64 expected_type =
        go_offset_of(ot, (go_offset){.v = _mongo_v1_topology_connection_type_addr});

    if (!mongo_connection_type_matches(conn_type, expected_type)) {
        return 0;
    }

    read_mongo_hostname_from_topology_connection(
        topology_conn_ptr, (char *)req->hostname, sizeof(req->hostname));
    return 0;
}
SEC("uprobe/mongo_v2_get_server_and_connection_ret")
int GUARDED_PROG(obi_uretprobe_mongo_v2_get_server_and_connection, struct pt_regs *, ctx) {
    bpf_dbg_printk("=== uprobe/op_execute ===");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    mongo_go_client_req_t *req = bpf_map_lookup_elem(&ongoing_mongo_requests, &g_key);

    if (!req) {
        return 0;
    }

    void *mnet_ptr = (void *)GO_PARAM3(ctx);

    if (!mnet_ptr) {
        return 0;
    }

    read_mongo_hostname_from_mnet(mnet_ptr, (char *)req->hostname, sizeof(req->hostname));
    return 0;
}