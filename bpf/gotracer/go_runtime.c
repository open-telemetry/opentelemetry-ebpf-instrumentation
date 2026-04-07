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

#include <gotracer/go_common.h>

#include <gotracer/maps/grpc.h>
#include <gotracer/maps/handled_by_go.h>
#include <gotracer/maps/kafka.h>
#include <gotracer/maps/mongo.h>
#include <gotracer/maps/nethttp.h>
#include <gotracer/maps/redis.h>
#include <gotracer/maps/runtime.h>

#include <gotracer/types/grpc.h>
#include <gotracer/types/nethttp.h>

#include <logger/bpf_dbg.h>

#include <shared/obi_ctx.h>

typedef struct new_func_invocation {
    u64 parent;
} new_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, new_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} newproc1 SEC(".maps");

SEC("uprobe/runtime_newproc1")
int obi_uprobe_runtime_newproc1(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/runtime_newproc1 ===");
    void *creator_goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("creator_goroutine_addr=%lx", creator_goroutine_addr);

    new_func_invocation_t invocation = {.parent = (u64)GO_PARAM2(ctx)};
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, creator_goroutine_addr);

    // Save the registers on invocation to be able to fetch the arguments at return of newproc1
    if (bpf_map_update_elem(&newproc1, &g_key, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update map element");
    }

    return 0;
}

SEC("uprobe/runtime_newproc1_return")
int obi_uprobe_runtime_newproc1_return(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/runtime_newproc1_return ===");
    void *creator_goroutine_addr = GOROUTINE_PTR(ctx);
    const u64 pid_tid = bpf_get_current_pid_tgid();
    const u32 pid = pid_from_pid_tgid(pid_tid);
    go_addr_key_t c_key = {.addr = (u64)creator_goroutine_addr, .pid = pid};

    bpf_dbg_printk("creator_goroutine_addr=%lx", creator_goroutine_addr);

    // Lookup the newproc1 invocation metadata
    new_func_invocation_t *invocation = bpf_map_lookup_elem(&newproc1, &c_key);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read newproc1 invocation metadata");
        goto done;
    }

    // The parent goroutine is the second argument of newproc1
    void *parent_goroutine = (void *)invocation->parent;
    bpf_dbg_printk("parent_goroutine=%lx", parent_goroutine);

    // The result of newproc1 is the new goroutine
    void *goroutine_addr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("goroutine_addr=%lx", goroutine_addr);

    go_addr_key_t g_key = {.addr = (u64)goroutine_addr, .pid = pid};
    go_addr_key_t p_key = {.addr = (u64)parent_goroutine, .pid = pid};

    goroutine_metadata metadata = {
        .timestamp = bpf_ktime_get_ns(),
        .parent = p_key,
    };

    if (bpf_map_update_elem(&ongoing_goroutines, &g_key, &metadata, BPF_ANY)) {
        bpf_dbg_printk("can't update active goroutine");
    }

done:
    bpf_map_delete_elem(&newproc1, &c_key);

    return 0;
}

SEC("uprobe/runtime_goexit1")
int obi_uprobe_proc_goexit1(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc goexit1 === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    u64 pid_tid = bpf_get_current_pid_tgid();
    u32 pid = pid_from_pid_tgid(pid_tid);

    go_addr_key_t g_key = {.addr = (u64)goroutine_addr, .pid = pid};

    remove_go_handled_goroutine(&g_key);

    return 0;
}

enum gstatus {
    // _Gidle: just allocated, not yet initialized
    g_idle = 0,
    // _Grunnable: on a run queue, not executing user code
    g_runnable, // 1
    // _Grunning: may execute user code, stack is owned, assigned to M and P
    g_running, // 2
    // _Gsyscall: executing a system call, not user code, stack owned
    g_syscall, // 3
    // _Gwaiting: blocked in runtime, not executing user code, not on run queue
    g_waiting, // 4
    // _Gmoribund_unused: currently unused, hardcoded in gdb scripts
    g_moribund_unused, // 5
    // _Gdead: currently unused, may have just exited or on free list
    g_dead, // 6
    // _Genqueue_unused: currently unused
    g_enqueue_unused, // 7
    // _Gcopystack: stack is being moved, not executing user code
    g_copystack, // 8
    // _Gpreempted: stopped for suspendG preemption
    g_preempted, // 9
};

// NOTE: this is a hot path in the Go runtime, fetching offsets from the offsets map
// introduces a non negligible overhead. These structs appear to be stable since
// old versions of Go, so keep the values hardcoded.
//
// pahole -C runtime.g main
//
// struct runtime.g {
//  runtime.stack              stack;                /*     0    16 */
//  uintptr                    stackguard0;          /*    16     8 */
//  uintptr                    stackguard1;          /*    24     8 */
//  runtime._panic *           _panic;               /*    32     8 */
//  runtime._defer *           _defer;               /*    40     8 */
//  runtime.m *                m;                    /*    48     8 */
//  ...
// }
//
// pahole -C runtime.m main
//
// struct runtime.m {
//  runtime.g *                g0;                   /*     0     8 */
//  runtime.gobuf              morebuf;              /*     8    48 */
//  uint32                     divmod;               /*    56     4 */
//
//  /* XXX 4 bytes hole, try to pack */
//
//  /* --- cacheline 1 boundary (64 bytes) --- */
//  uint64                     procid;               /*    64     8 */
//  ...
// }
enum offsets : u8 {
    k_g_m_off = 0x30,
    k_m_procid_off = 0x40,
};

SEC("uprobe/runtime.mstart1")
int obi_uprobe_runtime_mstart1(struct pt_regs *ctx) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();

    void *g = (void *)GOROUTINE_PTR(ctx);
    void *m = NULL;

    bpf_probe_read_user(&m, sizeof(m), (void *)((char *)g + k_g_m_off));
    if (!m) {
        return 0;
    }

    bpf_map_update_elem(&mptr_to_root_tid, &m, &(u32){pid_tgid}, BPF_ANY);
    return 0;
}

SEC("uprobe/runtime.mexit")
int obi_uprobe_runtime_mexit(struct pt_regs *ctx) {
    void *g = (void *)GOROUTINE_PTR(ctx);
    void *m = NULL;

    bpf_probe_read_user(&m, sizeof(m), (void *)((char *)g + k_g_m_off));
    if (!m) {
        return 0;
    }

    bpf_map_delete_elem(&mptr_to_root_tid, &m);
    return 0;
}

// gp *g, oldval, newval uint32
SEC("uprobe/runtime.casgstatus")
int obi_uprobe_runtime_casgstatus(struct pt_regs *ctx) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();

    void *g = (void *)GO_PARAM1(ctx);
    void *m = NULL;

    bpf_probe_read_user(&m, sizeof(m), (void *)((char *)g + k_g_m_off));
    if (!m) {
        return 0;
    }

    u64 procid = 0;
    bpf_probe_read_user(&procid, sizeof(procid), (void *)((char *)m + k_m_procid_off));
    if (procid == 0) {
        return 0;
    }

    const u32 pid = pid_tgid >> 32;
    u32 *root_tid = bpf_map_lookup_elem(&mptr_to_root_tid, &m);
    if (root_tid != NULL) {
        procid = *root_tid;
    }

    const u64 g_pid_tgid = ((u64)pid << 32) | (procid & 0xffffffff);
    go_addr_key_t g_key = {
        .addr = (u64)g,
        .pid = pid,
    };

    // grpc
    grpc_srv_func_invocation_t *grpc_server_inv;
    grpc_client_func_invocation_t *grpc_client_inv;
    // http
    server_http_func_invocation_t *http_server_inv;
    // kafka_go
    tp_info_t *kafka_go_tp;
    // mongo
    mongo_go_client_req_t *mongo;
    // redis
    redis_client_req_t *redis;
    // sql
    sql_func_invocation_t *sql;

    obi_ctx_info_t obi_info = {};

    const u32 newval = (u32)(uintptr_t)GO_PARAM3(ctx);
    switch (newval) {
    case g_running:
    case g_syscall:
        // grpc
        grpc_server_inv = bpf_map_lookup_elem(&ongoing_grpc_server_requests, &g_key);
        if (grpc_server_inv) {
            obi_ctx__set_(g_pid_tgid, &grpc_server_inv->tp, &obi_info);
            return 0;
        }
        grpc_client_inv = bpf_map_lookup_elem(&ongoing_grpc_client_requests, &g_key);
        if (grpc_client_inv) {
            obi_ctx__set_(g_pid_tgid, &grpc_client_inv->tp, &obi_info);
            return 0;
        }
        // http
        http_server_inv = bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);
        if (http_server_inv) {
            obi_ctx__set_(g_pid_tgid, &http_server_inv->tp, &obi_info);
            return 0;
        }
        // kafka_go
        kafka_go_tp = bpf_map_lookup_elem(&produce_traceparents_by_goroutine, &g_key);
        if (kafka_go_tp) {
            obi_ctx__set_(g_pid_tgid, kafka_go_tp, &obi_info);
            return 0;
        }
        // mongo
        mongo = bpf_map_lookup_elem(&ongoing_mongo_requests, &g_key);
        if (mongo) {
            obi_ctx__set_(g_pid_tgid, &mongo->tp, &obi_info);
            return 0;
        }
        // redis
        redis = bpf_map_lookup_elem(&ongoing_redis_requests, &g_key);
        if (redis) {
            obi_ctx__set_(g_pid_tgid, &redis->tp, &obi_info);
            return 0;
        }
        // sql
        sql = bpf_map_lookup_elem(&ongoing_sql_queries, &g_key);
        if (sql) {
            obi_ctx__set_(g_pid_tgid, &sql->tp, &obi_info);
            return 0;
        }

        break;
    default:
        obi_ctx__del(g_pid_tgid);
    }

    return 0;
}
