// Copyright The OpenTelemetry Authors
// Copyright Grafana Labs
//
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

// This implementation was inspired by https://github.com/open-telemetry/opentelemetry-go-instrumentation/blob/ca1afccea6ec520d18238c3865024a9f5b9c17fe/internal/pkg/instrumentors/bpf/database/sql/bpf/probe.bpf.c
// and has been modified since.

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/http_types.h>
#include <common/ringbuf.h>

#include <gotracer/go_common.h>

static __always_inline void
set_sql_info(void *goroutine_addr, void *driver_conn, void *sql_param, void *query_len) {
    sql_func_invocation_t invocation = {.start_monotime_ns = bpf_ktime_get_ns(),
                                        .sql_param = (u64)sql_param,
                                        .query_len = (u64)query_len,
                                        .driver_conn_ptr = (u64)driver_conn,
                                        .conn = {0},
                                        .tp = {0}};

    client_trace_parent(goroutine_addr, &invocation.tp);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    // Write event
    if (bpf_map_update_elem(&ongoing_sql_queries, &g_key, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update map element");
    }
}

SEC("uprobe/queryDC")
int obi_uprobe_queryDC(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/queryDC === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *driver_conn = GO_PARAM4(ctx);
    void *sql_param = GO_PARAM8(ctx);
    void *query_len = GO_PARAM9(ctx);

    set_sql_info(goroutine_addr, driver_conn, sql_param, query_len);
    return 0;
}

SEC("uprobe/execDC")
int obi_uprobe_execDC(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/execDC === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *driver_conn = GO_PARAM3(ctx);
    void *sql_param = GO_PARAM5(ctx);
    void *query_len = GO_PARAM6(ctx);
    set_sql_info(goroutine_addr, driver_conn, sql_param, query_len);
    return 0;
}

typedef struct sql_open_invocation {
    u64 driver_ptr;
    u64 driver_len;
    u64 dsn_ptr;
    u64 dsn_len;
} sql_open_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: goroutine
    __type(value, sql_open_invocation_t);
    __uint(max_entries, 1024);
} ongoing_sql_opens SEC(".maps");

SEC("uprobe/sqlOpen")
int obi_uprobe_sqlOpen(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/sql.Open === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *driver_ptr = GO_PARAM1(ctx);
    void *driver_len = GO_PARAM2(ctx);
    void *dsn_ptr = GO_PARAM3(ctx);
    void *dsn_len = GO_PARAM4(ctx);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    sql_open_invocation_t invocation = {
        .driver_ptr = (u64)driver_ptr,
        .driver_len = (u64)driver_len,
        .dsn_ptr = (u64)dsn_ptr,
        .dsn_len = (u64)dsn_len,
    };

    bpf_map_update_elem(&ongoing_sql_opens, &g_key, &invocation, BPF_ANY);
    return 0;
}

SEC("uprobe/sqlOpen")
int obi_uretprobe_sqlOpen(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uretprobe/sql.Open === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    sql_open_invocation_t *invocation = bpf_map_lookup_elem(&ongoing_sql_opens, &g_key);
    if (invocation == NULL) {
        bpf_dbg_printk("sql.Open invocation not found");
        return 0;
    }

    void *db_ptr = GO_PARAM1(ctx);
    if (db_ptr == NULL) {
        bpf_dbg_printk("sql.Open returned nil DB");
        bpf_map_delete_elem(&ongoing_sql_opens, &g_key);
        return 0;
    }

    sql_db_info_t db_info = {0};

    // Copy driver name
    u64 driver_len = invocation->driver_len;
    if (driver_len > sizeof(db_info.driver) - 1) {
        driver_len = sizeof(db_info.driver) - 1;
    }
    bpf_probe_read(db_info.driver, driver_len, (void *)invocation->driver_ptr);
    db_info.driver[driver_len] = '\0';

    // Copy DSN
    u64 dsn_len = invocation->dsn_len;
    if (dsn_len > sizeof(db_info.dsn) - 1) {
        dsn_len = sizeof(db_info.dsn) - 1;
    }
    bpf_probe_read(db_info.dsn, dsn_len, (void *)invocation->dsn_ptr);
    db_info.dsn[dsn_len] = '\0';

    u64 db_key = (u64)db_ptr;
    bpf_map_update_elem(&sql_db_hostname, &db_key, &db_info, BPF_ANY);
    bpf_dbg_printk("Stored driver=%s DSN for DB %llx", db_info.driver, db_key);

    bpf_map_delete_elem(&ongoing_sql_opens, &g_key);
    return 0;
}

SEC("uprobe/queryDC")
int obi_uprobe_queryReturn(struct pt_regs *ctx) {

    bpf_dbg_printk("=== uprobe/query return === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    sql_func_invocation_t *invocation = bpf_map_lookup_elem(&ongoing_sql_queries, &g_key);
    if (invocation == NULL) {
        bpf_dbg_printk("Request not found for this goroutine");
        return 0;
    }
    bpf_map_delete_elem(&ongoing_sql_queries, &g_key);

    sql_request_trace_t *trace = bpf_ringbuf_reserve(&events, sizeof(sql_request_trace_t), 0);
    if (trace) {
        task_pid(&trace->pid);
        trace->type = EVENT_SQL_CLIENT;
        trace->start_monotime_ns = invocation->start_monotime_ns;
        trace->end_monotime_ns = bpf_ktime_get_ns();

        void *resp_ptr = GO_PARAM1(ctx);
        trace->status = (resp_ptr == NULL);
        trace->tp = invocation->tp;

        u64 query_len = invocation->query_len;
        if (query_len > sizeof(trace->sql)) {
            query_len = sizeof(trace->sql);
        }

        bpf_probe_read(trace->sql, query_len, (void *)invocation->sql_param);

        if (query_len < sizeof(trace->sql)) {
            trace->sql[query_len] = '\0';
        }

        bpf_dbg_printk("Found sql statement %s", trace->sql);

        __builtin_memcpy(&trace->conn, &invocation->conn, sizeof(connection_info_t));

        u64 db_ptr = 0;
        if (invocation->driver_conn_ptr != 0) {
            bpf_probe_read(&db_ptr, sizeof(db_ptr), (void *)invocation->driver_conn_ptr);
            bpf_dbg_printk("DB pointer: %llx", db_ptr);

            if (db_ptr != 0) {
                sql_db_info_t *db_info = bpf_map_lookup_elem(&sql_db_hostname, &db_ptr);
                if (db_info) {
                    // Copy both driver and DSN to trace->hostname
                    // Format: "driver|dsn" for userspace parsing
                    __builtin_memcpy(trace->hostname, db_info, sizeof(sql_db_info_t));
                    bpf_dbg_printk("Found DB info for DB %llx", db_ptr);
                } else {
                    bpf_dbg_printk("No DB info found for DB %llx", db_ptr);
                    trace->hostname[0] = '\0';
                }
            } else {
                trace->hostname[0] = '\0';
            }
        } else {
            trace->hostname[0] = '\0';
        }

        bpf_ringbuf_submit(trace, get_flags());
    } else {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
    }
    return 0;
}
