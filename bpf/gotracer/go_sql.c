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
#include <gotracer/go_str.h>

// Validates that driverConn.ci points to a MySQL connection and returns the mysqlConn pointer.
static __always_inline void *get_mysql_conn_ptr(u64 driver_conn_ptr) {
    if (driver_conn_ptr == 0) {
        return NULL;
    }

    off_table_t *ot = get_offsets_table();

    // Get driverConn.ci offset
    u64 ci_offset = go_offset_of(ot, (go_offset){.v = _driverconn_ci_pos});
    if (!ci_offset) {
        bpf_dbg_printk("can't get driverConn.ci offset");
        return NULL;
    }

    // driverConn.ci is a Go interface [type_ptr (8 bytes), data_ptr (8 bytes)]
    // Read the type pointer (at ci_offset + 0) to validate driver type
    void *ci_type_ptr = NULL;
    int res = bpf_probe_read_user(
        &ci_type_ptr, sizeof(ci_type_ptr), (void *)(driver_conn_ptr + ci_offset));

    if (res != 0) {
        bpf_dbg_printk("can't read driverConn.ci type pointer");
        return NULL;
    }

    u64 mysql_type_addr = go_offset_of(ot, (go_offset){.v = _mysql_conn_type_off});
    if (!mysql_type_addr) {
        bpf_dbg_printk("can't read mysql.mysqlConn offset");
        return NULL;
    }

    bpf_dbg_printk("validating mysql conn type %llx with %llx", mysql_type_addr, ci_type_ptr);
    if ((u64)ci_type_ptr != mysql_type_addr) {
        bpf_dbg_printk("connection type doesn't match from mysql.mysqlConn");
        return NULL;
    }

    void *mysql_conn_ptr = 0;
    res = bpf_probe_read(
        &mysql_conn_ptr, sizeof(mysql_conn_ptr), (void *)(driver_conn_ptr + ci_offset + 8));

    if (res != 0 || !mysql_conn_ptr) {
        bpf_dbg_printk("can't read MySQL connection data pointer");
        return NULL;
    }

    return mysql_conn_ptr;
}

// Extracts MySQL server hostname from a validated mysqlConn pointer.
// Follows the pointer chain: mysqlConn -> cfg (*Config) -> Addr (string)
static __always_inline bool
read_mysql_hostname_from_mysqlconn(void *mysql_conn_ptr, char *hostname, u64 max_len) {
    if (!mysql_conn_ptr) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();

    // Dereference mysqlConn.cfg to get pointer to Config struct
    void *cfg_ptr = 0;
    int res = bpf_probe_read(
        &cfg_ptr,
        sizeof(cfg_ptr),
        (void *)((u64)mysql_conn_ptr + go_offset_of(ot, (go_offset){.v = _mysql_conn_cfg_pos})));

    if (res != 0 || !cfg_ptr) {
        bpf_dbg_printk("can't read mysql.mysqlConn.cfg");
        return 0;
    }

    // Read Config.Addr string field
    if (!read_go_str("mysql hostname",
                     cfg_ptr,
                     go_offset_of(ot, (go_offset){.v = _mysql_config_addr_pos}),
                     hostname,
                     max_len)) {
        bpf_dbg_printk("can't read mysql.Config.Addr");
        return 0;
    }

    return 1;
}

// SQL hostname extraction with driver type routing.
// Attempts to extract hostname by trying supported database drivers
static __always_inline void extract_sql_hostname(sql_request_trace_t *trace, u64 driver_conn_ptr) {
    trace->hostname[0] = '\0';

    if (driver_conn_ptr == 0) {
        bpf_dbg_printk("sql hostname extraction skipped: driver_conn_ptr is null");
        return;
    }

    void *mysql_conn_ptr = get_mysql_conn_ptr(driver_conn_ptr);
    if (!mysql_conn_ptr) {
        return;
    }

    if (read_mysql_hostname_from_mysqlconn(
            mysql_conn_ptr, (char *)trace->hostname, sizeof(trace->hostname))) {
        bpf_dbg_printk("extracted MySQL hostname: %s", trace->hostname);
    }
}

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

    void *driver_conn = GO_PARAM6(ctx);
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

    void *driver_conn = GO_PARAM4(ctx);
    void *sql_param = GO_PARAM6(ctx);
    void *query_len = GO_PARAM7(ctx);

    set_sql_info(goroutine_addr, driver_conn, sql_param, query_len);
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

        extract_sql_hostname(trace, invocation->driver_conn_ptr);

        // submit the completed trace via ringbuffer
        bpf_ringbuf_submit(trace, get_flags());
    } else {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
    }
    return 0;
}
