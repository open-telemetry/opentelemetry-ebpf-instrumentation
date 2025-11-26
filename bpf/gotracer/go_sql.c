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

static __always_inline void set_sql_info(void *goroutine_addr, void *driver_conn, void *sql_param, void *query_len) {
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

    void *dsn_ptr = GO_PARAM3(ctx);
    void *dsn_len = GO_PARAM4(ctx);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    sql_open_invocation_t invocation = {
        .dsn_ptr = (u64)dsn_ptr,
        .dsn_len = (u64)dsn_len,
    };

    bpf_map_update_elem(&ongoing_sql_opens, &g_key, &invocation, BPF_ANY);
    return 0;
}

// Helper function to extract hostname from DSN (user:pass@tcp(hostname:port)/database)
static __always_inline u8 extract_hostname_from_dsn(const unsigned char *dsn,
                                                      u64 dsn_len,
                                                      unsigned char *hostname,
                                                      u64 max_hostname_len) {
    u8 found = 0;
    u64 start_idx = 0;

    // Search for "@tcp(" in the DSN
    for (u64 i = 0; i < dsn_len - 5 && i < 512; i++) {
        unsigned char c1, c2, c3, c4, c5;
        bpf_probe_read(&c1, 1, &dsn[i]);
        bpf_probe_read(&c2, 1, &dsn[i + 1]);
        bpf_probe_read(&c3, 1, &dsn[i + 2]);
        bpf_probe_read(&c4, 1, &dsn[i + 3]);
        bpf_probe_read(&c5, 1, &dsn[i + 4]);

        if (c1 == '@' && c2 == 't' && c3 == 'c' && c4 == 'p' && c5 == '(') {
            start_idx = i + 5;
            found = 1;
            break;
        }
    }

    if (!found) {
        return 0;
    }

    // Extract hostname until we hit ')' or reach max length
    u64 hostname_len = 0;
    for (u64 i = start_idx; i < dsn_len && i < start_idx + max_hostname_len - 1 && i < 512; i++) {
        unsigned char c;
        bpf_probe_read(&c, 1, &dsn[i]);
        if (c == ')' || c == '\0') {
            break;
        }
        hostname[hostname_len++] = c;
    }

    if (hostname_len > 0 && hostname_len < max_hostname_len) {
        hostname[hostname_len] = '\0';
        return 1;
    }

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

    unsigned char hostname[256] = {0};
    u8 extracted = extract_hostname_from_dsn((const unsigned char *)invocation->dsn_ptr,
                                              invocation->dsn_len,
                                              hostname,
                                              sizeof(hostname));

    if (extracted) {
        u64 db_key = (u64)db_ptr;
        bpf_map_update_elem(&sql_db_hostname, &db_key, hostname, BPF_ANY);
        bpf_dbg_printk("Stored hostname for DB %llx: %s", db_key, hostname);
    }

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
                unsigned char *hostname = bpf_map_lookup_elem(&sql_db_hostname, &db_ptr);
                if (hostname) {
                    __builtin_memcpy(trace->hostname, hostname, sizeof(trace->hostname));
                    bpf_dbg_printk("Found hostname: %s", trace->hostname);
                } else {
                    bpf_dbg_printk("No hostname found for DB %llx", db_ptr);
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
