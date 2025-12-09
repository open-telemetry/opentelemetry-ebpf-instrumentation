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

// Offsets for database/sql driverConn struct:
// driverConn.ci is at offset 40 (after db *DB, createdAt time.Time, sync.Mutex)
// ci is an interface [type_ptr, data_ptr] - data_ptr is at offset 48
#define DRIVERCONN_CI_DATA_OFFSET 48

static __always_inline int
read_mysql_hostname_from_driverconn(u64 driver_conn_ptr, char *hostname, int max_len) {
    if (driver_conn_ptr == 0) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();
    if (!ot) {
        return 0;
    }

    void *mysql_conn_ptr = NULL;
    bpf_probe_read(&mysql_conn_ptr,
                   sizeof(mysql_conn_ptr),
                   (void *)(driver_conn_ptr + DRIVERCONN_CI_DATA_OFFSET));

    if (!mysql_conn_ptr) {
        return 0;
    }

    u64 cfg_offset = go_offset_of(ot, (go_offset){.v = _mysql_conn_cfg_pos});
    if (cfg_offset == (u64)-1) {
        return 0;
    }

    void *cfg_ptr = NULL;
    bpf_probe_read(&cfg_ptr, sizeof(cfg_ptr), (void *)((u64)mysql_conn_ptr + cfg_offset));

    if (!cfg_ptr) {
        return 0;
    }

    u64 addr_offset = go_offset_of(ot, (go_offset){.v = _mysql_config_addr_pos});
    if (addr_offset == (u64)-1) {
        return 0;
    }

    u64 addr_ptr = 0, addr_len = 0;
    bpf_probe_read(&addr_ptr, sizeof(addr_ptr), (void *)((u64)cfg_ptr + addr_offset));
    bpf_probe_read(&addr_len, sizeof(addr_len), (void *)((u64)cfg_ptr + addr_offset + 8));

    if (addr_ptr == 0 || addr_len == 0) {
        return 0;
    }

    if (addr_len > max_len - 1) {
        addr_len = max_len - 1;
    }

    bpf_probe_read(hostname, addr_len, (void *)addr_ptr);
    hostname[addr_len] = '\0';

    // Basic validation: check first few chars are printable
#pragma unroll
    for (int i = 0; i < 4 && i < addr_len; i++) {
        if (hostname[i] < 32 || hostname[i] > 126) {
            return 0;
        }
    }

    return 1;
}

static __always_inline int
read_pgx_hostname_from_pgconn(void *pgconn_ptr, char *hostname, int max_len) {
    if (!pgconn_ptr) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();
    if (!ot) {
        return 0;
    }

    u64 config_offset = go_offset_of(ot, (go_offset){.v = _pgconn_config_pos});
    if (config_offset == (u64)-1) {
        return 0;
    }

    void *config_ptr = NULL;
    bpf_probe_read(&config_ptr, sizeof(config_ptr), (void *)((u64)pgconn_ptr + config_offset));

    if (!config_ptr) {
        return 0;
    }

    u64 host_offset = go_offset_of(ot, (go_offset){.v = _pgconfig_host_pos});
    if (host_offset == (u64)-1) {
        return 0;
    }

    u64 host_ptr = 0, host_len = 0;
    bpf_probe_read(&host_ptr, sizeof(host_ptr), (void *)((u64)config_ptr + host_offset));
    bpf_probe_read(&host_len, sizeof(host_len), (void *)((u64)config_ptr + host_offset + 8));

    if (host_ptr == 0 || host_len == 0) {
        return 0;
    }

    if (host_len > max_len - 1) {
        host_len = max_len - 1;
    }

    bpf_probe_read(hostname, host_len, (void *)host_ptr);
    hostname[host_len] = '\0';

    // Basic validation: check first few chars are printable
#pragma unroll
    for (int i = 0; i < 4 && i < host_len; i++) {
        if (hostname[i] < 32 || hostname[i] > 126) {
            return 0;
        }
    }

    return 1;
}

static __always_inline int
read_pgx_stdlib_hostname_from_conn(void *stdlib_conn_ptr, char *hostname, int max_len) {
    if (!stdlib_conn_ptr) {
        return 0;
    }

    off_table_t *ot = get_offsets_table();
    if (!ot) {
        return 0;
    }

    u64 pgx_conn_offset = go_offset_of(ot, (go_offset){.v = _pgstdlib_conn_pos});
    if (pgx_conn_offset == (u64)-1) {
        return 0;
    }

    void *pgx_conn_ptr = NULL;
    bpf_probe_read(
        &pgx_conn_ptr, sizeof(pgx_conn_ptr), (void *)(stdlib_conn_ptr + pgx_conn_offset));

    if (!pgx_conn_ptr) {
        return 0;
    }

    u64 pgconn_offset = go_offset_of(ot, (go_offset){.v = _pgx_conn_pgconn_pos});
    if (pgconn_offset == (u64)-1) {
        return 0;
    }

    void *pgconn_ptr = NULL;
    bpf_probe_read(&pgconn_ptr, sizeof(pgconn_ptr), (void *)(pgx_conn_ptr + pgconn_offset));

    if (!pgconn_ptr) {
        return 0;
    }

    return read_pgx_hostname_from_pgconn(pgconn_ptr, hostname, max_len);
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

    // func (db *DB) queryDC(ctx, txctx context.Context, dc *driverConn, releaseConn func(error), query string, ...)
    // context.Context is an interface (2 words each)
    // PARAM1: db, PARAM2-3: ctx, PARAM4-5: txctx, PARAM6: dc, PARAM7: releaseConn, PARAM8-9: query (ptr+len)
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

    // func (db *DB) execDC(ctx context.Context, dc *driverConn, release func(error), query string, ...)
    // context.Context is an interface (2 words)
    // PARAM1: db, PARAM2-3: ctx, PARAM4: dc, PARAM5: release, PARAM6-7: query (ptr+len)
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

        u64 driver_conn_ptr = invocation->driver_conn_ptr;
        int hostname_extracted = 0;

        if (driver_conn_ptr != 0) {
            void *driver_impl_ptr = NULL;
            bpf_probe_read(&driver_impl_ptr,
                           sizeof(driver_impl_ptr),
                           (void *)(driver_conn_ptr + DRIVERCONN_CI_DATA_OFFSET));

            if (driver_impl_ptr) {
                if (read_mysql_hostname_from_driverconn(driver_conn_ptr,
                                                        (char *)(trace->hostname + 16),
                                                        sizeof(trace->hostname) - 16)) {
                    hostname_extracted = 1;
                } else if (read_pgx_stdlib_hostname_from_conn(driver_impl_ptr,
                                                              (char *)(trace->hostname + 16),
                                                              sizeof(trace->hostname) - 16)) {
                    hostname_extracted = 1;
                }
            }
        }

        if (!hostname_extracted) {
            trace->hostname[16] = '\0';
        }

        // submit the completed trace via ringbuffer
        bpf_ringbuf_submit(trace, get_flags());
    } else {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
    }
    return 0;
}
