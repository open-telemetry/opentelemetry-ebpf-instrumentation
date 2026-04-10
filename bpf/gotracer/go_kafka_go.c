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

#include <gotracer/maps/handled_by_go.h>
#include <gotracer/maps/kafka.h>

#include <gotracer/types/kafka.h>

#include <logger/bpf_dbg.h>

#include <shared/obi_ctx.h>

// Code for the produce messages path
SEC("uprobe/writer_write_messages")
int obi_uprobe_writer_write_messages(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    void *w_ptr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("=== uprobe/writer_write_messages ===");
    bpf_dbg_printk("goroutine_addr=%llx, w_ptr=%llx", goroutine_addr, w_ptr);

    tp_info_t tp = {};

    client_trace_parent(goroutine_addr, &tp);
    go_addr_key_t p_key = {};
    go_addr_key_from_id(&p_key, w_ptr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    store_go_handled_goroutine(&g_key);

    bpf_map_update_elem(&produce_traceparents, &p_key, &tp, BPF_ANY);
    bpf_map_update_elem(&produce_traceparents_by_goroutine, &g_key, &tp, BPF_ANY);

    obi_ctx__set(bpf_get_current_pid_tgid(), &tp);

    return 0;
}

SEC("uprobe/writer_produce")
int obi_uprobe_writer_produce(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/writer_produce ===");
    bpf_dbg_printk("goroutine_addr=%llx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    store_go_handled_goroutine(&g_key);

    void *w_ptr = (void *)GO_PARAM1(ctx);
    void *topic_ptr = (void *)GO_PARAM2(ctx);
    u64 topic_len = (u64)GO_PARAM3(ctx);
    off_table_t *ot = get_offsets_table();

    if (w_ptr) {

        if (topic_len == 0) {
            topic_ptr = 0;
            topic_len = k_max_topic_name_len - 1;
            bpf_probe_read_user(&topic_ptr,
                                sizeof(void *),
                                w_ptr +
                                    go_offset_of(ot, (go_offset){.v = _kafka_go_writer_topic_pos}));
        }
        bpf_clamp_umax(topic_len, k_max_topic_name_len - 1);

        bpf_dbg_printk("topic_ptr=%llx", topic_ptr);
        go_addr_key_t p_key = {};
        go_addr_key_from_id(&p_key, w_ptr);
        if (topic_ptr) {
            topic_t topic = {};
            tp_info_t *tp = bpf_map_lookup_elem(&produce_traceparents, &p_key);
            if (tp) {
                bpf_dbg_printk("found existing traceparent, tp=%llx", tp);
                __builtin_memcpy(&topic.tp, tp, sizeof(tp_info_t));
            } else {
                urand_bytes(topic.tp.trace_id, TRACE_ID_SIZE_BYTES);
                urand_bytes(topic.tp.span_id, SPAN_ID_SIZE_BYTES);
            }

            bpf_probe_read_user(&topic.name, topic_len, topic_ptr);
            topic.name[topic_len] = '\0';
            bpf_map_update_elem(&ongoing_produce_topics, &g_key, &topic, BPF_ANY);
        }
        bpf_map_delete_elem(&produce_traceparents, &p_key);
    }

    return 0;
}

SEC("uprobe/client_roundTrip")
int obi_uprobe_client_roundTrip(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/client_roundTrip  ===");
    bpf_dbg_printk("goroutine_addr=%llx", goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    store_go_handled_goroutine(&g_key);

    topic_t *topic_ptr = bpf_map_lookup_elem(&ongoing_produce_topics, &g_key);

    if (topic_ptr) {
        void *msg_ptr = (void *)GO_PARAM7(ctx);
        bpf_dbg_printk("msg_ptr=%llx", msg_ptr);
        if (msg_ptr) {
            topic_t topic;
            __builtin_memcpy(&topic, topic_ptr, sizeof(topic_t));
            go_addr_key_t m_key = {};
            go_addr_key_from_id(&m_key, msg_ptr);
            bpf_map_update_elem(&ongoing_produce_messages, &m_key, &topic, BPF_ANY);
        }
    }

    bpf_map_delete_elem(&ongoing_produce_topics, &g_key);
    return 0;
}

SEC("uprobe/protocol_RoundTrip")
int obi_uprobe_protocol_roundtrip(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/protocol_RoundTrip ===");
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    void *rw_ptr = (void *)GO_PARAM2(ctx);
    void *msg_ptr = (void *)GO_PARAM8(ctx);
    off_table_t *ot = get_offsets_table();

    bpf_dbg_printk(
        "goroutine_addr=%lx, rw_ptr=%llx, msg_ptr=%llx", goroutine_addr, rw_ptr, msg_ptr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    store_go_handled_goroutine(&g_key);

    if (rw_ptr) {
        go_addr_key_t m_key = {};
        go_addr_key_from_id(&m_key, msg_ptr);
        topic_t *topic_ptr = bpf_map_lookup_elem(&ongoing_produce_messages, &m_key);
        bpf_dbg_printk("Found topic, topic_ptr=%llx", topic_ptr);
        if (topic_ptr) {
            produce_req_t p = {
                .conn_ptr =
                    ((u64)rw_ptr) + go_offset_of(ot, (go_offset){.v = _kafka_go_protocol_conn_pos}),
                .msg_ptr = (u64)msg_ptr,
                .start_monotime_ns = bpf_ktime_get_ns(),
            };

            bpf_map_update_elem(&produce_requests, &g_key, &p, BPF_ANY);
        }
    }

    return 0;
}

SEC("uprobe/protocol_RoundTrip_ret")
int obi_uprobe_protocol_roundtrip_ret(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/protocol_RoundTrip_ret ===");
    bpf_dbg_printk("goroutine_addr=%llx", goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    produce_req_t *p_ptr = bpf_map_lookup_elem(&produce_requests, &g_key);

    bpf_dbg_printk("p_ptr=%llx", p_ptr);

    if (p_ptr) {
        void *msg_ptr = (void *)p_ptr->msg_ptr;
        go_addr_key_t m_key = {};
        go_addr_key_from_id(&m_key, msg_ptr);
        topic_t *topic_ptr = bpf_map_lookup_elem(&ongoing_produce_messages, &m_key);

        bpf_dbg_printk("goroutine_addr=%lx, conn_ptr=%llx", goroutine_addr, p_ptr->conn_ptr);
        bpf_dbg_printk("msg_ptr=%llx, topic_ptr=%llx", p_ptr->msg_ptr, topic_ptr);

        if (topic_ptr) {
            kafka_go_req_t *trace = bpf_ringbuf_reserve(&events, sizeof(kafka_go_req_t), 0);
            if (trace) {
                trace->type = EVENT_GO_KAFKA_SEG;
                trace->op = k_kafka_api_produce;
                trace->start_monotime_ns = p_ptr->start_monotime_ns;
                trace->end_monotime_ns = bpf_ktime_get_ns();

                void *conn_ptr = 0;
                bpf_probe_read(
                    &conn_ptr, sizeof(conn_ptr), (void *)(p_ptr->conn_ptr + 8)); // find conn
                bpf_dbg_printk("conn_ptr=%llx", conn_ptr);
                if (conn_ptr) {
                    const u8 ok = get_conn_info(conn_ptr, &trace->conn);
                    if (!ok) {
                        __builtin_memset(&trace->conn, 0, sizeof(connection_info_t));
                    }
                }

                __builtin_memcpy(trace->topic, topic_ptr->name, k_max_topic_name_len);
                __builtin_memcpy(&trace->tp, &(topic_ptr->tp), sizeof(tp_info_t));
                task_pid(&trace->pid);
                bpf_ringbuf_submit(trace, get_flags());
            }
        }
        bpf_map_delete_elem(&ongoing_produce_messages, &m_key);
    }

    bpf_map_delete_elem(&produce_requests, &g_key);

    return 0;
}

// Code for the fetch messages path
SEC("uprobe/reader_read")
int obi_uprobe_reader_read(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    void *r_ptr = (void *)GO_PARAM1(ctx);
    void *conn = (void *)GO_PARAM5(ctx);
    off_table_t *ot = get_offsets_table();

    bpf_dbg_printk("=== uprobe/reader_read ===");
    bpf_dbg_printk("goroutine_addr=%llx, r_ptr=%llx", goroutine_addr, r_ptr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    store_go_handled_goroutine(&g_key);

    if (r_ptr) {
        kafka_go_req_t r = {
            .type = EVENT_GO_KAFKA_SEG,
            .op = k_kafka_api_fetch,
            .start_monotime_ns = 0,
        };

        void *topic_ptr = 0;
        bpf_probe_read_user(&topic_ptr,
                            sizeof(void *),
                            r_ptr + go_offset_of(ot, (go_offset){.v = _kafka_go_reader_topic_pos}));

        bpf_dbg_printk("topic_ptr=%llx", topic_ptr);
        if (topic_ptr) {
            bpf_probe_read_user(&r.topic, sizeof(r.topic), topic_ptr);
        }

        if (conn) {
            void *conn_ptr = 0;
            bpf_probe_read(&conn_ptr, sizeof(conn_ptr), (void *)(conn + 8)); // find conn
            bpf_dbg_printk("conn_ptr=%llx", conn_ptr);
            if (conn_ptr) {
                const u8 ok = get_conn_info(conn_ptr, &r.conn);
                if (!ok) {
                    __builtin_memset(&r.conn, 0, sizeof(connection_info_t));
                }
            }
        }

        bpf_map_update_elem(&fetch_requests, &g_key, &r, BPF_ANY);
    }

    return 0;
}

SEC("uprobe/reader_send_message")
int obi_uprobe_reader_send_message(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/reader_send_message ===");
    bpf_dbg_printk("goroutine_addr=%llx", goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    store_go_handled_goroutine(&g_key);

    kafka_go_req_t *req_ptr = (kafka_go_req_t *)bpf_map_lookup_elem(&fetch_requests, &g_key);
    bpf_dbg_printk("Found req_ptr: %llx", req_ptr);

    if (req_ptr) {
        req_ptr->start_monotime_ns = bpf_ktime_get_ns();
    }

    return 0;
}

SEC("uprobe/reader_read")
int obi_uprobe_reader_read_ret(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/reader_read goroutine_addr=%llx ===", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    kafka_go_req_t *req_ptr = (kafka_go_req_t *)bpf_map_lookup_elem(&fetch_requests, &g_key);
    bpf_dbg_printk("Found req_ptr: %llx", req_ptr);

    if (req_ptr) {
        if (req_ptr->start_monotime_ns) {
            kafka_go_req_t *trace = bpf_ringbuf_reserve(&events, sizeof(kafka_go_req_t), 0);
            if (trace) {
                __builtin_memcpy(trace, req_ptr, sizeof(kafka_go_req_t));
                trace->end_monotime_ns = bpf_ktime_get_ns();
                task_pid(&trace->pid);
                bpf_ringbuf_submit(trace, get_flags());
            }
        } else {
            bpf_dbg_printk("Found request with no start time, ignoring...");
        }
    }

    bpf_map_delete_elem(&fetch_requests, &g_key);

    return 0;
}
